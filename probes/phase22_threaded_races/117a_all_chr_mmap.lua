-- CRASH_CLASS: LOW
-- PROBE 117a: mmap ALL character device fds + fd 9 deep dump
--
-- From 113a fd scan:
-- CHR devices: 0,1,2,3,4,5,6,8,10,14,16
-- Sony 0x9000: 9,15
-- Sony 0xB000: 7 (mmap failed)
-- FIFO: 11,12,13,17,18
-- REG: 19,20
-- SOCK: 21,22
--
-- fd 4,5 = GPU PM4 command buffer (identical, writable)
-- fd 9 = Sony obj, mmap works, almost empty
--
-- This probe: mmap every remaining fd, dump first 256 bytes of each.
-- Looking for: MMIO registers, page table bases, kernel addresses.

print("=== PROBE 117a: ALL FD MMAP SURVEY ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
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

local function try_mmap(fd, size, prot, flags, offset)
    local ok, addr = pcall(function()
        return sc_mmap(uint64(0), uint64(size), uint64(prot),
            uint64(flags), uint64(fd), uint64(offset or 0))
    end)
    if not ok then return nil end
    if not addr then return nil end
    local h, l = get_hi_lo(addr)
    if h<0 then h=h+0x100000000 end
    if h==0xFFFFFFFF then return nil end
    return addr
end

local function dump_mapping(addr, label, size)
    local MA = N(addr)
    local non_zero = 0
    local kptrs = 0

    -- Count non-zero and find kernel pointers
    for off=0,size-4,4 do
        local ok2, val = pcall(function() return memory.read_dword(MA+off) end)
        if not ok2 then
            print(string.format("  %s: readable to +0x%X (%d bytes)", label, off, off))
            break
        end
        local v = N(val)
        if v ~= 0 then non_zero = non_zero + 1 end
    end

    -- Check qwords for kernel pointers
    for off=0,size-8,8 do
        local ok3, val = pcall(function() return memory.read_qword(MA+off) end)
        if not ok3 then break end
        if is_kptr(val) then
            kptrs = kptrs + 1
            print(string.format("    *** KPTR %s+0x%X: %s ***", label, off, fmt_ptr(val)))
        end
    end

    -- Print non-zero dwords (first 64 only)
    local printed = 0
    for off=0,size-4,4 do
        local ok4, val = pcall(function() return memory.read_dword(MA+off) end)
        if not ok4 then break end
        local v = N(val)
        if v ~= 0 then
            if v<0 then v=v+0x100000000 end
            print(string.format("    %s+0x%03X: 0x%08X", label, off, v))
            printed = printed + 1
            if printed >= 32 then
                print(string.format("    ... (%d more non-zero)", non_zero - 32))
                break
            end
        end
    end

    print(string.format("  %s: %d non-zero dwords, %d kernel ptrs",
        label, non_zero, kptrs))
    return non_zero, kptrs
end

-- ============================================================
-- Try all fds with multiple mmap strategies
local fds_to_test = {0, 1, 2, 3, 6, 7, 8, 10, 14, 16, 19, 20}
-- Already tested: 4,5 (GPU PM4), 9 (Sony empty), 15 (Sony zeros)
-- Skip: 11-13, 17-18 (FIFO), 21-22 (SOCK)

for _, fd in ipairs(fds_to_test) do
    print(string.format("--- fd %d ---", fd))
    local mapped = false

    -- Try PROT_READ MAP_SHARED
    local addr = try_mmap(fd, 0x4000, 1, 1)
    if addr then
        print(string.format("  PROT_R MAP_SHARED: %s", fmt_ptr(addr)))
        dump_mapping(addr, "fd"..fd, 0x400)
        mapped = true
    end

    -- Try PROT_RW MAP_SHARED
    if not mapped then
        addr = try_mmap(fd, 0x4000, 3, 1)
        if addr then
            print(string.format("  PROT_RW MAP_SHARED: %s", fmt_ptr(addr)))
            dump_mapping(addr, "fd"..fd, 0x400)
            mapped = true
        end
    end

    -- Try PROT_READ MAP_PRIVATE
    if not mapped then
        addr = try_mmap(fd, 0x4000, 1, 2)
        if addr then
            print(string.format("  PROT_R MAP_PRIVATE: %s", fmt_ptr(addr)))
            dump_mapping(addr, "fd"..fd, 0x400)
            mapped = true
        end
    end

    if not mapped then
        print("  all mmap attempts failed")
    end

    -- Check process alive
    local c = N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
    if c~=pid then print("PROCESS DIED") return end
end

-- ============================================================
print("")
print("--- DEEP: fd 9 larger mapping ---")
-- fd 9 had only 1 non-zero qword (0x4D400000001) at offset 0
-- Let's map more and see if there's data further in
local fd9_big = try_mmap(9, 0x100000, 1, 1)  -- 1MB
if fd9_big then
    local MA9 = N(fd9_big)
    print(string.format("  fd 9 1MB mapping: %s", fmt_ptr(fd9_big)))
    -- Scan for non-zero regions
    local first_nz = nil
    local last_nz = nil
    local nz_count = 0
    local kp_count = 0
    for off=0,0x100000-8,8 do
        local ok5, val = pcall(function() return memory.read_qword(MA9+off) end)
        if not ok5 then
            print(string.format("  unreadable at +0x%X", off))
            break
        end
        local h,l = get_hi_lo(val)
        if h~=0 or l~=0 then
            nz_count = nz_count + 1
            if not first_nz then first_nz = off end
            last_nz = off
            if is_kptr(val) then
                kp_count = kp_count + 1
                print(string.format("  *** KPTR fd9+0x%X: %s ***", off, fmt_ptr(val)))
            end
        end
    end
    print(string.format("  fd 9 1MB: %d non-zero qwords, first=0x%X last=0x%X, %d kptrs",
        nz_count, first_nz or 0, last_nz or 0, kp_count))
end

-- ============================================================
print("")
print("--- DEEP: fd 4 at offset 0x1000 (beyond command buffer) ---")
-- The PM4 stream was in the first 4KB. What's at higher offsets?
local fd4_off1 = try_mmap(4, 0x4000, 1, 1, 0x1000)
if fd4_off1 then
    print(string.format("  fd 4 @0x1000: %s", fmt_ptr(fd4_off1)))
    dump_mapping(fd4_off1, "fd4@1000", 0x400)
end

local fd4_off2 = try_mmap(4, 0x4000, 1, 1, 0x10000)
if fd4_off2 then
    print(string.format("  fd 4 @0x10000: %s", fmt_ptr(fd4_off2)))
    dump_mapping(fd4_off2, "fd4@10000", 0x400)
end

-- ============================================================
print("")
local fc=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("FINAL: canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 117a COMPLETE ===")
