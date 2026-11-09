-- CRASH_CLASS: LOW
-- PROBE 528u: Scan /dev/gc mmap space for kernel pointers
--
-- 528t: /dev/gc mmap at offset 0 returned 0xFFFFFFFF (all ones).
-- The GPU device might expose MMIO registers, command buffers, or
-- even a shared memory region that contains kernel addresses.
--
-- Also: the dmem0 pool starts with 0xC0012800 which looks like a
-- GPU register value. Let's see what's in the gc mapping at various offsets.

print("=== PROBE 528u: GC MMAP SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local sc_477 = mk(477)
local sc_73 = mk(73)
local PAGE = 0x4000

local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
    end)
    return ok and N(rv) or -1
end

-- ============================================================
-- [A] Scan /dev/gc at various offsets
-- ============================================================
print("[A] /dev/gc mmap scan")
local gc_fd = open_dev("/dev/gc")
print("  gc fd=" .. gc_fd)

if gc_fd >= 0 and gc_fd < 200 then
    local kptrs = {}
    local mapped = 0
    local failed = 0

    -- Try offsets: 0, 4K, 8K, ..., 1MB (in 16KB steps), then 1MB steps to 256MB
    local offsets = {}
    -- Fine scan: 0 to 1 MiB
    for i = 0, 63 do table.insert(offsets, i * PAGE) end
    -- Coarse scan: 1 MiB to 256 MiB
    for i = 1, 255 do table.insert(offsets, i * 0x100000) end
    -- Very coarse: 256 MiB to 4 GB
    for i = 1, 15 do table.insert(offsets, i * 0x10000000) end

    for _, off in ipairs(offsets) do
        local phi = math.floor(off / 0x100000000)
        local plo = off % 0x100000000
        local phys = uint64(string.format("0x%X%08X", phi, plo))

        local ok_m, rv = pcall(function()
            return sc_477(uint64(0), uint64(PAGE), uint64(1), uint64(1), uint64(gc_fd), phys)
        end)

        if ok_m and rv then
            local rh, rl = get_hi_lo(rv)
            if rh < 0 then rh = rh + 0x100000000 end
            if rh == 0xFFFFFFFF then
                failed = failed + 1
            else
                mapped = mapped + 1
                -- Read first 4 qwords
                local has_kptr = false
                for qi = 0, 3 do
                    local v = rq(N(rv) + qi * 8)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh < 0 then vh = vh + 0x100000000 end
                        if vl < 0 then vl = vl + 0x100000000 end
                        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                            table.insert(kptrs, {off, qi * 8, vh, vl})
                            has_kptr = true
                        end
                    end
                end

                -- Print interesting pages
                if has_kptr or mapped <= 5 then
                    local d = rd(N(rv))
                    local q = rq(N(rv))
                    if d then
                        if d < 0 then d = d + 0x100000000 end
                    end
                    print(string.format("  off=0x%X: d=0x%08X q=%s%s",
                        off, d or 0, fmt(q), has_kptr and " *** KPTR ***" or ""))
                end

                pcall(function() sc_73(rv, uint64(PAGE)) end)
            end
        else
            failed = failed + 1
        end
    end

    print(string.format("  mapped=%d failed=%d kptrs=%d", mapped, failed, #kptrs))
    for i, k in ipairs(kptrs) do
        if i > 20 then break end
        print(string.format("    off=0x%X+0x%X: 0x%08X%08X", k[1], k[2], k[3], k[4]))
    end

    pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)
end

-- ============================================================
-- [B] Check what dmem0 offset 0 really is
-- ============================================================
print("")
print("[B] dmem0 offset 0 investigation")
local dm_fd = open_dev("/dev/dmem0")
if dm_fd >= 0 then
    local rv, st = nil, ""
    local ok_m, rv_r = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(3), uint64(1), uint64(dm_fd), uint64(0))
    end)
    if ok_m and rv_r then
        local rh, rl = get_hi_lo(rv_r)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then
            -- Dump first 128 bytes
            for i = 0, 15 do
                local v = rq(N(rv_r) + i * 8)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh < 0 then vh = vh + 0x100000000 end
                    if vl < 0 then vl = vl + 0x100000000 end
                    local tag = ""
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then tag = " <KPTR>" end
                    if vh >= 1 and vh <= 0xFFF then tag = " <UPTR>" end
                    print(string.format("  [+0x%02X] 0x%08X%08X%s", i*8, vh, vl, tag))
                end
            end
            pcall(function() sc_73(rv_r, uint64(PAGE)) end)
        end
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)
end

-- ============================================================
-- [C] Scan process VM map for kernel pointer leaks
-- ============================================================
print("")
print("[C] Process VM map kernel pointer scan")
-- sys 674 returns the process VM map with 317 regions
-- Each region has: start, end, protection, name
-- Check if any region contains addresses near kernel space

local sc_674 = mk(674)
local vmbuf = memory.alloc(0x8000)
local vmlenbuf = memory.alloc(8)
wq(N(vmlenbuf), uint64(0x8000))

local ok_vm, rv_vm = pcall(function()
    return sc_674(uint64(vmbuf), uint64(N(vmlenbuf)))
end)

if ok_vm then
    local used = rd(N(vmlenbuf)) or 0
    print(string.format("  vm map: rv=%s used=%d bytes", fmt(rv_vm), used))

    -- Parse entries — each is variable size, but scan for kernel-like values
    local kptr_in_vm = 0
    for off = 0, math.min(used, 0x7FF8) - 8, 8 do
        local v = rq(N(vmbuf) + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                kptr_in_vm = kptr_in_vm + 1
                if kptr_in_vm <= 10 then
                    print(string.format("    off=0x%X: 0x%08X%08X KPTR", off, vh, vl))
                end
            end
        end
    end
    print(string.format("  kernel ptrs in vm map: %d", kptr_in_vm))
end

print("")
print("=== 528u DONE ===")
