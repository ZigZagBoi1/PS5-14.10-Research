-- CRASH_CLASS: LOW -- no byte is ever read out of a range whose backing is unknown; every report
-- comes from 547, which does not dereference. The only writes are into probe-owned buffers.
-- PROBE 1488b: sys 548 map ops take a descriptor from entry+0x08
--
-- 1480b swept ops 0/1/3/4 with {addr,0,0x4000,3} and got rv=0 processed=1 with no change on a
-- mapped page and EBUSY(16) at unmapped addresses, so with a zero +0x08 field those ops do nothing
-- useful. This probe asks the question 1480b did not: does +0x08 hold a DESCRIPTOR?
--
-- From the 13.60 body (RVA 0xabbe60, cases after `cmp ecx,4 / ja`), case A at 0x8b47bff3 does:
--   gate  [proc+0x1c9] >= 2
--   gate  ![proc+0x464] & 2
--   gate  !(entry[+0x08] & 0x400)
--   gate  [proc+0x5d4] >= 0x2500000         (a memory budget word)
--   build { start = entry[+0x00], len = entry[+0x10], -1, prot, entry[+0x08], entry[+0x08] }
--   call  0x8b47d540
-- and 0x8b47d540 hands that struct to 0x8b142a80 in a loop over the fd table, which is descriptor
-- resolution. The other two map cases build fd = -1 explicitly. So exactly one batch op carries a
-- caller descriptor, and if that descriptor can be /dev/dmem0 the map installs a real vm_map entry
-- onto the GPU aperture - the thing 628 mmap_dmem refused for every shape (122a/122a4).
--
-- [A] op 2 control on a page we own - 548 must move prot 3 -> 1 -> 3 or the probe stops
-- [B] open /dev/dmem0, /dev/gc, /dev/zero; print the descriptors
-- [C] op 0..4 with {hole, fd, 0x4000, 3} for each descriptor - does any op install an entry?
-- [D] op 0..4 with {0, fd, 0x4000, 3} so the kernel picks the address
-- every step reports only rv, errno, processed and the 547 record; nothing is dereferenced
--
-- -- prior art:
--   results/phase36_realargs/1480b_sys548_low_map_20261109_200449.txt (ops 0/1/3/4 with +0x08 = 0)
--   results/phase36_realargs/1479e_sys548_prot_matrix_20261109_195636.txt (len must be 0x4000)
--   probes/phase22_devices/122a_mmap_dmem_direct.lua and results/phase17_new_vectors/122a4_* (628 refused)
--   results/phase36_realargs/1481f_full_map_dump_20261109_201845.txt (the full 336-entry map)

print("=== PROBE 1488b: SYS 548 MAP OPS AND A DESCRIPTOR ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h, l = N(v.h), N(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return h * 4294967296 + l
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent = memory.alloc(0x40)
local done = memory.alloc(0x10)
local rec = memory.alloc(0x40)
local sc548 = mk(548)

local function fill_entry(addr, field8, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent + 0x00, uint64(string.format("0x%X", addr))) end)
    pcall(function() memory.write_qword(ent + 0x08, uint64(string.format("0x%X", field8))) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(string.format("0x%X", len))) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
end

-- 547 does not dereference; nil means "no entry covers this address"
local function map547(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function()
        return N(mk(547)(uint64(string.format("0x%X", addr)), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if not ok or rv ~= 0 then return nil end
    return string.format("start=0x%X%08X end=0x%X%08X prot=%d flags=%d",
        N(memory.read_dword(rec + 0x04)), N(memory.read_dword(rec + 0x00)),
        N(memory.read_dword(rec + 0x0C)), N(memory.read_dword(rec + 0x08)),
        N(memory.read_dword(rec + 0x10)), N(memory.read_dword(rec + 0x14)))
end

local function batch(op, addr, field8, len, prot)
    fill_entry(addr, field8, len, prot, op)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return N(sc548(uint64(0), uint64(0), uint64(ent), uint64(1), uint64(done), uint64(0)))
    end)
    if not ok then return "EXC", 0, "raised" end
    local pr = N(memory.read_dword(done))
    local e = ""
    if rv == -1 then e = es() end
    return rv, pr, e
end

local function open_path(s)
    local b = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    local ok, v = pcall(function()
        return mk(5)(uint64(b), uint64(0x4002), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return -1, "EXC" end
    return sgn(v), es()
end

-- ---------------------------------------------------------------- [A] control
print("")
print("--- [A] op 2 control on a page we own ---")
local ctl_ok = false
local ctlva = 0
do
    local va = sgn(mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if va > 0x10000 then
        ctlva = va
        local before = map547(va)
        print(string.format("  ctl 0x%X before: %s", va, tostring(before)))
        local rv, pr, e = batch(2, va, 0, 0x4000, 1)
        local after = map547(va)
        print(string.format("  op2 prot1 -> rv=%s processed=%d %s | after: %s", tostring(rv), pr, e, tostring(after)))
        if rv == 0 and after and after:find("prot=1") then ctl_ok = true end
        local rv2, pr2 = batch(2, va, 0, 0x4000, 3)
        print(string.format("  op2 prot3 -> rv=%s processed=%d", tostring(rv2), pr2))
    else
        print(string.format("  ctl mmap failed: %s", es()))
    end
end
print(string.format("[A] 548 control usable: %s", tostring(ctl_ok)))
if not ctl_ok then
    print("548 is not behaving as measured; stopping so nothing else is read as a negative")
    print("=== PROBE 1488b INCOMPLETE ===")
    return
end

-- ---------------------------------------------------------------- [B] descriptors
print("")
print("--- [B] open the device nodes ---")
local FDS = {}
for _, name in ipairs({"/dev/dmem0", "/dev/dmem1", "/dev/gc", "/dev/zero"}) do
    local fd, msg = open_path(name)
    print(string.format("  %-14s fd=%d %s", name, fd, fd < 0 and msg or ""))
    if fd >= 0 then FDS[#FDS + 1] = {name = name, fd = fd} end
end
FDS[#FDS + 1] = {name = "no-fd(-1)", fd = 0xFFFFFFFF}

-- a fresh 64 KiB aligned hole: map 0x10000 then munmap it. munmap is entry scoped (1450a), so the
-- whole entry goes and the address is free.
local HOLE = 0
do
    local h = sgn(mk(477)(uint64(0), uint64(0x10000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if h > 0x10000 then
        pcall(function() mk(73)(uint64(string.format("0x%X", h)), uint64(0x10000), uint64(0), uint64(0), uint64(0), uint64(0)) end)
        HOLE = h
        print(string.format("[0] hole 0x%X, 547 after unmap: %s", HOLE, tostring(map547(HOLE))))
    else
        print(string.format("[0] hole mmap failed: %s - [C] skipped, [D] still runs", es()))
    end
end

-- ---------------------------------------------------------------- [C] fd in entry+0x08
print("")
print("--- [C] ops 0..4 with entry+0x08 = a descriptor, fixed hole address ---")
if HOLE == 0 then
    print("  skipped: no hole")
else
    for _, d in ipairs(FDS) do
        for op = 0, 4 do
            local rv, pr, e = batch(op, HOLE, d.fd, 0x4000, 3)
            local m = map547(HOLE)
            print(string.format("  op%d fd=%-3s (%s) rv=%-3s processed=%s %s | %s",
                op, tostring(d.fd), d.name, tostring(rv), tostring(pr), e, tostring(m)))
        end
    end
end

-- ---------------------------------------------------------------- [D] kernel picks the address
print("")
print("--- [D] ops 0..4 with entry+0x08 = a descriptor, start = 0 ---")
for _, d in ipairs(FDS) do
    for op = 0, 4 do
        local rv, pr, e = batch(op, 0, d.fd, 0x4000, 3)
        -- a kernel-chosen map may write the address back into the entry
        local s0 = N(memory.read_dword(ent + 0x00))
        local s1 = N(memory.read_dword(ent + 0x04))
        print(string.format("  op%d fd=%-3s (%s) rv=%-3s processed=%s %s | entry<%08X%08X>",
            op, tostring(d.fd), d.name, tostring(rv), tostring(pr), e, s1, s0))
    end
end

-- ---------------------------------------------------------------- [E] re-read the control
print("")
print("--- [E] control page still reads as it did ---")
if ctlva > 0 then print(string.format("  ctl 0x%X: %s", ctlva, tostring(map547(ctlva)))) end

local final = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print("")
print(string.format("final canary: pid=%d (started %d)", final, PID))
print("=== PROBE 1488b COMPLETE ===")
