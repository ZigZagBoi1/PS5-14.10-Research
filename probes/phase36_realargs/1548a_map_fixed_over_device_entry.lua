-- CRASH_CLASS: HIGH -- [B] performs eight 548 op 3 MAP_FIXED carves that each delete a page out of
-- a device-backed vm_map entry, which is the exact operation whose reference accounting is under
-- test. If that accounting is wrong the kernel panics or the game dies and the console needs a
-- relaunch. Nothing here writes into device memory: the only device-page access is a read of the
-- register frame in [A]/[E], and [D] reads an address only after a 547 record covers it.
-- PROBE 1548a: does 548 op 3 MAP_FIXED over a device-backed entry corrupt the pager's reference?
--
-- WHAT IS ALREADY TRUE, and why this is the next question.
--   * 548 op 1 is a precise munmap that SPLITS (1544a: one 0x40000 mapping, unmap one 0x4000 page,
--     the neighbours survive and 547 says so). op 3 is an anonymous map, and with arg2 bit 0x10
--     (MAP_FIXED) it carves an existing entry the same way -- 1512a measured a 16 MiB anonymous
--     entry at 0x3110AC000 splitting into 0x4000 / 0x4000 / 0xFF8000 with the middle page zeroed.
--   * /dev/dmem0 maps at 4 KiB offset granularity into a 0x4000 frame, one vm_map entry per mapping,
--     and its 547 record carries flags = 0x10020 (1547a), while anonymous entries carry 0x610020
--     (1512a/1513a). The field is reported at [C] but it is NOT a general object-type test -- 1533a
--     shows the SceGnmTrapData DEVICE window also reporting 0x610020 -- so the decisive observation
--     is [D]'s content read of device offset 0, which is the register dword 0xC0012800 for a device
--     frame and 0 for an anonymous page.
--   * Nobody has carved a DEVICE entry before. A split of a device entry has to hand the device
--     object's reference to two surviving entries and then drop the reference held by the page that
--     became anonymous. That is where a reference-count error would live.
--
-- THE SHAPES THIS RUN SEPARATES.
--   1. [B] returns rv == the requested address with a boundary check passing (the entry above each
--      carve starts exactly at the carve), [C] shows the carved pages at flags 0x610020 with the
--      tail still at 0x10020, and [E] re-maps the node and still reads 0xC0012800 -> the
--      split/release is correct for every accepted carve. A clean negative that closes the
--      composition. Without the boundary check a whole-entry delete would read as success.
--   2. [B] returns rv>0, [C] shows the flip, but [E] refuses the node or reads something other than
--      0xC0012800 -> the device object was over-released. That is a real bug and the reason to run.
--   3. [B] returns EBUSY/EINVAL or [C] shows no flip -> op 3 refuses to carve an object it does not
--      own, and there is nothing here.
--   4. The kernel dies at any point in [B] -> the delete path faults on a device entry. Also a
--      finding, and the cheapest possible one.
--
-- WHY EIGHT CARVES AND NOT ONE. One carve exercises the split path once. The carve order is
-- 8,4,12,2,6,10,14,1: each of the first seven is the midpoint of a surviving device entry, so every
-- one of them is an interior split with device-backed neighbours on both sides, and the split/release
-- path runs seven times instead of once. The eighth is an end clip, which exercises the other branch.
-- A one-in-N reference error becomes something the capture sees; the cost of a failure is the same
-- either way, because the first bad delete already breaks.
--
-- Prior art:
--   results/phase36_realargs/1547a_dmem_frame_straddle_20261110_165645.txt (dmem 547 flags = 0x10020)
--   results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt (op 3 MAP_FIXED splits an anon entry)
--   results/phase36_realargs/1513a_sys548_op3_vnode_clip_20261109_230353.txt (anon/carved flags = 0x610020)
--   results/phase36_realargs/1544a_munmap_pte_scope_20261110_162901.txt (precise split, page size 0x4000)
--   results/phase36_realargs/1537b_sys548_op4_and_op0_semantics_20261110_151410.txt (op 3 with MAP_FIXED works)
--   results/phase36_realargs/1481b_gpu_windows_write_20261109_201732.txt (device frames are per-frame)
--   docs/VM_LAYER_14_10.md sections 14-15, docs/DMEM_WINDOW_14_10.md section 6
--
-- WHAT THIS CANNOT SHOW. 547 reports an entry's address range, protection and flags, not the object
-- behind it, so a replace that produced an identical record would be invisible -- flags is the field
-- that makes it visible, and [D]'s content read is the second opinion. A clean run proves the
-- accounting survives eight same-mapping carves; it does not prove it survives an unmapping of the
-- whole entry or a second descriptor.

print("=== PROBE 1548a: 548 op 3 MAP_FIXED over a device-backed vm_map entry ===")
print("")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

-- SIG_IGN on the signals a bad syscall can raise, so a refused call answers instead of killing us.
local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
local sig_ok = 0
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    local ok, r = pcall(function() return N(mk(416)(uint64(s), uint64(sa), uint64(0))) end)
    if ok and r == 0 then sig_ok = sig_ok + 1 end
end
print(string.format("[0] SIG_IGN accepted on %d/10 signals", sig_ok))

local sc_open, sc_close = mk(5), mk(6)
local sc_mmap, sc_munmap = mk(477), mk(73)
local sc_547, sc_548 = mk(547), mk(548)
local O_RDWR, PROT_RW, MAP_SHARED = 2, 3, 1
local PAGE = 0x4000
local DEV_FLAGS, ANON_FLAGS = 0x10020, 0x610020

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return N(b)
end

-- 547's record is {start_lo, start_hi, end_lo, end_hi, prot, flags} at 0x18 bytes (1362a; corrected
-- in docs/ARG23_CLASSES_14_10.md:74 -- the old +0x04 "prot" was the high dword of the start).
local REC = memory.alloc(0x40)
local function rec(addr)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(REC + i, 0xDEADBEEF) end) end
    local ok, rv = pcall(function() return N(sc_547(uint64(addr), uint64(N(REC)), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    if not ok or rv ~= 0 then return nil end
    -- An unfilled record must not be read as an entry: a 547 that answered 0 without writing would
    -- otherwise surface as start=DEADBEEFDEADBEEF and be classified as a third flags value.
    if N(memory.read_dword(REC + 0x00)) == 0xDEADBEEF then return nil end
    local sl = N(memory.read_dword(REC + 0x00)) + N(memory.read_dword(REC + 0x04)) * 4294967296
    local el = N(memory.read_dword(REC + 0x08)) + N(memory.read_dword(REC + 0x0C)) * 4294967296
    return sl, el, N(memory.read_dword(REC + 0x10)), N(memory.read_dword(REC + 0x14))
end
local function show(tag, addr)
    local sl, el, pr, fl = rec(addr)
    if sl == nil then
        print(string.format("    %-22s 547 refused", tag))
        return nil
    end
    print(string.format("    %-22s start=%X end=%X prot=%X flags=%X len=%X", tag, sl, el, pr, fl, el - sl))
    return sl, el, pr, fl
end
local function covered_pr(addr)
    local sl, el, pr = rec(addr)
    if sl == nil then return nil end
    if addr >= sl and addr < el and pr ~= nil and pr ~= 0 then return pr end
    return nil
end

local fd = -1
do
    local p = str_addr("/dev/dmem0")
    local ok, v = pcall(function() return N(sc_open(uint64(p), uint64(O_RDWR), uint64(0), uint64(0), uint64(0), uint64(0))) end)
    if ok then fd = v end
end
print(string.format("[0] /dev/dmem0 fd=%d", fd))
if fd <= 0 then print("[!] no descriptor; aborting"); print("=== PROBE 1548a ABORTED ===") return end

local function try_map(off, len, prot)
    local ok, v = pcall(function()
        return N(sc_mmap(uint64(0), uint64(len), uint64(prot), uint64(MAP_SHARED), uint64(fd), uint64(off)))
    end)
    if not ok then return nil, -999, "pcall" end
    if v < 0x1000 or v > 549755813888 then return nil, v, es() end
    return v, v, es()
end
local function drop(va, len)
    if va == nil then return nil end
    local ok, rv = pcall(function()
        return N(sc_munmap(uint64(va), uint64(len), uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    if ok then return rv end
    return nil
end

-- 548's entry is 0x20 bytes: {start@0x00, offset@0x08, length@0x10, prot@0x18 dword, op@0x1C byte}.
local ENT = memory.alloc(0x40)
local OUT = memory.alloc(0x40)
local function set_entry(start, off, len, prot, op)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(ENT + i, 0) end) end
    pcall(function() memory.write_qword(ENT + 0x00, uint64(start)) end)
    pcall(function() memory.write_qword(ENT + 0x08, uint64(off)) end)
    pcall(function() memory.write_qword(ENT + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ENT + 0x18, prot) end)
    pcall(function() memory.write_byte(ENT + 0x1C, op) end)
end
-- arg1 is the descriptor and is ignored by op 3; arg2 is the flag word; arg3 the entry array;
-- arg4 the count; arg5 the processed-count output.
local function batch(entry, count, arg2)
    pcall(function() memory.write_dword(OUT, 0xEEEEEEEE) end)
    local ok, rv = pcall(function()
        return N(sc_548(uint64(0), uint64(arg2), uint64(entry), uint64(count), uint64(N(OUT)), uint64(0)))
    end)
    local processed = N(memory.read_dword(OUT))
    if not ok then return -999, processed, "pcall" end
    return rv, processed, es()
end

-- ---------------------------------------------------------------------------------------------
-- [A] one device mapping, sixteen frames, and its record
-- ---------------------------------------------------------------------------------------------
print("")
print("[A] map /dev/dmem0 offset 0, len 0x40000, prot 3")
local D, dmap, derr = try_map(0, 0x40000, PROT_RW)
if D == nil then
    print(string.format("    mmap refused: %s (%s); aborting", tostring(dmap), tostring(derr)))
    pcall(function() return sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print("=== PROBE 1548a ABORTED ===")
    return
end
print(string.format("    D = %X (aligned=%s)", D, tostring(D % PAGE == 0)))
local s0, e0, p0, f0 = show("[A] 547(D)", D)
if s0 == nil or e0 == nil or e0 - s0 ~= 0x40000 then
    print("    the record is not the single 0x40000 entry this probe needs; aborting")
    drop(D, 0x40000)
    pcall(function() return sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print("=== PROBE 1548a ABORTED ===")
    return
end
print(string.format("    record flags = %X (%s)", f0,
    (f0 == DEV_FLAGS and "device") or (f0 == ANON_FLAGS and "ANONYMOUS -- not a device mapping") or "unrecognised"))
local d0 = nil
print(string.format("    [A] about to read %X", D))
do
    local ok, v = pcall(function() return memory.read_dword(D) end)
    if ok then d0 = N(v) end
end
print(string.format("    [A] dword at D = %s (expect C0012800, the GPU register frame)", d0 and string.format("%08X", d0) or "FAULT"))
if d0 == nil then
    print("    the device frame is not readable; nothing below is attributable. aborting")
    drop(D, 0x40000)
    pcall(function() return sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print("=== PROBE 1548a ABORTED ===")
    return
end

-- ---------------------------------------------------------------------------------------------
-- [B] eight MAP_FIXED carves, each deleting one device-backed page
-- ---------------------------------------------------------------------------------------------
print("")
print("[B] eight 548 op3 MAP_FIXED carves at D + i*0x4000 (each deletes one device-backed page)")
print("    order 8,4,12,2,6,10,14,1 -- the first seven are each the midpoint of a surviving device")
print("    entry, so the middle-split release path runs seven times; the last is an end clip")
local ORDER = {8, 4, 12, 2, 6, 10, 14, 1}
local carves, taken, split = 0, 0, 0
for k = 1, #ORDER do
    local i = ORDER[k]
    local at = D + i * PAGE
    set_entry(at, 0, PAGE, PROT_RW, 3)
    print(string.format("    [B%d] carve %X ...", i, at))
    local rv, processed, err = batch(N(ENT), 1, 0x10)
    carves = carves + 1
    if rv == at then
        taken = taken + 1
    elseif rv ~= nil and rv >= 0 then
        print(string.format("    [B%d] accepted at %X, not at the requested carve address", i, rv))
    end
    print(string.format("    [B%d] rv=%s info=%s processed=%d", i, tostring(rv),
        tostring((rv == -1) and err or "ok"), processed))
    -- The split test 1512a established: after a carve, the entry above the carve starts exactly at
    -- the carve address. No entry there means the whole entry was deleted, not split, and a later
    -- "replacement" reading would describe a page op 3 created out of a hole.
    if rv == at then
        local nsl = rec(at + PAGE)
        if nsl == nil then
            print(string.format("    [B%d] no entry above the carve: the entry was deleted, not split", i))
            break
        elseif nsl == at + PAGE then
            split = split + 1
        else
            print(string.format("    [B%d] no boundary at the carve start: page not replaced", i))
        end
    end
end
print(string.format("    [B] carves attempted=%d accepted=%d boundary-ok=%d", carves, taken, split))
if taken == 0 then
    print("    no carve was accepted: op 3 refuses to replace a device entry. There is nothing here.")
end

-- ---------------------------------------------------------------------------------------------
-- [C] what each page's record says now -- flags is the discriminator
-- ---------------------------------------------------------------------------------------------
print("")
print("[C] 547 across the sixteen frames after the carves")
local dev_pages, anon_pages, other_pages, absent = 0, 0, 0, 0
for i = 0, 15 do
    local at = D + i * PAGE
    local sl, el, pr, fl = rec(at)
    if sl == nil then
        absent = absent + 1
    elseif fl == ANON_FLAGS then
        anon_pages = anon_pages + 1
    elseif fl == DEV_FLAGS then
        dev_pages = dev_pages + 1
    else
        other_pages = other_pages + 1
    end
    if sl == nil then
        print(string.format("    page %2d %X  no entry", i, at))
    else
        print(string.format("    page %2d %X  start=%X end=%X prot=%X flags=%X", i, at, sl, el, pr, fl))
    end
end
print(string.format("    [C] totals: anon=%d device=%d other=%d absent=%d", anon_pages, dev_pages, other_pages, absent))
local changed = (anon_pages + absent) > 0
if absent > 0 and anon_pages == 0 then
    print("    [C] VERDICT: DESTROYED -- the carved pages have no entry at all, so the device entry")
    print("        was deleted rather than split. A later 'replacement' reading would describe op 3")
    print("        filling a hole, not replacing a page.")
elseif not changed then
    print("    [C] VERDICT: NOTHING CHANGED -- no carved page flipped to an anonymous entry.")
    print("        op 3 accepted the request without replacing the device entry (or [B] was refused).")
    print("        [D]/[E] below cannot test a replacement that did not happen; they still run as controls.")
elseif other_pages > 0 then
    print("    [C] VERDICT: MIXED -- some page carries a flags value that is neither the dmem value")
    print("        nor the anonymous value. The table above names it; no single reading covers this run.")
else
    print("    [C] VERDICT: REPLACED -- the carved pages no longer carry the dmem flag 0x10020.")
    print("        CAUTION: flags is NOT a general object-type test. 1533a records flags=0x610020 for")
    print("        BOTH an anonymous entry and the SceGnmTrapData device window, so 0x610020 does not")
    print("        mean 'anonymous' -- it only means 'not this dmem mapping'. The flip is consistent")
    print("        with a replacement, not proof of one. [D] decides, because the dmem frame at device")
    print("        offset 0 holds the register dword 0xC0012800 and an anonymous page reads 0.")
end

-- ---------------------------------------------------------------------------------------------
-- [D] content of the carved page, gated on its own record
-- ---------------------------------------------------------------------------------------------
print("")
print("[D] content reads, each gated on a 547 record that covers that exact address")
local function gated_read(tag, at)
    print(string.format("    [D] about to read %X", at))
    local pr = covered_pr(at)
    if pr == nil then
        print(string.format("    %-22s no covering entry; skipped", tag))
        return nil
    end
    local ok, v = pcall(function() return memory.read_dword(at) end)
    if not ok then
        print(string.format("    %-22s read raised a Lua error, not a fault (a fault kills the loader)", tag))
        return nil
    end
    print(string.format("    %-22s %08X", tag, N(v)))
    return N(v)
end
-- Page 8 was carved first and is interior, so it is the page that must now be anonymous. Page 0
-- was never carved and is the control that the surviving neighbours still map device memory.
local DCARVED = D + 8 * PAGE
local dpage = gated_read("carved page 8", DCARVED)
local dkeep = gated_read("uncarved page 0", D)
if dpage ~= nil then
    if dpage == 0 and d0 ~= 0 then
        print("    the carved page reads 0: an anonymous page replaced the device frame there.")
    elseif dpage == 0 then
        print("    the device frame itself reads 0, so a zero here proves nothing either way.")
    elseif dpage == d0 then
        if taken == 0 then
            print("    the carved page is unchanged, but no carve was accepted; the frame was never touched.")
        else
            print("    the carved page still reads the device dword: the frame survived the carve.")
        end
    else
        print(string.format("    the carved page reads %08X: neither zero nor the original device dword.", dpage))
    end
end
if dkeep ~= nil then
    if dkeep == d0 and d0 ~= 0 then
        print("    the uncarved page 0 still reads the device dword: the surviving neighbours are intact.")
    else
        print(string.format("    the uncarved page 0 reads %08X, not %08X: an uncarved page changed too.", dkeep, d0))
    end
end

-- ---------------------------------------------------------------------------------------------
-- [E] does the device object still work after eight deletes?
-- ---------------------------------------------------------------------------------------------
print("")
print("[E] re-map the node after the carves: is the pager object still usable?")
local E, emap, eerr = try_map(0, PAGE, PROT_RW)
if E == nil then
    print(string.format("    re-map refused: %s (%s)", tostring(emap), tostring(eerr)))
    if not changed or taken == 0 then
        print("    [E] VERDICT: the node refuses a new mapping, but no replacement happened in [C], so")
        print("        this is a mapping-shape result (length or per-node limit), not pager evidence.")
    else
        print("    [E] VERDICT: the node refuses a mapping after a replacement. A pager refcount fault")
        print("        is one explanation; an ACL or a per-node mapping limit is another.")
    end
else
    local ep = covered_pr(E)
    print(string.format("    E = %X covering prot=%s", E, tostring(ep)))
    local er = gated_read("E first dword", E)
    if er == nil then
        print("    [E] VERDICT: 547 does not describe the fresh mapping, so nothing is concluded from it.")
    elseif er == d0 then
        if changed and split > 0 then
            print(string.format("    [E] VERDICT: the node still maps and still reads the register frame after %d", taken))
            print("        accepted, boundary-checked carves. The object was not freed; an over-release")
            print("        that leaves it alive is not excluded by a content read.")
        else
            print("    [E] VERDICT: reads the register frame, but [C] saw no checked replacement, so this")
            print("        only restates that the mapping was never changed. It tests nothing.")
        end
    else
        print(string.format("    [E] VERDICT: reads %08X instead of %08X -- the frame behind a fresh", er, d0))
        print("        mapping changed after the carves. That is an inconsistency worth chasing.")
    end
    drop(E, PAGE)
end

-- ---------------------------------------------------------------------------------------------
-- [F] teardown
-- ---------------------------------------------------------------------------------------------
print("")
print("[F] teardown")
local drv = drop(D, 0x40000)
pcall(function() return sc_close(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
local sl2 = rec(D)
print(string.format("    munmap rv=%s; 547(D) after munmap: %s",
    tostring(drv), sl2 == nil and "no entry" or "STILL MAPPED"))
print("")
print(string.format("=== PROBE 1548a COMPLETE pid=%s carves=%d accepted=%d boundary-ok=%d anon=%d device=%d absent=%d ===",
    tostring(PID), carves, taken, split, anon_pages, dev_pages, absent))
