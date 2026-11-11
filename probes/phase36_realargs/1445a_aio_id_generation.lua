-- CRASH_CLASS: LOW
-- PROBE 1445a: AIO request id — does the slot generation counter survive a delete
--
-- Why: a public analysis of the 14.20 fix says aio_multi_delete (662) drops its
-- table lock, re-looks-up the slot, and then frees the sub-objects of whatever
-- object it finds.  docs/AIO_DOUBLE_FREE_14_10.md retracted that as a
-- "double STATUS, not double free", but its evidence only ever raced 662
-- against 662.  The remaining deterministic question is cheaper than the race:
-- what does the id encode, and does the per-slot generation counter persist
-- across a delete?
--
-- 13.60 disassembly of aio_multi_delete at 0xffffffff8ad6f900 decodes an id as
--   gen  = (id >> 16) & 0x7f      (must be < 0x80)
--   slot =  id & 0xffff
-- and indexes entry->array[gen].  It also requires gen < word[entry] before it
-- will touch the slot, so the counter is what defends a stale id.  A third
-- decoder in the re-lookup helper at 0xffffffff8ad5a2a0 packs
--   ((dword[entry+0x28] & 7) << 13) | slot
-- i.e. three bits.  If the counter PERSISTS and only three of its bits reach
-- the id, then after 8 reuses of one slot an old id aliases a live object with
-- no race at all.  If the counter is reset by the delete, the entry is
-- recreated each cycle and the alias is unreachable.
--
-- What is measured here, all sequential, no threads:
--   [A] 12 submit -> poll -> delete cycles on the same socketpair, printing the
--       raw id each cycle plus both decodings, and whether the slot number is
--       stable (LIFO reuse) or moves.
--   [B] 8 submits held open at the same time, printing the slot allocation
--       order — the control that shows whether slots are handed out by index.
--   [C] the survivor check: after [A], one more submit must still be accepted.
--
-- Nothing here frees a live object.  The delete is only ever issued for an id
-- that 664 has already reported on, which is the established 65l/70e shape.
--
-- prior art:
--   probes/phase16_kwrite/65l_aio_race_fixed.lua        (662 vs 662, 65 status doubles)
--   probes/phase16_kwrite/70e_race_refcount_impact.lua  (refcount unchanged, retraction)
--   probes/phase16_kwrite/71a_aio_id_reuse_3thread.lua  (3-bit generation claim)
--   probes/phase17_new_vectors/465a_aio_complete_then_delete.lua (669/664 shapes)
--   docs/AIO_DOUBLE_FREE_14_10.md, docs/AIO_GATE_14_10.md, docs/AIO_BATCH_14_10.md
--   results/INDEX.md rows 65d-65w, 70d/70e, 71a, 352a-352k, 125a, 524a
--   static: 13.60 kernel_text 0xffffffff8ad6f900 (662 body),
--           0xffffffff8ad59ee0 (first lookup), 0xffffffff8ad5a2a0 (re-lookup)

print("=== PROBE 1445a: AIO ID GENERATION ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function sgn(v)
    if type(v) ~= "table" or not v.h then
        local n = tonumber(v) or 0
        if n < 0 then return -1 end
        return n
    end
    local h = tonumber(v.h) or 0
    local l = tonumber(v.l) or 0
    if h == -1 or h == 0xFFFFFFFF then
        if l == -1 or (l % 4294967296) == 0xFFFFFFFF then return -1 end
    end
    if h ~= 0 then return nil end
    return l
end
local function fmt(v)
    if v == nil then return "BIG" end
    return tostring(v)
end
local function rd(a) return N(memory.read_dword(uint64(a))) end
local function wr(a, v) memory.write_dword(uint64(a), uint64(v)) end
local function wrq(a, v) memory.write_qword(uint64(a), uint64(v)) end

local sc_mmap = mk(477)
local AIO_SUB = mk(669)
local AIO_POLL = mk(664)
local AIO_DEL = mk(662)
local GETPID = mk(20)

print(string.format("canary getpid=%s", fmt(sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))))))

local p = N(sc_mmap(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if p < 0x10000 or p > 0x8000000000 then
    print(string.format("mmap failed (%s)", tostring(p)))
    return
end
for i = 0, 0x7FFF, 8 do wrq(p + i, uint64(0)) end

local REQ = p
local DATA = p + 0x100
local RESULT = p + 0x200
local IDS = p + 0x300
local STATE = p + 0x400
local IDS8 = p + 0x500
local STATE8 = p + 0x800
local PAIR = p + 0xC00
local REQ8 = p + 0x1000

local sp = sgn(mk(135)(uint64(1), uint64(1), uint64(0), uint64(PAIR), uint64(0), uint64(0)))
local rd_fd = rd(PAIR)
local wr_fd = rd(PAIR + 4)
print(string.format("[0] socketpair rv=%s read=%d write=%d", fmt(sp), rd_fd, wr_fd))
if rd_fd <= 0 then print("socketpair failed"); return end

local function arm_req(base)
    for i = 0, 0x20, 8 do wrq(base + i, uint64(0)) end
    wrq(base + 0x08, 16)          -- byte count
    wrq(base + 0x10, DATA)        -- destination buffer
    wrq(base + 0x18, RESULT)      -- result word
    wr(base + 0x20, 0xFFFFFFFF)   -- fd patched by caller
end

-- one datagram is waiting so a read request can complete immediately
local payload = memory.alloc(16)
for i = 0, 15 do memory.write_byte(payload + i, 0x41 + i) end
local wrote = sgn(mk(4)(uint64(wr_fd), uint64(payload), uint64(16), uint64(0), uint64(0), uint64(0)))
print(string.format("    seeded %s bytes into fd %d", fmt(wrote), wr_fd))

local function submit_one(fd)
    arm_req(REQ)
    wr(REQ + 0x20, fd)
    wr(IDS, 0)
    wrq(RESULT, 0)            -- 669 reports a refusal only in the result word, never in rv
    local rv = sgn(AIO_SUB(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
    return rv, rd(IDS), rd(RESULT)
end
local function poll_one()
    local idv = rd(IDS)
    wr(STATE, 0x5A5A5A5A)
    local rv = sgn(AIO_POLL(uint64(IDS), uint64(1), uint64(STATE)))
    return rv, rd(STATE), idv
end
local function del_one()
    wr(STATE, 0x5A5A5A5A)
    local rv = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
    return rv, rd(STATE), rd(IDS)
end

print("")
print("[A] 12 sequential submit -> poll -> delete cycles on one socketpair")
print("    cyc  rv669 id        slot   gen16  gen13  rv664 state664  rv662 state662 id_after")

for cyc = 1, 12 do
    local rv669, id, res669 = submit_one(rd_fd)
    local slot = id % 0x2000
    local gen16 = math.floor(id / 0x10000) % 0x80
    local gen13 = math.floor(id / 0x2000) % 8
    local rv664, st664 = poll_one()
    local rv662, st662, ida = del_one()
    print(string.format("    %2d   %-5s 0x%08X %5d  %5d  %5d  %-5s 0x%08X  %-5s 0x%08X 0x%08X",
        cyc, fmt(rv669), id, slot, gen16, gen13,
        fmt(rv664), st664, fmt(rv662), st662, ida))
    -- keep the socket fed: one 16-byte datagram per cycle
    if wrote then pcall(function() mk(4)(uint64(wr_fd), uint64(payload), uint64(16), uint64(0), uint64(0), uint64(0)) end) end
    if rv669 == nil or rv669 == -1 or res669 ~= 0 or id == 0 then
        print(string.format("    submit refused (rv=%s result=0x%08X) -- stopping [A]", fmt(rv669), res669))
        break
    end
end

print("")
print("[B] 8 submits held open at once — slot allocation order")
for i = 0, 7 do wr(IDS8 + i * 4, 0) end
for i = 0, 7 do
    arm_req(REQ8 + 0x40 * i)
    wr(REQ8 + 0x40 * i + 0x20, rd_fd)
    local rv = sgn(AIO_SUB(uint64(1), uint64(REQ8 + 0x40 * i), uint64(1), uint64(1),
        uint64(IDS8 + i * 4), uint64(0)))
    local id = rd(IDS8 + i * 4)
    print(string.format("    req %d rv=%-5s id=0x%08X slot=%d gen16=%d gen13=%d",
        i, fmt(rv), id, id % 0x2000,
        math.floor(id / 0x10000) % 0x80, math.floor(id / 0x2000) % 8))
    pcall(function() mk(4)(uint64(wr_fd), uint64(payload), uint64(16), uint64(0), uint64(0), uint64(0)) end)
end
-- a refused submit leaves its id slot at 0, and id 0 decodes to context 0 / slot 0,
-- which the repo has never passed to 662.  Refuse to run the batch unless all 8 landed.
local bad8 = 0
for i = 0, 7 do if rd(IDS8 + i * 4) == 0 then bad8 = bad8 + 1 end end
if bad8 > 0 then
    print(string.format("    %d of 8 submits published no id -- skipping the batch poll/delete", bad8))
else
print("    polling all 8")
local rvp = sgn(AIO_POLL(uint64(IDS8), uint64(8), uint64(STATE8)))
print(string.format("    664 x8 rv=%s states=%08X %08X %08X %08X %08X %08X %08X %08X",
    fmt(rvp), rd(STATE8), rd(STATE8 + 4), rd(STATE8 + 8), rd(STATE8 + 12),
    rd(STATE8 + 16), rd(STATE8 + 20), rd(STATE8 + 24), rd(STATE8 + 28)))
print("    deleting all 8 in one call, then again in one call (double-delete control)")
local rvd1 = sgn(AIO_DEL(uint64(IDS8), uint64(8), uint64(STATE8)))
print(string.format("    662 #1 rv=%-5s states=%08X %08X %08X %08X %08X %08X %08X %08X",
    fmt(rvd1), rd(STATE8), rd(STATE8 + 4), rd(STATE8 + 8), rd(STATE8 + 12),
    rd(STATE8 + 16), rd(STATE8 + 20), rd(STATE8 + 24), rd(STATE8 + 28)))
local first = {}
for i = 0, 7 do first[i] = rd(STATE8 + i * 4) end
for i = 0, 7 do wr(STATE8 + i * 4, 0x5A5A5A5A) end
local rvd2 = sgn(AIO_DEL(uint64(IDS8), uint64(8), uint64(STATE8)))
print(string.format("    662 #2 rv=%-5s states=%08X %08X %08X %08X %08X %08X %08X %08X",
    fmt(rvd2), rd(STATE8), rd(STATE8 + 4), rd(STATE8 + 8), rd(STATE8 + 12),
    rd(STATE8 + 16), rd(STATE8 + 20), rd(STATE8 + 24), rd(STATE8 + 28)))

end

print("")
print("[C] survivor check")
pcall(function() mk(4)(uint64(wr_fd), uint64(payload), uint64(16), uint64(0), uint64(0), uint64(0)) end)
local rvS, idS = submit_one(rd_fd)
print(string.format("    669 rv=%-5s id=0x%08X slot=%d gen16=%d", fmt(rvS), idS,
    idS % 0x2000, math.floor(idS / 0x10000) % 0x80))
local rvP, stP = poll_one()
print(string.format("    664 rv=%-5s state=0x%08X result=0x%08X  pid=%s",
    fmt(rvP), stP, rd(RESULT), fmt(sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))))))

print("")
print("=== PROBE 1445a COMPLETE ===")
