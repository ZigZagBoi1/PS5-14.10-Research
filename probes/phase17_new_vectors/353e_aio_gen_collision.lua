-- CRASH_CLASS: LOW
-- PROBE 353e: AIO generation counter collision
--
-- 353a-353d2: AIO is synchronous (no race window), fd-close safe (fhold),
-- cancel/delete safe, unmap safe. Last angle: generation counter.
--
-- AIO IDs are generation-tagged (high bits = generation). If we can
-- make the counter wrap or collide, a stale ID might reference a
-- reused slot → UAF-like confusion.
--
-- Test: burn through many AIO IDs rapidly, look for wrap/reuse patterns.
-- Also: submit with spoofed/stale IDs to poll/delete, check behavior.

print("=== PROBE 353e: AIO GENERATION COLLISION ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sc_open   = mk(5)
local sc_close  = mk(6)
local sc_aio    = mk(669)
local sc_poll   = mk(664)
local sc_del    = mk(662)

-- Open /dev/zero
local path_buf = memory.alloc(16)
for i = 1, 9 do wd(N(path_buf) + i - 1, string.byte("/dev/zero", i)) end
wd(N(path_buf) + 9, 0)
local fd_ret = nil
pcall(function() fd_ret = sc_open(path_buf, uint64(0), uint64(0)) end)
local zero_fd = fd_ret and N(fd_ret) or -1
print("zero_fd=" .. zero_fd)

local req_buf  = memory.alloc(0x30)
local id_buf   = memory.alloc(0x10)
local res_buf  = memory.alloc(0x100)
local poll_buf = memory.alloc(0x20)

-- ============ TEST A: Burn IDs, find pattern ============
print("")
print("[A] Burn 200 AIO IDs — find generation pattern")

local ids = {}
local id_hi_set = {}

for i = 1, 200 do
    if not alive() then print("  DEAD at i=" .. i); break end

    for off = 0, 0x2C, 4 do wd(N(req_buf) + off, 0) end
    wd(N(req_buf), zero_fd)
    wq(N(req_buf) + 0x08, uint64(string.format("0x%X", N(res_buf))))
    wq(N(req_buf) + 0x10, uint64(16))
    wq(N(req_buf) + 0x18, uint64(0))

    wq(N(id_buf), uint64(0))
    pcall(function()
        sc_aio(uint64(1), req_buf, uint64(1), uint64(1), id_buf)
    end)

    local id_lo = rd(N(id_buf)) or 0
    local id_hi = rd(N(id_buf) + 4) or 0

    table.insert(ids, {lo = id_lo, hi = id_hi})
    id_hi_set[id_hi] = (id_hi_set[id_hi] or 0) + 1
end

-- Analyze pattern
print(string.format("  collected %d IDs", #ids))

if #ids > 0 then
    local first = ids[1]
    local last = ids[#ids]
    print(string.format("  first: lo=0x%X hi=0x%X", first.lo, first.hi))
    print(string.format("  last:  lo=0x%X hi=0x%X", last.lo, last.hi))

    -- Check if hi (generation) changes
    local hi_vals = {}
    for hi, cnt in pairs(id_hi_set) do
        table.insert(hi_vals, {hi = hi, cnt = cnt})
    end
    table.sort(hi_vals, function(a, b) return a.hi < b.hi end)
    print(string.format("  distinct hi values: %d", #hi_vals))
    for _, v in ipairs(hi_vals) do
        print(string.format("    hi=0x%X count=%d", v.hi, v.cnt))
    end

    -- Check lo (slot index) for reuse
    local lo_seen = {}
    local reuse_count = 0
    for _, id in ipairs(ids) do
        if lo_seen[id.lo] then
            reuse_count = reuse_count + 1
        end
        lo_seen[id.lo] = true
    end
    print(string.format("  slot reuse: %d times in %d IDs", reuse_count, #ids))

    -- Check if IDs are monotonically increasing
    local mono = true
    for i = 2, #ids do
        local prev = ids[i-1].lo + ids[i-1].hi * 0x100000000
        local curr = ids[i].lo + ids[i].hi * 0x100000000
        if curr <= prev then mono = false; break end
    end
    print(string.format("  monotonic: %s", tostring(mono)))
end

-- ============ TEST B: Poll/delete with stale IDs ============
print("")
print("[B] Poll/delete with stale/spoofed IDs")

if alive() and #ids >= 10 then
    -- Try polling the FIRST id (should be stale now)
    local stale = ids[1]
    for off = 0, 0x1C, 4 do wd(N(poll_buf) + off, 0) end
    wd(N(poll_buf), stale.lo)
    wd(N(poll_buf) + 4, stale.hi)
    pcall(function() sc_poll(poll_buf, uint64(1), uint64(0)) end)
    local st = rd(N(poll_buf) + 4) or -1
    print(string.format("  stale poll (id lo=0x%X hi=0x%X): state=0x%X", stale.lo, stale.hi, st))

    -- Delete stale ID
    for off = 0, 0x1C, 4 do wd(N(poll_buf) + off, 0) end
    wd(N(poll_buf), stale.lo)
    pcall(function() sc_del(poll_buf, uint64(1), uint64(0)) end)
    local del_st = rd(N(poll_buf) + 4) or -1
    print(string.format("  stale delete: state=0x%X", del_st))

    -- Spoofed IDs: try IDs that were never issued
    local spoofed_ids = {0xDEAD, 0xFFFF, 0x0, 0x1, 0x7FFFFFFF}
    for _, sid in ipairs(spoofed_ids) do
        for off = 0, 0x1C, 4 do wd(N(poll_buf) + off, 0) end
        wd(N(poll_buf), sid)
        pcall(function() sc_del(poll_buf, uint64(1), uint64(0)) end)
        local d_st = rd(N(poll_buf) + 4) or -1
        print(string.format("  spoofed delete 0x%X: state=0x%X", sid, d_st))
    end

    -- Try to reuse a recently-freed slot by submitting many more
    print("")
    print("  submitting 50 more to force slot wrap...")
    local new_ids = {}
    for i = 1, 50 do
        for off = 0, 0x2C, 4 do wd(N(req_buf) + off, 0) end
        wd(N(req_buf), zero_fd)
        wq(N(req_buf) + 0x08, uint64(string.format("0x%X", N(res_buf))))
        wq(N(req_buf) + 0x10, uint64(16))
        wq(N(req_buf) + 0x18, uint64(0))

        wq(N(id_buf), uint64(0))
        pcall(function()
            sc_aio(uint64(1), req_buf, uint64(1), uint64(1), id_buf)
        end)
        local lo = rd(N(id_buf)) or 0
        local hi = rd(N(id_buf) + 4) or 0
        table.insert(new_ids, {lo = lo, hi = hi})
    end

    -- Check if any new ID matches a stale lo value
    local old_lo_set = {}
    for _, id in ipairs(ids) do old_lo_set[id.lo] = id.hi end

    local collisions = 0
    for _, nid in ipairs(new_ids) do
        local old_hi = old_lo_set[nid.lo]
        if old_hi then
            collisions = collisions + 1
            local same_gen = (old_hi == nid.hi)
            if collisions <= 5 then
                print(string.format("  COLLISION: lo=0x%X old_hi=0x%X new_hi=0x%X same=%s",
                    nid.lo, old_hi, nid.hi, tostring(same_gen)))
            end
        end
    end
    print(string.format("  slot collisions: %d/50 (same gen = confusion risk)", collisions))
end

pcall(function() sc_close(uint64(zero_fd)) end)

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 353e COMPLETE ===")
