-- CRASH_CLASS: LOW
-- PROBE 531q: Does sigaction break thr_create?
--
-- 531p (no sigaction) works. 531o (with sigaction) dies.
-- Test: add sigaction to 531p and see if it breaks.

print("=== PROBE 531q: SIG TEST ===")
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
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)

-- [A] Test WITHOUT sigaction first
print("[A] Without sigaction")
do
    local info = memory.alloc(0x200)
    zero(info, 0x200)
    wd(info, 0x160)
    pcall(function() make_syscall(593)(uint64(0), info) end)
    local text_lo = rd(info + 0x108) or 0
    local text_hi = rd(info + 0x10C) or 0
    local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))

    local mov_rdi_rax_ret = eboot + uint64(0x92C67)
    local bare_ret = eboot + uint64(0x42)

    local ok_m1, marker = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local ok_m2, stack_base = pcall(function()
        return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    zero(marker, 0x4000)

    local stack_top = stack_base + 0x10000 - 0x100
    for off = 0, 0xF8, 8 do wq(stack_top + off, bare_ret) end

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480))
    wd(ctx + 0x0D0, 0)
    wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0C0, uint64(0x43))
    wq(ctx + 0x100, uint64(0x3B))
    wq(ctx + 0x0F0, uint64(0x202))
    wq(ctx + 0x0E0, mov_rdi_rax_ret)
    wq(ctx + 0x0F8, stack_top)
    wq(ctx + 0x078, uint64("0xAAAABBBBCCCC"))
    wq(ctx + 0x048, marker)

    local tid_buf = memory.alloc(8)
    wq(tid_buf, uint64(0))
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 100000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local got = rq(marker)
    print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)) .. " marker=" .. q(got))
end

-- [B] Now add sigaction and test again
print("[B] WITH sigaction (SIG_IGN for 10,11,12,13)")
do
    local sa = memory.alloc(0x20)
    wq(sa, uint64(1))  -- SIG_IGN = 1
    for _, sig in ipairs({10, 11, 12, 13}) do
        pcall(function() make_syscall(416)(uint64(sig), sa, uint64(0)) end)
    end
    print("  signals masked")

    local info = memory.alloc(0x200)
    zero(info, 0x200)
    wd(info, 0x160)
    pcall(function() make_syscall(593)(uint64(0), info) end)
    local text_lo = rd(info + 0x108) or 0
    local text_hi = rd(info + 0x10C) or 0
    local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))

    local mov_rdi_rax_ret = eboot + uint64(0x92C67)
    local bare_ret = eboot + uint64(0x42)

    local ok_m1, marker = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    local ok_m2, stack_base = pcall(function()
        return sc_mmap(uint64(0), uint64(0x10000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    zero(marker, 0x4000)

    local stack_top = stack_base + 0x10000 - 0x100
    for off = 0, 0xF8, 8 do wq(stack_top + off, bare_ret) end

    local ctx = memory.alloc(0x500)
    zero(ctx, 0x500)
    wq(ctx + 0x108, uint64(0x480))
    wd(ctx + 0x0D0, 0)
    wq(ctx + 0x110, uint64(0x10000))
    wq(ctx + 0x0C0, uint64(0x43))
    wq(ctx + 0x100, uint64(0x3B))
    wq(ctx + 0x0F0, uint64(0x202))
    wq(ctx + 0x0E0, mov_rdi_rax_ret)
    wq(ctx + 0x0F8, stack_top)
    wq(ctx + 0x078, uint64("0xDDDDEEEEFFFF"))
    wq(ctx + 0x048, marker)

    local tid_buf = memory.alloc(8)
    wq(tid_buf, uint64(0))
    local ok_tc, rv_tc = pcall(function()
        return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
    end)

    local ts = memory.alloc(16)
    wq(ts, 0); wq(ts + 8, 100000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

    local got = rq(marker)
    print("  rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(rq(tid_buf)) .. " marker=" .. q(got))
end

print("=== 531q DONE ===")
