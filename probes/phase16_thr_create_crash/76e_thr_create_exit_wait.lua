-- CRASH_CLASS: HIGH
-- 76e: thr_create exit-only context with a bounded parent wait.
-- Purpose: determine whether the delayed failure is a child cleanup race.
print("=== PROBE 76e: THR_CREATE EXIT-ONLY WITH WAIT ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val)
    return pcall(function() memory.write_dword(addr, val) end)
end
local function wq(addr, val)
    return pcall(function() memory.write_qword(addr, val) end)
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

syscall.resolve({ sc_getpid = 20 })
local sc_getpid = make_syscall(20)
local sc_nanosleep = make_syscall(240)
print("canary_getpid=" .. tostring(sc_getpid():tonumber()))

local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
local stack = memory.alloc(0x4000)
zero(ctx, 0x600)
zero(id_slot, 0x10)
zero(stack, 0x4000)

wq(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, 0x10000)
wq(ctx + 0x48, 0)
wq(ctx + 0x50, 0)
wq(ctx + 0xE0, stack + 0x3FF0)
wq(ctx + 0xF8, libc_addrofs.Thrd_exit)
wq(ctx + 0x100, 0)

print("ctx=" .. tostring(ctx) .. " id_slot=" .. tostring(id_slot))
print("thrd_exit=" .. q(libc_addrofs.Thrd_exit))
print("[BEFORE] 430(exit-only context)")
local ok_call, rv = pcall(function()
    local sc = make_syscall(430)
    return sc(uint64(ctx), uint64(id_slot), uint64(0))
end)
print("[RETURNED] ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))
local id_ok, id_val = pcall(function() return memory.read_qword(id_slot) end)
if id_ok then print("id_after=" .. q(id_val)) end

local ts = memory.alloc(16)
wq(ts, 0)
wq(ts + 8, 250000000)
local sleep_ok, sleep_rv = pcall(function() return sc_nanosleep(uint64(ts), uint64(0)) end)
print("wait_250ms_ok=" .. tostring(sleep_ok) .. " rv=" .. tostring(sleep_rv))
local alive_ok, alive = pcall(function() return sc_getpid():tonumber() end)
print("post_wait_canary_ok=" .. tostring(alive_ok) .. " pid=" .. tostring(alive))
print("=== PROBE 76e COMPLETE ===")
