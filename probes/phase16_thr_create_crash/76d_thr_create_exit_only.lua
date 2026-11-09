-- 76d: native thr_create control whose entry immediately exits the child.
-- This isolates the raw kernel-created thread from libc longjmp/ROP/TLS.
print("=== PROBE 76d: THR_CREATE EXIT-ONLY CONTROL ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
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

syscall.resolve({ sc_getpid = 20 })
print("canary_getpid=" .. tostring(syscall.sc_getpid():tonumber()))

local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
local stack = memory.alloc(0x4000)
zero(ctx, 0x600)
zero(id_slot, 0x10)
zero(stack, 0x4000)

-- Decoded 430 context gates.
wq(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, 0x10000)

-- Native entry: Thrd_exit(0). No longjmp, ROP, or loader Lua state.
wq(ctx + 0x48, 0)
wq(ctx + 0x50, 0)
wq(ctx + 0xE0, stack + 0x3FF0)
wq(ctx + 0xF8, libc_addrofs.Thrd_exit)
wq(ctx + 0x100, 0)

print("ctx=" .. tostring(ctx) .. " id_slot=" .. tostring(id_slot))
print("thrd_exit=" .. q(libc_addrofs.Thrd_exit))
print("[BEFORE] 430(exit-only context)")

local ok_call, rv = pcall(function()
    local sc = {}
    for k, v in pairs(syscall.pipe) do sc[k] = v end
    sc.syscall_no = 430
    setmetatable(sc, getmetatable(syscall.pipe))
    return sc(uint64(ctx), uint64(id_slot), uint64(0))
end)
print("[RETURNED] ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))
local id_ok, id_val = pcall(function() return memory.read_qword(id_slot) end)
if id_ok then print("id_after=" .. q(id_val)) end
local alive_ok, alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("post_canary_ok=" .. tostring(alive_ok) .. " pid=" .. tostring(alive))
print("=== PROBE 76d COMPLETE ===")
