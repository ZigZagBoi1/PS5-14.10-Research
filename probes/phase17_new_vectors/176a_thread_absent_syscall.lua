-- CRASH_CLASS: HIGH (a child thread calls an absent syscall slot on purpose)
-- PROBE 176a: does an absent-slot kill take the whole process, or only the thread?
--
-- Mapping which syscalls exist currently costs one game relaunch per absent
-- number, because calling an absent slot terminates the process (173a). If that
-- death is confined to the calling thread, a child thread can probe every slot
-- while the main thread keeps running, and the whole sysent map falls out of a
-- single connection.
--
-- 4095 is known absent, and 159a proved a thr_create child can execute the
-- syscall wrapper with any number in RAX. So:
--
--   thread: RIP = syscall_address, RAX = 4095, RSP -> [jmp $]
--   main:   busyloop on getpid, then print a canary
--
-- A canary after the spawn means the process survived an absent-slot call: the
-- killer is per-thread, and the map is cheap from here. No canary means the
-- process is gone and 176a costs exactly one relaunch, the same as any other
-- absent number.
--
-- No nanosleep anywhere: the parked-thread hazard in 158c came from a wrong
-- timespec, and a busyloop cannot park anything.

print("=== PROBE 176a: ABSENT SYSCALL FROM A CHILD THREAD ===")

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
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
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

local sc_getpid = make_syscall(20)
local sc_thr_create = make_syscall(430)
local sc_thr_self = make_syscall(432)
local sc_thr_kill = make_syscall(433)
local sc_mmap = make_syscall(477)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RAX = 0x048, 0x078

print("[0] canary pid=" .. tostring(to_num(sc_getpid())))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
local jmp_self = eboot_base + 0x15481
if not (rb(jmp_self) == 0xEB and rb(jmp_self + 1) == 0xFE) then
    print("[0] jmp $ mismatch at " .. q(jmp_self) .. "; aborting")
    return
end

local SW = syscall.syscall_address
if SW == nil then
    print("[0] syscall.syscall_address is nil; aborting")
    return
end
print("[0] syscall_address=" .. q(SW) .. " jmp $=" .. q(jmp_self))

local function page(n)
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for off = 0, (n or 0x38), 8 do wq(p + off, uint64(0)) end
    return p
end

local function spawn(rip, rax, rdi, rsp)
    local ctx = page(0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, rip)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, rax)
    wq(ctx + C_RDI, rdi)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv, ctx
end

-- The thread's stack: one slot holding `jmp $`, so a return parks instead of
-- running into unmapped memory. The absent call is expected to end the thread
-- before it ever returns, but the parking slot costs nothing.
local stack = page(0x100)
wq(stack + 0xF0, jmp_self)
wq(stack + 0xF8, uint64(0))

print("[1] spawning thread RAX=4095")
local tid, ok_spawn, rv_spawn = spawn(SW, uint64(4095), uint64(0), stack + 0xF0)
print("[1] spawn ok=" .. tostring(ok_spawn) .. " rv=" .. tostring(rv_spawn) .. " tid=" .. q(tid))

-- Busyloop so the child gets scheduled; getpid is cheap and cannot park.
local spins = 0
for i = 1, 4000000 do
    pcall(function() return sc_getpid():tonumber() end)
    spins = spins + 1
end
print("[2] spun " .. tostring(spins))

print("[3] canary after: pid=" .. tostring(to_num(sc_getpid())))
if tid then
    local ok_kill, rv_kill = pcall(function() return sc_thr_kill(tid, uint64(1)) end)
    print("[3] thr_kill ok=" .. tostring(ok_kill) .. " rv=" .. tostring(rv_kill))
end
print("[3] canary final: pid=" .. tostring(to_num(sc_getpid())))
print("=== PROBE 176a DONE ===")
