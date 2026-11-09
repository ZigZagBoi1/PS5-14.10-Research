-- CRASH_CLASS: MODERATE
-- PROBE 734a: isolate which part of a sendmsg call ends the process
--
-- 733a installed the SIGSYS shield (4095 -> -1 with the process alive), opened
-- a socketpair (fd 22), and then died before its first shape printed. This
-- probe prints before AND after every individual call so the last line names
-- the culprit.

print("=== PROBE 734a: SENDMSG ISOLATION ===")
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
local function live(tag)
    local ok, v = pcall(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
    print(string.format("  (%s) alive ok=%s pid=%s", tag, tostring(ok), tostring(ok and to_num(v) or "?")))
end

local act = to_num(memory.alloc(64)); local old = to_num(memory.alloc(64))
for k=0,15 do wq(act+k*8, Z) end
wd(act, 1)
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
local okc, ctl = pcall(function() return mk(4095)(Z,Z,Z,Z,Z,Z) end)
print(string.format("[0] shield control 4095: ok=%s ret=%s", tostring(okc), tostring(okc and to_num(ctl) or "dead")))
live("after shield")

local fds = to_num(memory.alloc(64))
print("[1] about to socketpair")
local okp, prv = pcall(function() return mk(135)(U(1),U(1),U(0),U(fds),Z,Z) end)
local fdA, fdB = rd(fds), rd(fds+4)
print(string.format("[1] socketpair ok=%s ret=%s fd=%d,%d", tostring(okp), tostring(okp and to_num(prv) or "?"), fdA, fdB))

local msg = to_num(memory.alloc(64))
for k=0,15 do wd(msg+k*4, 0x44434241) end

print(string.format("[2] about to write(%d,16)", fdA))
local okw, wr = pcall(function() return mk(4)(U(fdA), U(msg), U(16), Z, Z, Z) end)
print(string.format("[2] write ret=%s", tostring(okw and to_num(wr) or "DEAD")))
live("after write")

local rbuf = to_num(memory.alloc(64))
print(string.format("[3] about to read(%d,16)", fdB))
local okr, rrv = pcall(function() return mk(3)(U(fdB), U(rbuf), U(16), Z, Z, Z) end)
print(string.format("[3] read ret=%s word=%08X", tostring(okr and to_num(rrv) or "DEAD"), rd(rbuf)))
live("after read")

local HDR = to_num(memory.alloc(0x1000))
local iov = to_num(memory.alloc(0x4000))
local data = to_num(memory.alloc(0x4000))
for k=0,0xFFF do wd(iov+k*4,0); wd(data+k*4,0x41414141) end

print("[4] about to sendmsg(fd, NULL, 0)")
local ok4, r4 = pcall(function() return mk(28)(U(fdA), U(0), U(0), Z, Z, Z) end)
print(string.format("[4] sendmsg NULL ret=%s", tostring(ok4 and to_num(r4) or "DEAD")))
live("after null sendmsg")

local function hdr(iovlen, base, len)
    for k=0,0x1FF do wd(HDR+k*4, 0) end
    wq(HDR+0x00, Z); wd(HDR+0x08, 0)
    wq(HDR+0x10, U(iov)); wd(HDR+0x18, iovlen)
    wq(HDR+0x20, Z); wd(HDR+0x28, 0); wd(HDR+0x2c, 0)
    wq(iov+0, U(base)); wq(iov+8, U(len))
end

hdr(0, 0, 0)
print("[5] about to sendmsg(fd, valid, iovlen=0)")
local ok5, r5 = pcall(function() return mk(28)(U(fdA), U(HDR), U(0), Z, Z, Z) end)
print(string.format("[5] sendmsg iovlen=0 ret=%s", tostring(ok5 and to_num(r5) or "DEAD")))
live("after iovlen0")

hdr(1, data, 16)
print("[6] about to sendmsg(fd, valid, iovlen=1, 16 bytes)")
local ok6, r6 = pcall(function() return mk(28)(U(fdA), U(HDR), U(0), Z, Z, Z) end)
print(string.format("[6] sendmsg iovlen=1 ret=%s", tostring(ok6 and to_num(r6) or "DEAD")))
live("after iovlen1")
print("=== 734a DONE ===")
