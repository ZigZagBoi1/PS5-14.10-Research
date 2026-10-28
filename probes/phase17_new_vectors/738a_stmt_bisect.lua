-- CRASH_CLASS: LOW
-- PROBE 738a: which statement ends the process?
--
-- 733a, 734a and 737a all died between a working step and the construction of
-- the msghdr, in three small memory.alloc calls and a fill loop that 735a ran
-- fine without a sigaction. This repeats the exact sequence twice, once before
-- the SIGSYS shield and once after, with a numbered print after every statement.

print("=== PROBE 738a: STATEMENT BISECT ===")
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
local n = 0
local function say(tag) n = n + 1; print(string.format("[%03d] %s", n, tag)) end

local function sequence(tag)
    say(tag.." alloc HDR")
    local HDR = to_num(memory.alloc(0x1000))
    say(tag.." HDR="..string.format("%X", HDR))
    say(tag.." alloc iov")
    local iov = to_num(memory.alloc(0x1000))
    say(tag.." iov="..string.format("%X", iov))
    say(tag.." alloc dat")
    local dat = to_num(memory.alloc(0x1000))
    say(tag.." dat="..string.format("%X", dat))
    say(tag.." fill loop start")
    for k=0,0x3FF do wd(HDR+k*4,0); wd(iov+k*4,0); wd(dat+k*4,0x5A5A5A5A) end
    say(tag.." fill loop done")
    wq(HDR+0x00, Z); say(tag.." wrote msg_name")
    wd(HDR+0x08, 0); say(tag.." wrote namelen")
    wq(HDR+0x10, U(iov)); say(tag.." wrote msg_iov="..string.format("%X",iov))
    wd(HDR+0x18, 1); say(tag.." wrote iovlen")
    wq(HDR+0x20, Z); say(tag.." wrote msg_control")
    wd(HDR+0x28, 0); wd(HDR+0x2c, 0); say(tag.." wrote controllen and flags")
    wq(iov+0, U(dat)); wq(iov+8, U(16)); say(tag.." wrote iovec")
    return HDR, iov, dat
end

local H1 = sequence("A")
say("A sequence complete")

local act = to_num(memory.alloc(64)); local old = to_num(memory.alloc(64))
for k=0,15 do wq(act+k*8, Z) end
wd(act, 1)
say("installing shield")
pcall(function() return mk(416)(U(12), U(act), U(old), Z, Z, Z) end)
local okc, ctl = pcall(function() return mk(4095)(Z,Z,Z,Z,Z,Z) end)
say("shield control: "..tostring(okc and to_num(ctl) or "DEAD"))

local H2 = sequence("B")
say("B sequence complete")
print(string.format("[end] H1=%X H2=%X health=%d", H1, H2, to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
print("=== 738a DONE ===")
