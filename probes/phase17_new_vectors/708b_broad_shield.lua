-- CRASH_CLASS: MODERATE
-- PROBE 708b: a broad signal shield, then the numbers that kill.
--
-- Context: 589 with a real path string died even with SIGSYS (12) ignored, so
-- its kill is either a different catchable signal or an uncatchable one. The
-- same question applies to the 677+ range, which was filed as "past the end"
-- on the strength of consecutive kills.
--
-- This probe ignores every catchable signal (1..31 except KILL 9 and STOP 19)
-- and then calls one candidate per line, printing before each call so a kill
-- names the number. If a number returns a value under the broad shield, that
-- slot exists and its earlier kill was a delivered signal, not a missing slot.

print("=== PROBE 708b: broad signal shield then lethal numbers ===")
print("")

local function N(v)
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
local function U(a)
    a=N(a)
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a)
    local o,v=pcall(function() return memory.read_dword(a) end)
    if o then return N(v) end
    return nil
end

local sigact=mk(416)
local sa=memory.alloc(0x80)
local oldsa=memory.alloc(0x80)
for i=0,0x78,8 do pcall(function() memory.write_qword(N(sa)+i,0) end) end
pcall(function() memory.write_qword(N(sa),1) end)   -- SIG_IGN at act[0]
local ignored=0
local refused={}
for sig=1,31 do
    if sig~=9 and sig~=19 then
        local ok,rv=pcall(function() return sigact(uint64(sig),U(N(sa)),U(N(oldsa))) end)
        if ok and N(rv)==0 then ignored=ignored+1 else refused[#refused+1]=sig end
    end
end
if #refused>0 then print("    refused: "..table.concat(refused,",")) end
print(string.format("[0] ignored %d catchable signals",ignored))

local buf=memory.alloc(0x200)
local path="/system/common/lib/libkernel.sprx"
for i=1,#path do
    pcall(function() memory.write_byte(N(buf)+i-1,string.byte(path,i)) end)
end
pcall(function() memory.write_byte(N(buf)+#path,0) end)
local out=memory.alloc(0x100)

local targets={
    {n=589, a=function(sc) return sc(U(N(buf)),uint64(0),U(N(out)),uint64(0),uint64(0),uint64(0)) end},
    {n=590, a=function(sc) return sc(uint64(1),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
    {n=597, a=function(sc) return sc(uint64(1),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
    {n=631, a=function(sc) return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
    {n=650, a=function(sc) return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
    {n=651, a=function(sc) return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
    {n=677, a=function(sc) return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
    {n=678, a=function(sc) return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
    {n=4095,a=function(sc) return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end},
}

for _,t in ipairs(targets) do
    local sc=mk(t.n)
    print(string.format("[call %d] before",t.n))
    local ok,rv=pcall(function() return t.a(sc) end)
    print(string.format("[call %d] ok=%s rv=%s",t.n,tostring(ok),tostring(rv)))
end

print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
