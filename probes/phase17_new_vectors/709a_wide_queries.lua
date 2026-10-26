-- CRASH_CLASS: LOW
-- PROBE 709a: widen the three queries that never killed anyone, in one connection.
--
-- Context: 649 (module member) was swept over member types 0..255 on all 39
-- handles from 592 and returned 233 answers, none kernel-shaped. 593 (dynlib
-- info) was only ever called with a 0x160-byte struct, and 674 (VM map) with a
-- 512-entry cap. Widening a query costs nothing and cannot kill the process, so
-- this runs all three before any lethal number is touched.
--
-- Every section prints its own header, so a truncated capture still localises.

print("=== PROBE 709a: widen 649 / 593 / 674 ===")
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
local function rq(a)
    local o,v=pcall(function() return memory.read_qword(a) end)
    if o then return N(v) end
    return nil
end
local function is_kern(v)
    if not v then return false end
    if type(v)~="number" then v=N(v) end
    local hi=math.floor(v/4294967296)
    return hi>=0xFFFF8000 and hi<=0xFFFFFFFF
end

local sc416=mk(416)
pcall(function() sc416(uint64(12),uint64(1),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print("[0] shield set")

-- [A] 649 member types 0..1023 on handle 0 and on every handle that answered before
print("[A] 649 member sweep")
local sc649=mk(649)
local handles={0}
local list=memory.alloc(0x200)
local cnt=memory.alloc(8)
local sc592=mk(592)
wd(N(cnt),0)
pcall(function() sc592(U(N(list)),uint64(0x200),U(N(cnt))) end)
local n=N(rd(N(cnt)) or 0)
if n>0 and n<64 then
    for i=0,n-1 do
        local h=rd(N(list)+i*4)
        if h and h~=0 then handles[#handles+1]=h end
    end
end
print(string.format("    handles=%d",#handles))
local out=memory.alloc(0x100)
local hits=0
local kernel=0
for hi=1,#handles do
    local h=handles[hi]
    local best=-1
    for m=0,1023 do
        for i=0,0x3C,4 do wd(N(out)+i,0) end
        local ok,rv=pcall(function() return sc649(uint64(h),uint64(m),U(N(out)),uint64(0x40),uint64(0),uint64(0)) end)
        if ok and N(rv)==0 then
            hits=hits+1
            best=m
            local q0=rq(N(out))
            if is_kern(q0) then
                kernel=kernel+1
                print(string.format("    KERNEL h=%x m=%d q0=%X",h,m,q0))
            end
        end
    end
    print(string.format("    h=%x highest-answering-member=%d",h,best))
end
print(string.format("    hits=%d kernel-shaped=%d",hits,kernel))

-- [B] 593 with larger structs, dump every non-zero qword
print("[B] 593 wide struct")
local sc593=mk(593)
for _,sz in ipairs({0x200,0x400}) do
    for hi=1,math.min(#handles,6) do
        local h=handles[hi]
        local buf=memory.alloc(sz)
        for i=0,sz-4,4 do wd(N(buf)+i,0) end
        wd(N(buf),sz-8)
        local ok,rv=pcall(function() return sc593(uint64(h),U(N(buf))) end)
        if ok and N(rv)==0 then
            local vals={}
            local kn=0
            for off=0,sz-8,8 do
                local v=rq(N(buf)+off)
                if v and v~=0 then
                    if is_kern(v) then kn=kn+1 end
                    if #vals<8 then vals[#vals+1]=string.format("+%X=%X",off,v) end
                end
            end
            print(string.format("    sz=%X h=%x rv=0 kern=%d %s",sz,h,kn,table.concat(vals," ")))
        end
    end
end

-- [C] 674 with a bigger cap
print("[C] 674 map with 1024 entries")
local sc674=mk(674)
local map=memory.alloc(1024*72)
local mcnt=memory.alloc(8)
wd(N(mcnt),0)
local ok,rv=pcall(function() return sc674(U(N(map)),uint64(72),uint64(1024),U(N(mcnt)),uint64(0x40000000),uint64(0)) end)
local got=N(rd(N(mcnt)) or 0)
print(string.format("    674 ok=%s rv=%s count=%d",tostring(ok),tostring(rv),got))
local kn=0
local names={}
for i=0,math.min(got,1024)-1 do
    local base=N(map)+i*72
    local lo=rd(base) or 0
    local hi=rd(base+4) or 0
    local start=hi*4294967296+lo
    if is_kern(start) then
        kn=kn+1
        if kn<=6 then
            local nm=""
            for k=0,23 do
                local c=pcall(function() return memory.read_byte(base+0x20+k) end)
                if c then nm=nm..string.char(0) end
            end
            names[#names+1]=string.format("%X",start)
        end
    end
end
print(string.format("    674 kernel-range regions=%d %s",kn,table.concat(names,",")))

print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
