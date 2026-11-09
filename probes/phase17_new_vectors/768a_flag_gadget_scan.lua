-- CRASH_CLASS: LOW
-- PROBE 768a: every flag-touching opcode in eboot, with following bytes
--
-- 767b showed there is no pushfq;pop rX;ret. I still need a way to read
-- RFLAGS out of a native child to learn whether thr_create restores it from
-- the context. Scan for pushfq (9C), popfq (9D), lahf (9F), sahf (9E), iretq
-- (CF) and jcc-short (7x) and print the next bytes so each can be judged.
print("=== PROBE 768a: FLAG GADGET SCAN ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=to_num(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function mmap(px)
    local ok,r=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    if not ok then return 0 end
    local a=to_num(r); if a>0 then zero(a,px) end; return a
end
local rb=mmap(0x8000)
if rb==0 then print("[A] mmap failed") return end
local cnt=to_num(memory.alloc(8)); wd(cnt,0)
call(mk(674),rb,72,512,cnt,0x40000000,0)
local n=rd(cnt) or 0
local ebase,bsz=nil,0
for i=0,math.min(n,512)-1 do
    local r=rb+i*72
    local a=rd(r)+(rd(r+4) or 0)*4294967296
    local b=rd(r+8)+(rd(r+12) or 0)*4294967296
    if rd(r+0x18)==5 and (b-a)>0x200000 and a<0x1000000000 and (b-a)>bsz then ebase,bsz=a,b-a end
end
if not ebase then print("[A] no eboot") return end
print(string.format("[A] eboot=%X size=%X",ebase,bsz))
local img=""
local off=0
while off<bsz do
    local want=0x8000; if bsz-off<want then want=bsz-off end
    local ok,s=pcall(function() return memory.read_buffer(ebase+off,want) end)
    if not ok or type(s)~="string" then break end
    img=img..s; off=off+want
end
print(string.format("[B] read %d of %d bytes",#img,bsz))
local function hexat(i,k)
    local t={}
    for j=i,i+k-1 do if j>#img then break end t[#t+1]=string.format("%02X",string.byte(img,j)) end
    return table.concat(t," ")
end
local function scan(byte,label,limit)
    local out,cnt2,pos={},0,1
    while true do
        local i=string.find(img,string.char(byte),pos,true)
        if not i then break end
        cnt2=cnt2+1
        if #out<limit then out[#out+1]=string.format("%X:%s",ebase+i-1,hexat(i+1,6)) end
        pos=i+1
    end
    print(string.format("[C] %s (byte %02X): %d hits",label,byte,cnt2))
    if #out>0 then print("    "..table.concat(out,"  ")) end
end
scan(0x9C,"pushfq",6)
scan(0x9D,"popfq",6)
scan(0x9F,"lahf",6)
scan(0x9E,"sahf",4)
scan(0xCF,"iretq",4)
print("[D] looking for pairs")
local pairs_t={{0x9C,0xC3,"pushfq;ret"},{0x9D,0xC3,"popfq;ret"},{0x9F,0xC3,"lahf;ret"},{0xCF,0xC3,"iret;ret"},{0x9C,0x5E,"pushfq;pop rsi"},{0x9F,0x48,"lahf;rex"}}
for _,p in ipairs(pairs_t) do
    local pat=string.char(p[1],p[2]); local i=string.find(img,pat,1,true)
    print(string.format("[D] %s = %s",p[3],i and string.format("%X (%s)",ebase+i-1,hexat(i,8)) or "none"))
end
print("[E] health="..tostring(call(syscall.pipe,20,0,0,0,0,0,0)))
print("=== 768a DONE ===")
