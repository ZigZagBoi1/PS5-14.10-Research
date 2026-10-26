-- CRASH_CLASS: MODERATE
-- PROBE 671b: non-block create with count=32 is a single syscall that allocates
-- 32 work items (0x58) plus one context (0x30), and its entry count is 1 so one
-- delete frees everything. Control: 20 such bursts, no threads.
print("=== PROBE 671b: NON-BLOCK COUNT=32 BURST CONTROL ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669,sc664,sc662=mk(669),mk(664),mk(662)
local DATA=memory.alloc(0x1000)
local OUT=memory.alloc(0x40)
local IDP=memory.alloc(8)
local ST=memory.alloc(8)
for i=0,0xFFC,4 do wd(N(DATA)+i,0) end
local made,pol,del,ref=0,0,0,0
for n=1,20 do
    wd(N(OUT),0)
    local o,r=pcall(function() return sc669(U(1),U(N(DATA)),U(32),U(1),U(N(OUT)),U(0)) end)
    local bid=rd(N(OUT)) or 0
    if o and N(r)==0 and bid>0 then
        made=made+1
        wd(N(IDP),bid)
        wd(N(ST),0x77777777)
        pcall(function() sc664(U(N(IDP)),U(1),U(N(ST)),U(0),U(0),U(0)) end)
        local s1=rd(N(ST))
        if s1==3 or s1==0x10003 then pol=pol+1 end
        wd(N(ST),0x77777777)
        pcall(function() sc662(U(N(IDP)),U(1),U(N(ST))) end)
        local s2=rd(N(ST))
        if s2==0 then del=del+1 else ref=ref+1; if ref<=3 then print(string.format("[!] round %d del status %X",n,s2 or 0)) end end
    else
        print(string.format("[!] round %d create rv=%s",n,tostring(r)))
        break
    end
    if n==1 then print(string.format("[A] first burst poll=%X del=%X",rd(N(ST)) or 0,0)) end
end
print(string.format("[H] made=%d polled=%d deleted=%d refused=%d",made,pol,del,ref))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
