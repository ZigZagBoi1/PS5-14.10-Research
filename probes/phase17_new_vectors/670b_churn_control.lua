-- CRASH_CLASS: MODERATE
-- PROBE 670b: control for 670a. Same 400 single-item create/poll/delete cycles,
-- no threads.
print("=== PROBE 670b: SINGLE-ITEM CHURN CONTROL ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local sc669,sc664,sc662=mk(669),mk(664),mk(662)
local CDATA=memory.alloc(0x100)
local COUT=memory.alloc(0x40)
local CID=memory.alloc(8)
local CST=memory.alloc(8)
local made,del,ref=0,0,0
for n=1,400 do
    wd(N(COUT),0)
    local o,r=pcall(function() return sc669(U(1),U(N(CDATA)),U(1),U(1),U(N(COUT)),U(0)) end)
    local cid=rd(N(COUT)) or 0
    if o and N(r)==0 and cid>0 then
        made=made+1
        wd(N(CID),cid)
        wd(N(CST),0)
        pcall(function() sc664(U(N(CID)),U(1),U(N(CST)),U(0),U(0),U(0)) end)
        wd(N(CST),0)
        pcall(function() sc662(U(N(CID)),U(1),U(N(CST))) end)
        local s=rd(N(CST))
        if s==0 then del=del+1 else ref=ref+1 end
    end
    if n%100==0 then print(string.format("[C] n=%d made=%d del=%d ref=%d",n,made,del,ref)) end
end
print(string.format("[H] made=%d del=%d refused=%d",made,del,ref))
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
