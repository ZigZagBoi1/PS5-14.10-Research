-- CRASH_CLASS: LOW
print("=== PROBE 617a: PLT SCAN ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function raw(a) local o,v=pcall(function() return memory.read_byte(a) end) if o then return N(v) end return nil end
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
print(string.format("[A] regions=%d",n))
local RS,RE,RP={},{},{}
for i=0,n-1 do
    local b=N(bufp)+i*72
    RS[i+1]=N(rawq(b)); RE[i+1]=N(rawq(b+8)); RP[i+1]=N(rawd(b+0x18))
end
local hits=0
for k=1,n do
    local p=math.floor(RP[k])
    print(string.format("  [%d] %s-%s prot=%d size=%08X",k-1,hex(RS[k]),hex(RE[k]),p,lo(RE[k]-RS[k])))
end
for k=1,n do
    if math.floor(RP[k])%2==1 and RP[k]>=5 then
        local lim=math.min(0x4000,RE[k]-RS[k]-16)
        for off=0,lim,1 do
            local a=RS[k]+off
            if raw(a)==0xFF and raw(a+1)==0x25 and raw(a+6)==0xCC and raw(a+7)==0xCC and raw(a+8)==0x00 and raw(a+9)==0x11 then
                local d=rawd(a+2)
                if d and d>=0x80000000 then d=d-0x100000000 end
                local slot=a+6+d
                local v=rawq(slot)
                print(string.format("  STUB %s slot %s -> %s",hex(a),hex(slot),hex(v or 0)))
                hits=hits+1
                if hits>=6 then break end
            end
        end
    end
    if hits>=6 then break end
end
print(string.format("[B] stubs=%d",hits))
print("[Z] alive")
