-- CRASH_CLASS: LOW
print("=== PROBE 615b: REGION NAMES ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return N(v) end return nil end
local function rd8(a) local ok,v=pcall(function() return memory.read_byte(a) end) if ok then return N(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end

local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local n=rd(N(cnt)) or 0
print(string.format("[A] n=%d",n))
for i=0,math.min(n-1,6) do
    local b=N(bufp)+i*72
    local q0=N(rq(b)) local q4=N(rq(b+0x20))
    local bytes=""
    for k=0,15 do local ch=rd8(b+0x20+k) bytes=bytes..string.format("%02X",ch or 0) end
    local s=""
    if q4>0x10000 then
        for k=0,31 do local ch=rd8(q4+k) if not ch or ch<32 or ch>126 then break end s=s..string.char(ch) end
    end
    print(string.format("  r%d start=%X q@+20=%016X bytes=%s str='%s'",i,q0,q4,bytes,s))
end
print("[Z] alive")
