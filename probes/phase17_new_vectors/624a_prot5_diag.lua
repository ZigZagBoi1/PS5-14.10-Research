-- CRASH_CLASS: LOW
print("=== PROBE 624a: PROT5 DIAG ===")
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
print(string.format("[A] n=%d",n))
for i=0,math.min(n-1,8) do
    local b=N(bufp)+i*72
    print(string.format("  rec%d %s-%s prot=%d",i,hex(N(rawq(b))),hex(N(rawq(b+8))),N(rawd(b+0x18))))
end
for i=0,n-1 do
    local b=N(bufp)+i*72
    local s=N(rawq(b)) local e=N(rawq(b+8)) local p=N(rawd(b+0x18))
    if p==5 then
        local g=""
        for j=0,3 do g=g..string.format("%02X",raw(s+0x92C67+j) or 0) end
        print(string.format("  P5 %s-%s size=%X at92C67=%s",hex(s),hex(e),e-s,g))
    end
end
print("[Z] alive")
