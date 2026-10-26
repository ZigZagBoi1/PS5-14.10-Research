-- CRASH_CLASS: LOW
print("=== PROBE 621a: FCALL STUB ===")
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

local ts=tostring(syscall.pipe)
local fh,fl=ts:match("fn_addr: (0x%x+)")
print(string.format("[A] tostring len=%d fn_addr=%s",#ts,tostring(fh)))
local fn = fh and tonumber(fh) or 0
if fn and fn>4294967296 then fn=N(uint64(fh)) end
local rh,rl=ts:match("ropchain @ (0x%x+)")
print(string.format("[B] fn=%s rop=%s",hex(fn),tostring(rh)))

local sc674=mk(674)
local bufp=memory.alloc(0x20000)
local cnt=memory.alloc(4) wd(N(cnt),0)
pcall(function() sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
local okc,cv=pcall(function() return memory.read_dword(N(cnt)) end)
local n=okc and N(cv) or 0
local canread=nil
for i=0,n-1 do
    local b=N(bufp)+i*72
    local s=N(rawq(b)) local e=N(rawq(b+8)) local p=N(rawd(b+0x18))
    if fn>=s and fn<e then
        print(string.format("[C] fn region %s-%s prot=%d",hex(s),hex(e),p))
        canread=(p%2==1)
        if canread then
            local out=""
            for j=0,15 do out=out..string.format("%02X",raw(fn+j) or 0) end
            print(string.format("[D] bytes %s",out))
        end
    end
end
print("[Z] alive")
