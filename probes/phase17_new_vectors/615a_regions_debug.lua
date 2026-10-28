-- CRASH_CLASS: LOW
print("=== PROBE 615a: REGIONS DEBUG ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return N(v) end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end

local sc674=mk(674)
local bufp=memory.alloc(0x20000)
for i=0,0x100,4 do wd(N(bufp)+i,0xCDCDCDCD) end
local cnt=memory.alloc(4) wd(N(cnt),0)
local ok,rv=pcall(function() return sc674(U(N(bufp)),uint64(72),uint64(512),U(N(cnt)),uint64(0x40000000),uint64(0)) end)
print(string.format("[A] ok=%s ret=%s cnt=%s buf=0x%X",tostring(ok),tostring(ok and N(rv) or "err"),tostring(rd(N(cnt))),N(bufp)))
for i=0,4 do
    local b=N(bufp)+i*72
    print(string.format("  rec%d: %016X %016X %016X %016X",i,N(rq(b)),N(rq(b+8)),N(rq(b+0x10)),N(rq(b+0x18))))
end
print("[Z] alive")
