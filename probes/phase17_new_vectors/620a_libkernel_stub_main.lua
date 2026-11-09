-- CRASH_CLASS: HIGH
-- PROBE 620a: call the libc GOT target from the MAIN thread with rax=syscall_no
print("=== PROBE 620a: LIBKERNEL STUB MAIN ===")
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

local stub=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("[A] fcall stub getpid=%d",stub))

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
local target=nil
for k=1,n do
    if RP[k]==5 then
        local a=RS[k]+0x108
        if raw(a)==0xFF and raw(a+1)==0x25 then
            local d=rawd(a+2)
            if d and d>=0x80000000 then d=d-0x100000000 end
            local slot=a+6+d
            local v=rawq(slot)
            if v and v>=0x800000000 and v<0x900000000 then
                target=v
                print(string.format("[B] libc=%s stub=%s slot=%s -> %s",hex(RS[k]),hex(a),hex(slot),hex(v)))
            end
        end
    end
end
if not target then print("[!] no target"); return end
print(string.format("[C] calling target with rax=20"))
local ok,rv=pcall(function() return native.fcall_with_rax(target,20) end)
print(string.format("[D] ok=%s rv=%s",tostring(ok),tostring(ok and N(rv) or "err")))
print(string.format("[E] pid-match=%s",tostring(ok and N(rv)==stub)))
print("[Z] alive")
