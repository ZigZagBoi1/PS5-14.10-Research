-- CRASH_CLASS: HIGH (syscall 597 is called; its gate is expected to refuse)
-- PROBE 1201a: syscall 597 is a capability grant: on 13.60 it sets dword [ctx+0x150]=1 and
-- ORs 0x40 into the privilege mask dword [ctx+0x140], and syscall 608 dynlib_get_info_ex
-- consults the same mask (level 2) to decide whether to fill segment sets or zero them.
-- The experiment was written twice and never run. It runs now, and it runs *with errno*:
-- 1200d proved the numeric return value is not rax (every failure reads 0) and that
-- get_error_string() carries the real code, so every step below prints both.
print("=== PROBE 1201a: 597 GRANT + 608 ORACLE, WITH ERRNO ===")
local function tn(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=tn(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function ES() local ok,r=pcall(get_error_string) if ok then return tostring(r) end return "<no-es>" end
local Z=uint64(0)
local sc608,sc597=mk(608),mk(597)
local function alloc(n) return tn(memory.alloc(n)) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rq(a) local ok,v=pcall(function() return tn(memory.read_qword(uint64(a))) end) if ok then return v end return -1 end
local function rd(a) local ok,v=pcall(function() return tn(memory.read_dword(uint64(a))) end) if ok then return v end return -1 end

local rec=alloc(0x1a8)
local function oracle(tag,id,flags)
    for i=0,0x1a8-1,4 do wd(rec+i,0xCDCDCDCD) end
    wq(rec,0x1a8)
    local ok=pcall(function() return sc608(U(id),U(flags),U(rec),Z,Z,Z) end)
    local e=ES()
    local z=0
    for i=0,0x1a8-1,4 do if rd(rec+i)==0 then z=z+1 end end
    print(string.format("  [%s] id=%02X flags=%d ok=%s err=%s zeroed=%d/106",tag,id,flags,tostring(ok),e,z))
    local out={}
    for i=0,0x1a8-1,8 do
        local v=rq(rec+i)
        if v~=0 and v~=0xCDCDCDCDCDCDCDCD then
            local hi=math.floor(v/4294967296)
            local tagp = (hi>=0xFFFF8000) and " <KPTR?>" or ""
            out[#out+1]=string.format("+%03X=%016X%s",i,v,tagp)
        end
    end
    print("      "..table.concat(out," "):sub(1,900))
    return z
end

print("[P0] baseline")
local z0=oracle("P0",0x13,0)
local z0b=oracle("P0b",0x13,0)

print("[P1] syscall 597, argument shape A: six zeroes")
local okA=pcall(function() return sc597(Z,Z,Z,Z,Z,Z) end)
print(string.format("  597(0,0,0,0,0,0) ok=%s err=%s",tostring(okA),ES()))
local zA=oracle("P1",0x13,0)

print("[P2] syscall 597, argument shape B: id 0x13 in arg1")
local okB=pcall(function() return sc597(U(0x13),Z,Z,Z,Z,Z) end)
print(string.format("  597(0x13,0,...) ok=%s err=%s",tostring(okB),ES()))
local zB=oracle("P2",0x13,0)

print("[P3] syscall 597, argument shape C: id, size, pointer to a 0x1a8 record")
local okC=pcall(function() return sc597(U(0x13),U(0x1a8),U(rec),Z,Z,Z) end)
print(string.format("  597(0x13,0x1a8,ptr) ok=%s err=%s",tostring(okC),ES()))
local zC=oracle("P3",0x13,0)

print(string.format("[S] zeroed dwords: P0=%d P0b=%d P1=%d P2=%d P3=%d",z0,z0b,zA,zB,zC))
if zA~=z0 or zB~=z0 or zC~=z0 then print("[S] VERDICT: the grant changed the 608 output") else print("[S] VERDICT: no change from 597 in any shape") end
print(string.format("[Z] alive=%d",tn(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
print("=== DONE")
