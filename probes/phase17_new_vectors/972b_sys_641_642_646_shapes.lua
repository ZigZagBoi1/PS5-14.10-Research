-- CRASH_CLASS: MODERATE
-- PROBE 972b: 641/642/646 with the struct form and the flat-argument form
print("=== PROBE 972b: 641/642/646 ARG SHAPES ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function rd(a) local o,v=pcall(function() return to_num(memory.read_dword(a)) end) if o then return v end return -999 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function zero(p,n) for i=0,n-4,4 do wd(p+i,0) end end
local function call(tag, sc, ...)
    local args={...}
    local rv
    local ok=pcall(function() rv=sc(unpack(args)) end)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return nil end
    local h,l=hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
    return to_num(rv)
end
local pid=to_num(mk(20)())
print("[0] pid=" .. tostring(pid))
local out=memory.alloc(0x400) zero(out,0x400)
local st=memory.alloc(0x20) zero(st,0x20)
local a=addr_of(out)
local alo,ahi=a%4294967296, math.floor(a/4294967296)

wd(st,pid) wd(st+8,alo) wd(st+12,ahi)
call("641 struct", mk(641), uint64(st))
call("641 flat3", mk(641), uint64(pid), uint64(0), uint64(out))
call("641 flat2", mk(641), uint64(pid), uint64(out))
call("641 self", mk(641), uint64(pid), uint64(st))

local rec=memory.alloc(0x68*4) zero(rec,0x68*4)
local cnt=memory.alloc(0x10) zero(cnt,0x10)
local r=addr_of(rec)
wd(st,pid) wd(st+8,4) wd(st+16,r%4294967296) wd(st+20,math.floor(r/4294967296))
wd(st+24,addr_of(cnt)%4294967296) wd(st+28,math.floor(addr_of(cnt)/4294967296))
call("642 struct", mk(642), uint64(st))
call("642 flat4", mk(642), uint64(pid), uint64(4), uint64(rec), uint64(cnt))

call("646 one", mk(646), uint64(out))
call("646 two", mk(646), uint64(0), uint64(out))
print("[Z] alive pid=" .. tostring(to_num(mk(20)())))
print("=== COMPLETE ===")
