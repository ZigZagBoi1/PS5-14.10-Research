-- CRASH_CLASS: MODERATE
-- PROBE 984a: 605 (workaround8849) with a real out buffer in arg2 — the one slot
-- never varied
--
-- The 13.60 body compares the first argument against five IDs and calls 0xae70c0
-- with a 4-byte out. 112b tested ID 0x19810000 with zeros and got 0. This varies
-- arg2/arg3 (pointer vs value, and the page contents afterwards), and sweeps the
-- neighbouring ID space so the other four whitelist entries can be found.

print("=== PROBE 984a: SYS 605 ARGUMENT SHAPES ===")
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
local function call(tag, ...)
    local a = {...}
    local ok, rv = pcall(function() return mk(605)(unpack(a)) end)
    if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end
    local h,l = hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
    return l
end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))

local page = memory.alloc(0x100)
local pa = addr_of(page)
for i=0,0xFF,4 do wd(page+i, 0xDEADBEEF) end
print(string.format("    page=0x%X prefilled 0xDEADBEEF", pa))

print("[B] ID 0x19810000 with a real out page")
call("id,out,size   ", uint64(0x19810000), uint64(pa), uint64(0x100))
print(string.format("    after: +0x00=0x%08X +0x04=0x%08X +0x08=0x%08X", rd(page), rd(page+4), rd(page+8)))
for i=0,0xFF,4 do wd(page+i, 0xDEADBEEF) end
call("id,size,out   ", uint64(0x19810000), uint64(0x100), uint64(pa))
print(string.format("    after: +0x00=0x%08X +0x04=0x%08X", rd(page), rd(page+4)))
for i=0,0xFF,4 do wd(page+i, 0xDEADBEEF) end
call("id,out        ", uint64(0x19810000), uint64(pa))
print(string.format("    after: +0x00=0x%08X +0x04=0x%08X", rd(page), rd(page+4)))
for i=0,0xFF,4 do wd(page+i, 0xDEADBEEF) end
call("id,out,0,size ", uint64(0x19810000), uint64(pa), uint64(0), uint64(0x100))
print(string.format("    after: +0x00=0x%08X +0x04=0x%08X", rd(page), rd(page+4)))
for i=0,0xFF,4 do wd(page+i, 0xDEADBEEF) end
call("id,0,out,size ", uint64(0x19810000), uint64(0), uint64(pa), uint64(0x100))
print(string.format("    after: +0x00=0x%08X +0x04=0x%08X", rd(page), rd(page+4)))

print("[C] neighbouring IDs, out page in arg2")
for id=0x1980FFF8,0x19810010 do
    for i=0,0xFF,4 do wd(page+i, 0xDEADBEEF) end
    local l = call(string.format("id=0x%08X", id), uint64(id), uint64(pa), uint64(0x100))
    if l == 0 then
        print(string.format("      ZERO id=0x%08X page[0]=0x%08X page[1]=0x%08X", id, rd(page), rd(page+4)))
    end
end

print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
