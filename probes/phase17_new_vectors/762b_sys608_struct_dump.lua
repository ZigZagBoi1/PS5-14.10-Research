-- CRASH_CLASS: LOW
-- PROBE 762b: full dynlib_get_info_ex struct (608), every qword
--
-- 762a established that 608 answers with ret=0 for every handle from 592 and
-- fills a 0x1a8 struct whose +0x08 is the module name. No kernel-shaped qword
-- appeared in that first 0x1a8, but the static audit named specific fields that
-- are two-level dereferences of the dynlib object, so this dumps every qword of
-- a 0x400 page and reports each one that is not a small integer or a userland
-- pointer, with the field offset.

print("=== PROBE 762b: 608 FULL STRUCT ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
print("[A] tid="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

local hl = to_num(memory.alloc(0x400)); wd(hl, 0)
local hc = to_num(memory.alloc(8)); wd(hc, 0)
call(mk(592), hl, 0x100, hc, 0, 0, 0)
local hn = rd(hc) or 0
local handles = {}
for i=0,math.min(hn,64)-1 do handles[#handles+1] = rd(hl + i*4) end
print(string.format("[A] handles=%s", tostring(hn)))

local page = 0x400
local buf = to_num(memory.alloc(page))
local function dump(tag, h, mode)
    zero(buf, page); wq(buf, uint64(0x1a8))
    local r = call(mk(608), h, mode, buf, 0, 0, 0)
    local name = ""
    local ok, s = pcall(function() return memory.read_buffer(buf + 8, 32) end)
    if ok and type(s) == "string" then name = s:gsub("%z.*$", "") end
    print(string.format("  %s h=%X ret=%s name=%s", tag, h, tostring(r), name))
    if tostring(r) ~= "0" then return end
    local interesting = 0
    for off=0,0x1a0,8 do
        local v = rq(buf+off) or 0
        local hi = math.floor(v / 4294967296)
        local is_user = hi > 0 and hi < 0x100     -- userland 0x0..0xFF_xxxxxxxx
        local is_small = v < 0x10000
        local is_zero = v == 0
        if not (is_user or is_small or is_zero) then
            interesting = interesting + 1
            print(string.format("    +%03X = %016X%s", off, v,
                (hi >= 0xFFFF8000) and "   <-- KERNEL RANGE" or ""))
        end
    end
    -- always show the audited fields
    local a = {0x128,0x130,0x160,0x170,0x148,0x150,0x158,0x168,0x178,0x180}
    local line = {}
    for _,off in ipairs(a) do line[#line+1] = string.format("+%X=%X", off, rq(buf+off) or 0) end
    print("    audited: "..table.concat(line, " "))
    if interesting == 0 then print("    (no unusual qwords)") end
end

local pick = {}
for i=1,#handles do
    if handles[i] == 0 or handles[i] == 0x2001 or handles[i] == 0x14 or handles[i] == 0x13 then
        pick[#pick+1] = handles[i]
    end
end
for _,h in ipairs(pick) do dump("608", h, 0) end
print("[D] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 762b DONE ===")
