-- CRASH_CLASS: HIGH
-- PROBE 791a: 557 flags come from uap[2], and only 0 has been tested
--
-- The body ORs uap[2] with 0x1000 into the registered flags. aio uses a 0x1000
-- bit to switch to block mode, so other bits here may select a different
-- object class. Sweep uap[2] with both a zero payload and an all-0xFF payload.
print("=== PROBE 791a: 557 FLAGS ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a)
    a=to_num(a); if a<0 then a=a+18446744073709551616 end
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function call(sc,a1,a2,a3,a4,a5,a6)
    local ok,r=pcall(function() return sc(U(a1),U(a2),U(a3),U(a4),U(a5),U(a6)) end)
    if not ok then return "ERR" end
    return to_num(r)
end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function alive() return tostring(call(mk(20),0,0,0,0,0,0)) end
local pl=to_num(memory.alloc(0x100))
local function payload(ff)
    for i=0,0x100-8,8 do wq(pl+i,0) end
    if ff then for i=0,3 do wq(pl+i*8,0xFFFFFFFFFFFFFFFF) end end
end
local flags={0,1,2,4,8,0x10,0x100,0x1000,0x2000,0x4000,0x8000,0x10000}
for _,ff in ipairs({false,true}) do
    for _,f in ipairs(flags) do
        payload(ff)
        local r=call(mk(557),pl,f,0,0,0,0)
        local d="skip"
        if type(r)=="number" and r>0 then d=tostring(call(mk(558),r,0,0,0,0,0)) end
        print(string.format("[%s] flags=%08X create=%s destroy=%s alive=%s",ff and "ff" or "z",f,tostring(r),d,alive()))
    end
end
print("[E] final alive="..alive())
print("=== 791a DONE ===")
