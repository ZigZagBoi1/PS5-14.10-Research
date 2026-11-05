-- CRASH_CLASS: HIGH
-- PROBE 1009a: are the "lethal" syscalls SIGSYS, and can we catch it?
--
-- Every syscall recorded as "kills the process" produced no fault report (990a),
-- so the signal is not SIGSEGV/BUS/ILL. This probe registers the loader's own pivot
-- handler for SIGSYS (12) and then calls the classic lethal numbers. If a report comes
-- back with signal 12 and the process is still alive, the kill is catchable and the
-- whole "lethal" list becomes measurable instead of fatal.

print("=== PROBE 1009a: SIGSYS CATCH ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return nil end
local function safe(f) local ok,v=pcall(f) if ok then return v end return nil end

print(string.format("[0] pid=%u fd=%s ready=%s", to_num(mk(20)()), rq(signal.fd_addr), tostring(signal.pivot_already_setup)))

local ph = gadgets.stack_pivot[1]
local GA, PA, PB = nil, nil, nil
for k,v in pairs(ph) do print(string.format("[G] %s = %s", tostring(k), tostring(v))) end
GA = to_num(ph.gadget_addr or ph.gadget)
print(string.format("[G] handler gadget = 0x%X", GA))

-- register the same pivot handler for SIGSYS
local sa = memory.alloc(0x28)
for o=0,0x20,8 do pcall(function() memory.write_qword(sa+o, 0) end) end
pcall(function() memory.write_qword(sa, GA) end)
pcall(function() memory.write_qword(sa+0x20, 0x4) end)   -- SA_SIGINFO
local sa_a = nil
local ok0, s0 = pcall(function() return tostring(sa):match("0x(%x+)") end)
if ok0 and s0 then sa_a = tonumber(s0,16) end
if not sa_a then local _,n = pcall(function() return sa:tonumber() end) sa_a = to_num(n) end
print(string.format("[1] sa=0x%X handler=0x%X", sa_a, GA))

local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[2] sigaction(12) ok=%s rv=%s", tostring(ok), ok and tostring(to_num(rv)) or ""))

-- now the previously lethal numbers, one at a time
local buf = memory.alloc(0x400)
local function zero() for o=0,0x3F8,8 do pcall(function() memory.write_qword(buf+o, 0) end) end end
local probes = {
    {306, "kldstat"},
    {189, "fstat"},
    {337, "kldsym"},
    {570, "sysctlbyname"},
}
for i,p in ipairs(probes) do
    zero()
    print(string.format("[C%d] calling %u (%s)", i, p[1], p[2]))
    local okc, cv = pcall(function() return mk(p[1])(uint64(as_addr(buf)), uint64(0x400), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print(string.format("[C%d] ok=%s rv=%s buf0=%s alive pid=%u", i, tostring(okc), okc and tostring(to_num(cv)) or "", rq(buf), to_num(mk(20)())))
end
print("=== COMPLETE ===")
