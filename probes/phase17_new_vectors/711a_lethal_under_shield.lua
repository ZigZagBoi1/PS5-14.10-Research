-- CRASH_CLASS: MODERATE
-- PROBE 711a: re-test every number that has ever killed us, with a proven shield.
--
-- Context: probe 710a established that the struct form of sigaction(416) really
-- installs SIG_IGN (rv=0) and that 4095 then returns -1 instead of killing,
-- while the direct form 416(12,1,0,0) returns -1 and installs nothing.
--
-- So the earlier "-1 means absent" and "kill means past the end" readings were
-- taken without protection. This re-tests the killing set with the shield on.
-- A -1 now means the slot answered (either ENOSYS or a handler rejecting
-- zeros); silence means the call blocked; a kill means neither, i.e. a fault
-- that SIGSYS ignoring cannot absorb.
--
-- Order: control first, then ascending difficulty, 677/678 last.

print("=== PROBE 711a: killers re-tested under a proven SIGSYS shield ===")
print("")

local function N(v)
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
local function U(a)
    a=N(a)
    return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296))
end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local o,v=pcall(function() return memory.read_dword(a) end)
    if o then return N(v) end
    return nil
end

local sigact=mk(416)
local sa=memory.alloc(0x80)
local oldsa=memory.alloc(0x80)
for i=0,0x78,8 do wq(N(sa)+i,0) end
wq(N(sa)+0,1)
local ok,rv=pcall(function() return sigact(uint64(12),U(N(sa)),U(N(oldsa))) end)
print(string.format("[0] shield rv=%s", tostring(rv)))

local function call(n)
    local sc=mk(n)
    local ok2,r=pcall(function() return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    if not ok2 then return "EXC" end
    return tostring(r)
end

local targets={4095,589,590,597,631,650,651,661,665,668,619,652,677,678}
for _,n in ipairs(targets) do
    print(string.format(">> %d", n))
    print(string.format("<< %d rv=%s", n, call(n)))
end

print(string.format("[Z] alive=%d", N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
