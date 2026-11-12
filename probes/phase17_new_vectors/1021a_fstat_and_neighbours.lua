-- CRASH_CLASS: LOW
-- PROBE 1021a: 189 fstat is a live handler, and its neighbours under the SIGSYS shield
--
-- docs/ATTACK_SURFACE.md:82-83 and CLAUDE.md's dead-end list still call 189/306/307/308
-- "instantly kills the process" (56k4/56k5, 152j), but 353a-353d (2026-10-22) measured the
-- opposite: the death is the nosys SIGSYS path, and with SIG_IGN in place every one of those
-- numbers returns -1 with the process alive. And 189 on a REAL descriptor returns 0 with a
-- filled struct stat, under the default disposition. This probe re-measures that here.
--
-- Section B installs the shield with the struct form (make_syscall(416), act[0]=1) because
-- 710a proved the direct-value form 416(12,1,0,0) installs nothing. Nothing in 185..196 is
-- known to block; if one does, the loader will go silent and that is itself the result.

print("=== PROBE 1021a: FSTAT AND NEIGHBOURS ===")
print("")

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local m = tostring(x):match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end
local function hexq(a) return rq(a) end

local sc_open = mk(5); local sc_fstat = mk(189); local sc_sig = mk(416); local sc_getpid = mk(20)
local getpid = function() return to_num(select(2, pcall(function() return sc_getpid() end))) end

-- [A] fstat on a real descriptor, default disposition
local buf = memory.alloc(0x100); local ba = as_addr(buf)
for o=0,0xF8,8 do wd(ba+o,0x41) end
local pathbuf = memory.alloc(0x40); local pa = as_addr(pathbuf)
local path = "/app0/eboot.bin"
for i=1,#path do wd(pa+i-1, path:byte(i)) end
wd(pa+#path, 0)
local fd = to_num(select(2, pcall(function() return sc_open(uint64(pa), uint64(0), uint64(0)) end)))
print(string.format("[A] open(fd)=%d pid=%d", fd, getpid()))
local okA, rvA = pcall(function() return sc_fstat(uint64(fd), uint64(ba)) end)
print(string.format("[A] fstat rv=%s", okA and tostring(to_num(rvA)) or "PCALL-FAIL"))
print(string.format("[A] st=%s %s %s %s", hexq(ba), hexq(ba+8), hexq(ba+16), hexq(ba+24)))
print(string.format("[A] alive pid=%d", getpid()))

-- [B] the shield, struct form
local act = memory.alloc(0x28); local aa = as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa, 1)                       -- sa_handler = SIG_IGN
local okB, rvB = pcall(function() return sc_sig(uint64(12), uint64(aa), uint64(0)) end)
print(string.format("[B] sigaction(12,SIG_IGN) rv=%s", okB and tostring(to_num(rvB)) or "PCALL-FAIL"))
print(string.format("[B] control 4095 = %s", (function() local o,v=pcall(function() return mk(4095)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end) if o then return tostring(to_num(v)) else return "KILLED" end end)()))
print(string.format("[B] alive pid=%d", getpid()))

-- [C] the cluster with six zeros, under the shield
local numbers = {189,190,191,192,193,194,195,196}
for _,n in ipairs(numbers) do
    local sc = mk(n)
    local o, v = pcall(function() return sc(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("  sys %d = %s", n, o and tostring(to_num(v)) or "PCALL-FAIL"))
end
print(string.format("[C] alive pid=%d", getpid()))
print("=== COMPLETE ===")
