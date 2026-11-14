-- CRASH_CLASS: HIGH
-- PROBE 1017a: SIGSYS with SIG_IGN, verified by read-back.
--
-- Reviewer findings applied: (1) the disposition is read back with sigaction(12, NULL,
-- oldact) so we can prove SIG_IGN landed; (2) the call is gated on the install result;
-- (3) the buffer is read back with rq(buf), not tostring(handle); (4) the same 0x400
-- buffer shape as 1011a is used. If SIG_IGN works, 306 returns ENOSYS and execution
-- continues, proving the "kill" was the default SIGSYS disposition and nothing else.
-- If the loader instead goes silent, the kernel forces termination regardless of the
-- disposition.

print("=== PROBE 1017a: SIGSYS SIG_IGN v2 ===")
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
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end

print(string.format("[0] pid=%u", to_num(mk(20)())))
local sa  = memory.alloc(0x28); local saa = as_addr(sa)
local old = memory.alloc(0x28); local oa  = as_addr(old)
for o=0,0x20,8 do wq(saa+o, 0); wq(oa+o, 0xCCCCCCCCCCCCCCCC) end
wq(saa, 1)      -- SIG_IGN
wq(saa+0x20, 0x4)

local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[1] install ok=%s rv=%s", tostring(ok), ok and tostring(to_num(rv)) or "ERR"))
if not ok or to_num(rv) ~= 0 then print("[!] install failed, abort"); print("=== COMPLETE ===") return end

local ok2, rv2 = pcall(function() return syscall.sigaction(12, 0, old) end)
print(string.format("[2] readback ok=%s rv=%s handler=%s", tostring(ok2), ok2 and tostring(to_num(rv2)) or "ERR", rq(old)))

local buf = memory.alloc(0x400); local ba = as_addr(buf)
for o=0,0x3F8,8 do wq(ba+o, 0x4141414141414141) end
print("[3] calling 306 kldstat")
local ok3, e3 = pcall(function() return mk(306)(uint64(ba), uint64(0x400), uint64(0), uint64(0), uint64(0), uint64(0)) end)
if ok3 then
    print(string.format("[3] returned %d", to_num(e3)))
else
    print("[3] pcall failed: "..tostring(e3):sub(1,80))
end
print(string.format("[3] alive pid=%u buf0=%s", to_num(mk(20)()), rq(buf)))
print("=== COMPLETE ===")
