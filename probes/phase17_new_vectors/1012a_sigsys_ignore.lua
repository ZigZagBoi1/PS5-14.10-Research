-- CRASH_CLASS: HIGH
-- PROBE 1012a: is the kill after SIGSYS avoidable with SIG_IGN?
--
-- 1011a: 306 kldstat delivered SIGSYS to our pivot handler (a truncated report arrived)
-- and then the process stopped answering. Two readings: the kernel kills after the
-- handler returns, or the handler itself dies. SIG_IGN removes the handler from the
-- picture: the signal is discarded in-kernel. If the process then survives and 306
-- returns an errno, the kill is a plain signal and every "lethal" number becomes
-- measurable. If it still dies, the kill is forced (SIGKILL) and no handler helps.

print("=== PROBE 1012a: SIGSYS IGNORE ===")
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

print(string.format("[0] pid=%u", to_num(mk(20)())))
local sa = memory.alloc(0x28)
local saa = as_addr(sa)
wq(saa, 1)          -- SIG_IGN
wq(saa+0x20, 0)
local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[1] SIG_IGN installed: ok=%s rv=%s", tostring(ok), ok and tostring(to_num(rv)) or "ERR"))

local buf = memory.alloc(0x200)
local ba = as_addr(buf)
for o=0,0x1F8,8 do wq(ba+o,0) end
print("[2] calling 306 kldstat")
local ok3, e3 = pcall(function() return mk(306)(uint64(ba), uint64(0x200), uint64(0), uint64(0), uint64(0), uint64(0)) end)
if ok3 then
    print(string.format("[2] returned %d", to_num(e3)))
else
    print("[2] pcall failed: "..tostring(e3):sub(1,90))
end
print(string.format("[2] alive pid=%u buf0=%s", to_num(mk(20)()), tostring(buf)))
print("=== COMPLETE ===")
