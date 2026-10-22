-- CRASH_CLASS: MODERATE
-- PROBE 354a: the last unexplained kills - absent, or a handler that faults
--
-- 353a/353b established the discriminator: the shared nosys trampoline raises
-- SIGSYS, so with SIGSYS ignored an absent slot returns -1. A slot that still
-- terminates the process under SIG_IGN is a real handler that faulted on the
-- arguments - and a fault in a handler that took a user pointer is the only
-- shape that can become a primitive.
--
-- Four numbers still carry an unexplained kill in the presence map: 568, 569,
-- 571 and 621. Each is called twice: six zeros, then a mapped page in slot 0 and
-- a length in slot 2, so a fault that needs a pointer is separated from one that
-- does not.

print("=== PROBE 354a: THE UNEXPLAINED KILLS UNDER SIG_IGN ===")
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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local Z = uint64(0)
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end

local sa = memory.alloc(0x80)
local old = memory.alloc(0x80)
for i = 0, 0x70, 8 do
    wq(sa + i, 0)
    wq(old + i, 0)
end
wq(sa + 0, 1)
wd(sa + 8, 0)
local okI, rvI = pcall(function()
    return make_syscall(416)(uint64(12), uint64(sa), uint64(old))
end)
print(string.format("[A] sigaction(12, SIG_IGN) -> %s", okI and tostring(sgn(rvI)) or "EXC"))
if not (okI and sgn(rvI) == 0) then
    print("    cannot ignore SIGSYS; stopping")
    print("=== 354a DONE ===")
    return
end

local page = memory.alloc(0x1000)
for i = 0, 0x3FF do wd(page + i * 4, 0) end

local function call(num, a0, a1, a2, a3, a4, a5)
    local ok, rv = pcall(function()
        return make_syscall(num)(a0 or Z, a1 or Z, a2 or Z, a3 or Z, a4 or Z, a5 or Z)
    end)
    if ok then return tostring(sgn(rv)) end
    return "EXC"
end

print("[B] six zeros")
for _, num in ipairs({568, 569, 571, 621}) do
    print(string.format("  sys %d(0 x6) = %s", num, call(num)))
end

print("[C] a mapped page and a length")
for _, num in ipairs({568, 569, 571, 621}) do
    print(string.format("  sys %d(page, 0x40, 0, 0, 0, 0) = %s", num,
        call(num, uint64(page), uint64(0x40))))
    print(string.format("  sys %d(0, page, 0x40, 0, 0, 0) = %s", num,
        call(num, Z, uint64(page), uint64(0x40))))
    print(string.format("  sys %d(page, 0x40, 0, 0, 0, 0) tag2 = %s", num,
        call(num, uint64(page), uint64(0x40), Z, Z)))
end

print("[D] restoring the disposition")
pcall(function()
    return make_syscall(416)(uint64(12), uint64(old), Z)
end)

print("")
print("=== 354a DONE ===")
