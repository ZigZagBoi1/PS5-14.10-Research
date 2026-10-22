-- CRASH_CLASS: LOW
-- PROBE 356a: re-test the chicken switches against calls that now work
--
-- 55a set all 32 chicken-switch bits (643) and saw no effect on mprotect(RWX),
-- fork or kldstat. Two of those three were measured against a kldstat that is
-- the nosys trampoline (353b), so that row was never a test of anything. Now
-- that the absent slots return -1 instead of killing, the same switch can be
-- re-checked against gates whose refusal is real: 585 is_in_sandbox, the
-- capability-gated 618/646, and the credential predicate behind 532 cmd 0x00.
--
-- The same connection also tries two object classes the surface never touched:
-- 482 shm_open and the 499 openat path, both with their real arguments.

print("=== PROBE 356a: CHICKEN SWITCHES AGAINST REAL GATES ===")
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
local U = function(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local Z = uint64(0)
local function rd(a) local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end return -1 end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function str_at(addr, s)
    for i = 1, #s do pcall(function() memory.write_byte(addr + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

local page = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do wq(page + i, 0) end
local pbuf = memory.alloc(0x100)
local dir  = memory.alloc(0x40)

-- a GPU mapping to try mprotect(RWX) on
local gpu = sgn(make_syscall(477)(Z, U(0, 0x10000), U(0, 0x33), U(0, 0x1002), U(0, 0xFFFFFFFF), Z))
print(string.format("[0] gpu mmap = %d", gpu))

local function probes(tag)
    local a = sgn(make_syscall(585)(Z, Z, Z, Z, Z, Z))
    local b = sgn(make_syscall(618)(U(0, to_num(page)), U(0, 0x100), U(0, 0), Z, Z, Z))
    local c = sgn(make_syscall(646)(U(0, to_num(page)), U(0, 0x100), Z, Z, Z, Z))
    local d = sgn(make_syscall(532)(U(0, 0), Z, U(0, to_num(page)), Z, U(0, 0x40), Z))
    local e = -999
    if gpu > 0 then
        e = sgn(make_syscall(74)(U(0, gpu), U(0, 0x1000), U(0, 7), Z, Z, Z))
    end
    print(string.format("  %s 585=%d 618=%d 646=%d 532(0x00)=%d mprotect(RWX)=%d",
        tag, a, b, c, d, e))
    return a, b, c, d, e
end

print("[A] before the switch")
probes("before:")

print("[B] 643(0xFFFFFFFF)")
local rv = sgn(make_syscall(643)(U(0, 0xFFFFFFFF), Z, Z, Z, Z, Z))
print(string.format("  643 = %d", rv))

print("[C] after the switch")
probes("after: ")

print("[D] 482 shm_open('/omp356a', O_CREAT|O_RDWR, 0600)")
str_at(dir, "/omp356a")
local fd = sgn(make_syscall(482)(U(0, to_num(dir)), U(0, 0x202), U(0, 0x180), Z, Z, Z))
print(string.format("  shm_open = %d", fd))
if fd >= 3 then
    local ft = sgn(make_syscall(480)(U(0, fd), U(0, 0x1000), Z, Z, Z, Z))
    local m = sgn(make_syscall(477)(Z, U(0, 0x1000), U(0, 3), U(0, 1), U(0, fd), Z))
    print(string.format("  ftruncate = %d  mmap = %d", ft, m))
    if m > 0 then
        wq(U(0, m), U(0x11223344, 0x55667788))
        print(string.format("  wrote, readback = 0x%X", rd(U(0, m))))
    end
    print(string.format("  unlink = %d", sgn(make_syscall(483)(U(0, to_num(dir)), Z, Z, Z, Z, Z))))
end

print("[E] 499 openat('/savedata0', 'omp356a.txt', O_CREAT|O_WRONLY, 0644)")
str_at(dir, "/savedata0")
local dfd = sgn(make_syscall(5)(U(0, to_num(dir)), U(0, 0), Z, Z, Z, Z))
str_at(dir + 0x20, "omp356a.txt")
local afd = sgn(make_syscall(499)(U(0, dfd), U(0, to_num(dir) + 0x20), U(0, 0x201), U(0, 0x1A4), Z, Z))
print(string.format("  dirfd = %d  openat = %d", dfd, afd))

print("")
print("=== 356a DONE ===")
