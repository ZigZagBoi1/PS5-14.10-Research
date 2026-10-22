-- CRASH_CLASS: LOW
-- PROBE 349b: the osem family, with the slot order 349a actually produced
--
-- results/kernel_handlers/analysis/sys_549.md names four slots
-- (attributes, initial, maximum, name). 349a called that layout five times and
-- every call failed, then called (0x310bd0800, 0, 0, 1) - a name pointer in
-- slot 0 - and got a handle back. So on 14.10 the name is the first slot:
-- (name, attributes, initial, maximum).
--
-- This probe confirms the order with validation controls, then uses the handle
-- through the rest of the family: 555 post, 554 poll, 553 wait, 556 cancel,
-- 550 delete, 552 close, and 551 open-by-name.

print("=== PROBE 349b: OSEM SLOT ORDER AND FAMILY ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi_lo(v)
    local h, l = get_hi_lo(v)
    return to_num(h), to_num(l)
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
local function call(n, a1, a2, a3, a4)
    local ok, rv = pcall(function()
        return sc(n)(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), Z, Z)
    end)
    if not ok then return nil end
    return sgn(rv)
end

local nameA = put_str("omp349b_a")
local nameB = put_str("omp349b_b")
local nameShared = put_str("omp349b_shared")
local tmo = memory.alloc(0x10)
wd(tmo, 0)
local res = memory.alloc(0x10)
wd(res, 0)

print("[A] slot order: name first")
local h1 = call(549, nameA, 0, 0, 1)
print(string.format("  549(name,0,0,1)          = %s", tostring(h1)))
local h2 = call(549, nameB, 0, 1, 2)
print(string.format("  549(name,0,1,2)          = %s", tostring(h2)))

print("[B] controls that must fail if the order is right")
print(string.format("  549(name,0,2,1) init>max = %s", tostring(call(549, nameA, 0, 2, 1))))
print(string.format("  549(name,0,0,0) max=0    = %s", tostring(call(549, nameA, 0, 0, 0))))
print(string.format("  549(NULL,0,0,1)          = %s", tostring(call(549, 0, 0, 0, 1))))
print(string.format("  549(name,0x104,0,1) attr = %s", tostring(call(549, nameA, 0x104, 0, 1))))

if not h1 or h1 == -1 then
    print("")
    print("no handle, family not reached")
    print("=== 349b DONE ===")
    return
end

print("[C] post / poll / wait / cancel on handle " .. tostring(h1))
print(string.format("  555(h,1) post            = %s", tostring(call(555, h1, 1))))
print(string.format("  554(h,1) poll            = %s", tostring(call(554, h1, 1))))
print(string.format("  554(h,1) poll again      = %s", tostring(call(554, h1, 1))))
print(string.format("  555(h,3) post            = %s", tostring(call(555, h1, 3))))
print(string.format("  554(h,2) poll            = %s", tostring(call(554, h1, 2))))
print(string.format("  555(h,0) post 0          = %s", tostring(call(555, h1, 0))))
print(string.format("  556(h,0,&res) cancel      = %s  res=0x%X", tostring(call(556, h1, 0, res)), rd(res)))
print(string.format("  553(h,1,NULL) wait       = %s", tostring(call(553, h1, 1, 0))))
print(string.format("  553(h,1,&tmo) wait       = %s  tmo=0x%X", tostring(call(553, h1, 1, tmo)), rd(tmo)))

print("[D] open by name, delete, close")
print(string.format("  551(shared) open absent  = %s", tostring(call(551, nameShared))))
print(string.format("  550(h1) delete           = %s", tostring(call(550, h1))))
print(string.format("  552(h1) close            = %s", tostring(call(552, h1))))
if h2 then
    print(string.format("  550(h2) delete           = %s", tostring(call(550, h2))))
end

print("")
print("=== 349b DONE ===")
