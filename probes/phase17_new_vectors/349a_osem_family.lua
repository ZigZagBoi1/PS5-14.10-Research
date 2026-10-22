-- CRASH_CLASS: LOW
-- PROBE 349a: create a counting-semaphore object and drive the family
--
-- 334a called every osem number with six "shapes" and all returned -1, which
-- only says the shapes never met the contract. results/kernel_handlers/analysis/
-- sys_549.md gives it: four slots, (attributes, initial, maximum, name), allowed
-- attribute bits 0x103, low bits 3 rejected, initial >= 0, maximum > 0,
-- initial <= maximum, non-null name bounded to 0x20, a 0x60-byte object with the
-- handle published at td+0x408. This is the first probe that creates one.
-- The rest of the family: 550 delete, 551 open by name, 552 close, 553 wait,
-- 554 poll, 555 post, 556 cancel.

print("=== PROBE 349a: OSEM FAMILY ===")
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
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end
local function call(num, a, b, c, d)
    local fn = make_syscall(num)
    local ok, rv = pcall(function()
        return fn(uint64(a or 0), uint64(b or 0), uint64(c or 0),
            uint64(d or 0), uint64(0), uint64(0))
    end)
    if not ok then return "EXC" end
    local h, l = get_hi_lo(rv)
    local hi, lo = to_num(h), to_num(l)
    if hi == 0xFFFFFFFF and lo == 0xFFFFFFFF then return -1 end
    if hi ~= 0 then return string.format("%08X_%08X", hi, lo) end
    return sgn(rv)
end

local function put_str(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local name = put_str("omp349a_sem")

print("[A] 549 with the recovered layout (attr, initial, maximum, name)")
local r = call(549, 0, 0, 1, name)
print(string.format("  549(0,0,1,name)        = %s", tostring(r)))
if type(r) ~= "number" or r < 0 then
    local perms = {
        { 0, 1, name, 0 }, { 1, 0, name, 0 }, { 0, name, 0, 1 },
        { name, 0, 0, 1 }, { 0, 0, 1, 0x100 }, { 1, 1, 1, 0 },
    }
    for i, p in ipairs(perms) do
        local pr = call(549, p[1], p[2], p[3], p[4])
        print(string.format("  549 perm%d (%s) = %s", i, tostring(p[1]) .. "," .. tostring(p[2]) .. "," .. tostring(p[3]) .. "," .. tostring(p[4]), tostring(pr)))
    end
end

print("[B] validation controls")
print(string.format("  549(0,2,1,name) init>max = %s", tostring(call(549, 0, 2, 1, name))))
print(string.format("  549(0,0,0,name) max=0    = %s", tostring(call(549, 0, 0, 0, name))))
print(string.format("  549(0,0,1,NULL) name=NUL = %s", tostring(call(549, 0, 0, 1, 0))))
print(string.format("  549(0x104,0,1,name)      = %s", tostring(call(549, 0x104, 0, 1, name))))

local h = type(r) == "number" and r > 0 and r or nil
print(string.format("[C] handle from [A] = %s", tostring(h)))
if h then
    print(string.format("  555 post(h,1)  = %s", tostring(call(555, h, 1, 0))))
    print(string.format("  554 poll(h)    = %s", tostring(call(554, h, 0, 0))))
    print(string.format("  553 wait(h,0)  = %s", tostring(call(553, h, 0, 0))))
    print(string.format("  555 post(h,5)  = %s", tostring(call(555, h, 5, 0))))
    print(string.format("  556 cancel(h)  = %s", tostring(call(556, h, 0, 0))))
    print(string.format("  552 close(h)   = %s", tostring(call(552, h, 0, 0))))
    print(string.format("  552 close(h)2  = %s", tostring(call(552, h, 0, 0))))
    print(string.format("  550 delete(h)  = %s", tostring(call(550, h, 0, 0))))
end

print("[D] open by name, and the shared registry")
local name2 = put_str("omp349a_shared")
local r2 = call(549, 0x100, 0, 1, name2)
print(string.format("  549(0x100,0,1,shared)  = %s", tostring(r2)))
if type(r2) == "number" and r2 > 0 then
    print(string.format("  551 open(shared)        = %s", tostring(call(551, name2, 0, 0))))
    print(string.format("  551 open(absent)        = %s", tostring(call(551, put_str("omp349a_absent"), 0, 0))))
end

print("")
print("=== 349a DONE ===")
