-- CRASH_CLASS: MODERATE
-- PROBE 347a: does an evf call accept a handle from another family?
--
-- 338a showed 544/545/546 returning 0 for handles 518-522, and 522 is a
-- namedobj handle (557 allocates those), not an evf. If the handle check is a
-- bound on a shared table rather than a type test, then an evf set/clear is
-- writing into a namedobj record at evf offsets - a shape difference that would
-- be a kernel object type confusion. This creates one object of each family and
-- calls every handle-taking number with every handle, recording the return.

print("=== PROBE 347a: CROSS-FAMILY HANDLES ===")
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
local function call(num, a, b, c, d, e, f)
    local fn = make_syscall(num)
    local ok, rv = pcall(function()
        return fn(uint64(a or 0), uint64(b or 0), uint64(c or 0),
            uint64(d or 0), uint64(e or 0), uint64(f or 0))
    end)
    if not ok then return "EXC" end
    local h, l = get_hi_lo(rv)
    local hi, lo = to_num(h), to_num(l)
    if hi == 0xFFFFFFFF and lo == 0xFFFFFFFF then return -1 end
    if hi ~= 0 then return string.format("%08X_%08X", hi, lo) end
    return sgn(rv)
end

local page = memory.alloc(0x1000)
for i = 0, 0x3FF do
    pcall(function() memory.write_qword(page + i * 8, uint64(0)) end)
end

-- name string for the registry
local function put_str(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

print("[A] create one of each family")
local evf = call(538, page)
print(string.format("  evf_create(page)        = %s", tostring(evf)))
local nm = put_str("omp347a_named")
local named = call(557, nm, 0, 0x1000)
print(string.format("  namedobj_create(name)   = %s", tostring(named)))
local ok, rv = pcall(function()
    return make_syscall(540)(uint64(named), 0, 0, 0, 0, 0)
end)
print(string.format("  evf_lookup(named handle)= %s", ok and tostring(sgn(lo_of(rv))) or "EXC"))

print("[B] every handle-taking number against every handle")
local handles = { { "evf", evf }, { "named", named } }
local nums = { 541, 542, 543, 544, 545, 546 }
for _, hn in ipairs(handles) do
    if type(hn[2]) == "number" then
        for _, n in ipairs(nums) do
            local r1 = call(n, hn[2], 0, 0)
            local r2 = call(n, hn[2], 1, 0)
            print(string.format("  %-3d %-5s h=%d -> val0=%s val1=%s",
                n, hn[1], hn[2], tostring(r1), tostring(r2)))
        end
    end
end

print("[C] the refused values as controls")
for _, h in ipairs({ 0, 1, 65535, 2147483647 }) do
    print(string.format("  544 h=%d -> %s", h, tostring(call(544, h, 1, 0))))
end

print("")
print("=== 347a DONE ===")
