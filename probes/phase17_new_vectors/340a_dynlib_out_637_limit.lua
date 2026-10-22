-- CRASH_CLASS: MODERATE
-- PROBE 340a: what 598 and 659 write, then 637 with limiting values only
--
-- 335a found 598 dynlib_get_proc_param returns 0 for (page, page, 0x100, page)
-- and 659 dynlib_get_list2 returns 0 for (page, 0x100, page, 0x100); both are
-- copy-out handlers, so this dumps what lands in the page. 637 answered 0 for a
-- large value and blocked the caller for a small one (339a: value 16 returns
-- -1, value 17 never returned), so it is called last and only with values far
-- above any plausible current usage. 637 is id 0 = this process, which skips
-- the capability predicate; id 1 and 2 exercise it and cost nothing.

print("=== PROBE 340a: 598 / 659 / 637 ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
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
local function call(sc, a, b, c, d, e, f)
    local ok, rv = pcall(function() return sc(a, b, c, d, e, f) end)
    if not ok then return nil end
    return sgn(lo_of(rv))
end
local function fmt(v)
    if v == nil then return "EXC" end
    return tostring(v)
end
local PAGE
local function dump(label, len)
    local shown = 0
    for i = 0, len - 8, 8 do
        local lo = safe_rd(PAGE + i)
        local hi = safe_rd(PAGE + i + 4)
        if lo and hi and (lo ~= 0 or hi ~= 0) then
            if shown < 24 then
                print(string.format("    %s+0x%03X = 0x%08X_%08X", label, i, hi, lo))
                shown = shown + 1
            end
        end
    end
    if shown == 0 then print("    " .. label .. "(all zero)") end
end

PAGE = memory.alloc(0x1000)
local Z = uint64(0)
local sc598 = make_syscall(598)
local sc659 = make_syscall(659)
local sc637 = make_syscall(637)
local P = uint64(PAGE)

print("[A] 598 dynlib_get_proc_param")
for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
local r598 = call(sc598, P, P, uint64(0x100), P, Z, Z)
print(string.format("  598(P,P,0x100,P) = %s", fmt(r598)))
dump("598", 0x400)

print("[B] 598 with the buffer in arg0 only")
for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
print(string.format("  598(P,0,0,0) = %s", fmt(call(sc598, P, Z, Z, Z, Z, Z))))
dump("598b", 0x400)

print("[C] 659 dynlib_get_list2")
for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
local r659 = call(sc659, P, uint64(0x100), P, uint64(0x100), Z, Z)
print(string.format("  659(P,0x100,P,0x100) = %s", fmt(r659)))
dump("659", 0x400)

print("[D] 659 with one buffer")
for i = 0, 0x1000 - 8, 8 do safe_wq(PAGE + i, Z) end
print(string.format("  659(P,0x100,0,0) = %s", fmt(call(sc659, P, uint64(0x100), Z, Z, Z, Z))))
dump("659b", 0x400)

print("[E] 637 with values above any current usage")
for _, v in ipairs({ 0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF }) do
    print(string.format("  637(0, 0x%X) = %s", v, fmt(call(sc637, Z, uint64(v), Z, Z, Z, Z))))
end
print("[F] 637 with a foreign id")
for _, id in ipairs({ 1, 2, 5 }) do
    print(string.format("  637(%d, 0xFFFFFFFF) = %s", id, fmt(call(sc637, uint64(id), uint64(0xFFFFFFFF), Z, Z, Z, Z))))
end

print("")
print("=== 340a DONE ===")
