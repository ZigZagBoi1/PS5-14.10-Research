-- CRASH_CLASS: MODERATE
-- PROBE 444a: 539 is the evf delete, not 541
--
-- 442a treated 541 as delete and found it refusing the creator's handle (-1) and accepting the
-- opened one (0). 435a had already used 539 for evf and freed 200 of 200, so 541 is the close
-- and 539 is the delete. This repeats the lifetime question with the right call.
--
-- [A] create a named evf, open it by name, delete the creator's handle
-- [B] does the name still resolve, and does the object still work through the opened handle?
-- [C] close the opened handle, then recreate the same name

print("=== PROBE 444a: EVF DELETE ===")

local GEN_SHIFT = 8192
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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end
local function tag(h) return string.format("%d(g%d/s%d)", h, math.floor(h / GEN_SHIFT), h % GEN_SHIFT) end

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end

local nm = memory.alloc(0x40)
local function put(s)
    local j = 1
    while j <= #s do memory.write_byte(nm + j - 1, s:byte(j)); j = j + 1 end
    memory.write_byte(nm + #s, 0)
end

put("omp444a")
local h1 = call(538, nm, 0x100, 0, 0, 0, 0)
local h2 = call(540, nm, 0, 0, 0, 0, 0)
print(string.format("[A] create=%s open=%s", tag(h1), tag(h2)))

local d = call(539, h1, 0, 0, 0, 0, 0)
print(string.format("[B] delete(creator)=%d", d))
local r = call(540, nm, 0, 0, 0, 0, 0)
local set = call(544, h2, 0x3, 0, 0, 0, 0)
print(string.format("[B] resolve name=%d set(opened h2)=%d", r, set))

local c = call(541, h2, 0, 0, 0, 0, 0)
local r2 = call(540, nm, 0, 0, 0, 0, 0)
print(string.format("[C] close(opened)=%d resolve after=%d", c, r2))

local h3 = call(538, nm, 0x100, 0, 0, 0, 0)
print(string.format("[C] recreate same name=%s (was %s)", tag(h3), tag(h1)))

print("=== 444a DONE ===")
