-- CRASH_CLASS: LOW
-- PROBE 437a: does a freed object slot come back to the next allocation?
--
-- 435a showed evf (538/539) and osem (549/550) create and delete cleanly - 200 of 200 freed -
-- and that every family draws from one per-process handle table. 436a saw that namedobj ids
-- are not plain slot numbers (9007, 9006, 9004 ...) and that 558 refuses them, so namedobj is
-- the wrong family to read the allocator from. evf is the clean one.
--
-- If a freed slot is handed to the next allocation, the table is a stack and a later primitive
-- can put a chosen object on a chosen slot. If ids keep climbing, the allocator hands out new
-- slots and old ones are not reused until the table wraps.
--
-- [A] eight evf, print ids
-- [B] delete the four in the middle in a chosen order (3rd, 1st, 4th, 2nd)
-- [C] create four, print ids - compare with the freed set
-- [D] delete everything, create four, print ids

print("=== PROBE 437a: SLOT REUSE ===")

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

local page = call(477, 0, 0x1000, 7, 0x1002, 0xFFFFFFFF, 0)
if page <= 0 then print("no page") return end
local i = 0
while i < 0x400 do memory.write_qword(page + i, uint64(0)); i = i + 8 end

local function mk() return call(538, page, 0, 0, 0, 0, 0) end
local function rm(h) return call(539, h, 0, 0, 0, 0, 0) end

local a, k = {}, 1
while k <= 8 do a[k] = mk(); k = k + 1 end
print(string.format("[A] created: %d %d %d %d %d %d %d %d", a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]))

local order = {3, 1, 4, 2}
local s = ""
k = 1
while k <= 4 do
    local idx = order[k]
    s = s .. string.format(" rm(%d)=%d", a[idx], rm(a[idx]))
    k = k + 1
end
print("[B]" .. s)

local b = {}
k = 1
while k <= 4 do b[k] = mk(); k = k + 1 end
print(string.format("[C] created: %d %d %d %d", b[1], b[2], b[3], b[4]))

-- free everything and allocate four
k = 1
while k <= 8 do rm(a[k]); k = k + 1 end
k = 1
while k <= 4 do rm(b[k]); k = k + 1 end
local c = {}
k = 1
while k <= 4 do c[k] = mk(); k = k + 1 end
print(string.format("[D] after full free: %d %d %d %d", c[1], c[2], c[3], c[4]))

print("=== 437a DONE ===")
