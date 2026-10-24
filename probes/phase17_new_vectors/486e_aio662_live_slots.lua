-- CRASH_CLASS: HIGH
-- PROBE 486e: does 662 resolve any low id?
--
-- 486a showed the delete body runs from a game process and reports 0x80020003
-- per id. In the 13.60 listing that status is the "id out of range / not found"
-- path, so a low id may resolve to a live slot. Any status other than
-- 0x80020003 means an id exists; a delete of a live slot may kill the game.

print("=== PROBE 486e: 662 live slot lookup ===")
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
    local n = to_num(v)
    if n >= 0x8000000000000000 then return n - 0x10000000000000000 end
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end
local function rd(a)
    local v = 0
    pcall(function() v = to_num(memory.read_dword(a)) end)
    return v
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local sc662 = make_syscall(662)
local ids = memory.alloc(0x1000)
local res = memory.alloc(0x1000)

local function run(first, n, label)
    for i = 0, 0xFFF, 4 do wd(res + i, 0) end
    for i = 0, n - 1 do wd(ids + i * 4, first + i) end
    local ok, rv = pcall(function()
        return sc662(uint64(ids), uint64(n), uint64(res))
    end)
    local r = ok and sgn(rv) or -999
    local hits, line = 0, ""
    for i = 0, n - 1 do
        local st = rd(res + i * 4)
        if st ~= 0x80020003 then hits = hits + 1 end
        if i < 16 then line = line .. string.format("%d:%08X ", first + i, st) end
    end
    print(string.format("[%s] ids %d..%d n=%d ret=%d nondefault=%d", label, first, first + n - 1, n, r, hits))
    print("  " .. line)
    print("")
end

print("[A] ids 0..7")
run(0, 8, "A")

print("[B] ids 0..63")
run(0, 64, "B")

print("[C] single large id")
run(0xFFFF, 1, "C")

print("=== PROBE 486e END ===")
