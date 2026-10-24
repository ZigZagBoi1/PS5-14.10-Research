-- CRASH_CLASS: MODERATE
-- PROBE 486a: is 662's process-mode gate identical on 14.10?
--
-- 13.60 reads: uap[0] -> rsi, uap[8] -> edx (count), uap[0x10] -> rcx.
-- Gate at 0x3af9c6 (process-mode word) runs BEFORE the count guard at 0x3af9f7.
-- Count guard accepts 1..0x80; 0x81 and above returns 0x16 (EINVAL).
-- So: -1 for every count => gate first, same as 13.60.
--     anything else for count<=0x80 => the body ran on 14.10.

print("=== PROBE 486a: aio_multi_delete gate shape ===")
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
local ids  = memory.alloc(0x1000)
local res  = memory.alloc(0x1000)

local function fill_ids(n, val)
    for i = 0, n * 4 - 1 do wd(ids + i * 4, val) end
end
local function dump_res(tag)
    local s = ""
    for i = 0, 7 do s = s .. string.format("%08X ", rd(res + i * 4)) end
    print("  " .. tag .. " results: " .. s)
end

local function run(count, label)
    for i = 0, 0xFFF, 4 do wd(res + i, 0) end
    fill_ids(math.max(count, 1), 0x41424344)
    local ok, rv = pcall(function()
        return sc662(uint64(ids), uint64(count), uint64(res))
    end)
    local r = ok and sgn(rv) or -999
    print(string.format("[%s] count=%d (%#x) ret=%d (0x%X)", label, count, count, r, r >= 0 and r or (r + 0x100000000) % 0x100000000))
    dump_res(label)
    print("")
end

print("[A] counts below the guard threshold (body reachable if the gate passes)")
run(1,    "A1")
run(4,    "A2")
run(0x10, "A3")
run(0x80, "A4")

print("[B] count above the guard threshold (EINVAL path if the gate passes)")
run(0x81,   "B1")
run(0x1000, "B2")

print("[C] zero count")
run(0, "C1")

print("=== PROBE 486a END ===")
