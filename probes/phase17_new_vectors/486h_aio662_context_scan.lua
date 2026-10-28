-- CRASH_CLASS: HIGH
-- PROBE 486h: the id is (context << 16) | slot.
--
-- 13.60 loop at 0x3afbaa:
--   r15 = ids[i]
--   r14 = r15 >> 16 (signed)   must be < 0x80
--   r15 = r15 & 0xffff         must be non-zero
--   otherwise status 0x80020003
-- A failing context lookup also writes 0x80020003, which is why every id we
-- tried was rejected uniformly. Scan all 127 contexts with slot 1 and report
-- any status that is not 0x80020003. A hit means a live AIO context belongs
-- to this process and the delete path can reach real slots.

print("=== PROBE 486h: 662 context scan ===")
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

local function scan(n, slot, label)
    for i = 0, 0xFFF, 4 do wd(res + i, 0) end
    for i = 0, n - 1 do wd(ids + i * 4, (i + 1) * 0x10000 + slot) end
    local ok, rv = pcall(function() return sc662(uint64(ids), uint64(n), uint64(res)) end)
    local r = ok and sgn(rv) or -999
    local hits = 0
    for i = 0, n - 1 do
        local st = rd(res + i * 4)
        if st ~= 0x80020003 then
            hits = hits + 1
            print(string.format("  HIT ctx=%d slot=%d status=%08X", i + 1, slot, st))
        end
    end
    print(string.format("[%s] n=%d ret=%d hits=%d", label, n, r, hits))
end

print("[A] contexts 1..127, slot 1")
scan(0x7F, 1, "A")

print("[B] contexts 1..127, slot 0 (low16 zero => expected default)")
scan(0x7F, 0, "B")

print("")
print("=== PROBE 486h END ===")
