-- CRASH_CLASS: HIGH
-- PROBE 486k: sweep every (context, slot) pair for a reachable aio object.
--
-- 486h covered slot 1 only. A valid context with an empty slot still reports
-- 0x80020003, so the earlier scan could not tell "no context" from "context,
-- no object at slot 1". This walks slots too: contexts 1..127 x slots 1..64,
-- then the same with the halves swapped, and reports any status that is not
-- 0x80020003. 662 returns rather than killing, so the load is cheap.

print("=== PROBE 486k: 662 (context, slot) sweep ===")
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

local total, hits, calls = 0, 0, 0
local function call(first_ctx, n, slot, swap, label)
    for i = 0, 0xFFF, 4 do wd(res + i, 0) end
    for i = 0, n - 1 do
        local ctx, sl = first_ctx + i, slot
        local id = swap and (sl * 0x10000 + ctx) or (ctx * 0x10000 + sl)
        wd(ids + i * 4, id)
    end
    local ok, rv = pcall(function() return sc662(uint64(ids), uint64(n), uint64(res)) end)
    calls = calls + 1
    total = total + n
    local r = ok and sgn(rv) or -999
    if r ~= 0 then print(string.format("  [%s] slot=%d ret=%d (non-zero return)", label, slot, r)) end
    for i = 0, n - 1 do
        local st = rd(res + i * 4)
        if st ~= 0x80020003 then
            hits = hits + 1
            local ctx, sl = first_ctx + i, slot
            print(string.format("  HIT ctx=%d slot=%d swap=%s status=%08X", ctx, sl, tostring(swap), st))
        end
    end
end

print("[A] contexts 1..127, slots 1..64")
for slot = 1, 64 do call(1, 0x7F, slot, false, "A") end
print(string.format("  phase A: calls=%d ids=%d hits=%d", calls, total, hits))

local a_hits = hits
print("[B] swapped halves: slots 1..127, contexts 1..64")
for ctx = 1, 64 do call(1, 0x7F, ctx, true, "B") end
print(string.format("  phase B: calls=%d ids=%d hits=%d", calls, total, hits))

print("")
print(string.format("=== PROBE 486k END calls=%d ids=%d hits=%d (A=%d) ===", calls, total, hits, a_hits))
