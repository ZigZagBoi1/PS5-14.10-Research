-- CRASH_CLASS: LOW
-- PROBE 143x: SIDT/SGDT small scan — first 256KB only
--
-- Previous 5MB scans produced binary garbage, probably from hitting
-- non-readable segments. Scan just the first 256KB of eboot .text
-- which is verified readable (RX).

print("=== PROBE 143x: SIDT SMALL SCAN ===")
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

-- Eboot base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

local eboot = uint64(string.format("0x%X%08X", ehi, elo))

-- First, verify reading works
local test_dw = to_num(memory.read_dword(eboot))
print("eboot[0]=0x" .. string.format("%08X", test_dw))

-- Known: the eboot .text header starts with MZ or ELF magic
-- Verify we're in readable region
print("")
print("--- [A] Verify readability ---")
local boundaries = {0x0, 0x1000, 0x10000, 0x40000, 0x80000, 0xC0000, 0x100000, 0x200000, 0x300000, 0x400000, 0x500000}
for _, off in ipairs(boundaries) do
    local ok, val = pcall(function() return to_num(memory.read_dword(eboot + off)) end)
    if ok then
        print("[A] +" .. string.format("0x%X", off) .. " readable (0x" .. string.format("%08X", val) .. ")")
    else
        print("[A] +" .. string.format("0x%X", off) .. " UNREADABLE")
    end
end

-- Scan VERIFIED readable region for 0F 01
print("")
print("--- [B] Scan first 1MB ---")

local SCAN = 0x100000  -- 1MB
local hits = {}

-- First verify the scan range is readable
local last_readable = 0
for off = 0, SCAN, 0x1000 do
    local ok = pcall(function() memory.read_dword(eboot + off) end)
    if ok then
        last_readable = off
    else
        break
    end
end
print("[B] Readable up to +" .. string.format("0x%X", last_readable))

local scan_end = math.min(SCAN, last_readable + 0x1000)
print("[B] Scanning " .. string.format("0x%X", scan_end) .. " bytes")

for off = 0, scan_end - 4, 4 do
    local ok, raw = pcall(function() return memory.read_dword(eboot + off) end)
    if not ok then break end
    local dw = to_num(raw)

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    if b0 == 0x0F and b1 == 0x01 then
        local modrm = b2
        local reg = math.floor(modrm / 8) % 8
        local md = math.floor(modrm / 64)
        local rm = modrm % 8
        if md ~= 3 and (reg == 0 or reg == 1) then
            table.insert(hits, {off=off, reg=reg, md=md, rm=rm})
        end
    end
    if b1 == 0x0F and b2 == 0x01 then
        local modrm = b3
        local reg = math.floor(modrm / 8) % 8
        local md = math.floor(modrm / 64)
        local rm = modrm % 8
        if md ~= 3 and (reg == 0 or reg == 1) then
            table.insert(hits, {off=off+1, reg=reg, md=md, rm=rm})
        end
    end
    if b2 == 0x0F and b3 == 0x01 then
        local ok2, nb = pcall(function() return to_num(memory.read_byte(eboot + off + 4)) end)
        if ok2 then
            local modrm = nb
            local reg = math.floor(modrm / 8) % 8
            local md = math.floor(modrm / 64)
            local rm = modrm % 8
            if md ~= 3 and (reg == 0 or reg == 1) then
                table.insert(hits, {off=off+2, reg=reg, md=md, rm=rm})
            end
        end
    end
end

print("[B] Hits: " .. #hits)

--------------------------------------------------------------------
-- [C] Check each hit for nearby ret (C3)
--------------------------------------------------------------------
print("")
print("--- [C] Check for ret ---")

local reg_names = {"rax", "rcx", "rdx", "rbx", "SIB", "RIP", "rsi", "rdi"}

for idx, h in ipairs(hits) do
    local ilen = 3
    if h.md == 1 then ilen = 4 end
    if h.md == 2 then ilen = 7 end
    if h.rm == 4 then ilen = ilen + 1 end

    local found_ret = -1
    for scan = ilen, 20 do
        local ok, b = pcall(function() return to_num(memory.read_byte(eboot + h.off + scan)) end)
        if ok and b == 0xC3 then
            found_ret = scan
            break
        end
    end

    if found_ret >= 0 then
        local name = h.reg == 0 and "SGDT" or "SIDT"
        local rn = reg_names[h.rm + 1] or "?"

        -- Dump bytes
        local bytes = ""
        for j = 0, found_ret do
            local ok, b = pcall(function() return to_num(memory.read_byte(eboot + h.off + j)) end)
            if ok then bytes = bytes .. string.format("%02X ", b) end
        end

        local star = ""
        if h.rm == 7 and h.md == 0 then star = " ***IDEAL***" end
        if h.rm == 6 and h.md == 0 then star = " *GOOD*" end
        if h.rm == 0 and h.md == 0 then star = " *OK*" end

        print(string.format("[C] %s [%s] +0x%06X ret@%d: %s%s",
            name, rn, h.off, found_ret, bytes, star))
    end
end

print("")
print("=== PROBE 143x COMPLETE ===")
