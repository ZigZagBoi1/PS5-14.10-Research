-- CRASH_CLASS: LOW
-- PROBE 143w: SIDT/SGDT gadget scan — scan only, no execution
--
-- Find all 0F 01 patterns in eboot .text, classify as SIDT/SGDT,
-- check for nearby C3 (ret), print results cleanly.

print("=== PROBE 143w: SIDT/SGDT SCAN ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

-- Eboot base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

local eboot_base = uint64(string.format("0x%X%08X", ehi, elo))

--------------------------------------------------------------------
-- [A] Dword scan for 0F 01 pattern
--------------------------------------------------------------------
print("")
print("--- [A] Scanning 5MB ---")

local SCAN = 0x500000
local hits = {}

for off = 0, SCAN - 4, 4 do
    local dw = safe_rd(eboot_base + off)
    if not dw then break end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Check byte pairs for 0F 01
    if b0 == 0x0F and b1 == 0x01 then
        local modrm = b2
        local reg = math.floor(modrm / 8) % 8
        local md = math.floor(modrm / 64)
        local rm = modrm % 8
        if md ~= 3 and (reg == 0 or reg == 1) then
            table.insert(hits, {off=off, reg=reg, md=md, rm=rm, modrm=modrm})
        end
    end
    if b1 == 0x0F and b2 == 0x01 then
        local modrm = b3
        local reg = math.floor(modrm / 8) % 8
        local md = math.floor(modrm / 64)
        local rm = modrm % 8
        if md ~= 3 and (reg == 0 or reg == 1) then
            table.insert(hits, {off=off+1, reg=reg, md=md, rm=rm, modrm=modrm})
        end
    end
    if b2 == 0x0F and b3 == 0x01 then
        local modrm = safe_rb(eboot_base + off + 4)
        if modrm then
            local reg = math.floor(modrm / 8) % 8
            local md = math.floor(modrm / 64)
            local rm = modrm % 8
            if md ~= 3 and (reg == 0 or reg == 1) then
                table.insert(hits, {off=off+2, reg=reg, md=md, rm=rm, modrm=modrm})
            end
        end
    end
end

print("[A] Total 0F 01 hits: " .. #hits)

--------------------------------------------------------------------
-- [B] For each hit, look for C3 (ret) within 20 bytes
--------------------------------------------------------------------
print("")
print("--- [B] Checking for ret ---")

local usable = {}

for _, h in ipairs(hits) do
    local ilen = 3
    if h.md == 1 then ilen = 4 end
    if h.md == 2 then ilen = 7 end
    if h.rm == 4 and h.md ~= 3 then ilen = ilen + 1 end

    for scan = ilen, 20 do
        local b = safe_rb(eboot_base + h.off + scan)
        if b == 0xC3 then
            h.retd = scan
            table.insert(usable, h)
            break
        end
    end
end

print("[B] Usable (gadget+ret): " .. #usable)

--------------------------------------------------------------------
-- [C] Print usable gadgets with byte dumps
--------------------------------------------------------------------
print("")
print("--- [C] Usable gadgets ---")

local reg_names = {[0]="rax", [1]="rcx", [2]="rdx", [3]="rbx",
    [4]="SIB", [5]="RIP", [6]="rsi", [7]="rdi"}

for i, h in ipairs(usable) do
    local name = h.reg == 0 and "SGDT" or "SIDT"
    local target_reg = reg_names[h.rm] or "?"

    -- Dump bytes
    local bytes = ""
    for j = 0, h.retd do
        local b = safe_rb(eboot_base + h.off + j)
        if b then bytes = bytes .. string.format("%02X ", b) end
    end

    local marker = ""
    if h.rm == 7 and h.md == 0 then marker = " *** [rdi] IDEAL" end
    if h.rm == 6 and h.md == 0 then marker = " * [rsi]" end
    if h.rm == 0 and h.md == 0 then marker = " * [rax]" end

    print(string.format("[C] %s [%s] +0x%06X mod=%d ret@%d: %s%s",
        name, target_reg, h.off, h.md, h.retd, bytes, marker))

    if i >= 30 then
        print("[C] ... (" .. (#usable - 30) .. " more)")
        break
    end
end

--------------------------------------------------------------------
-- [D] Summary: best candidates by register target
--------------------------------------------------------------------
print("")
print("--- [D] Best candidates ---")

local best = {}
for _, rm_want in ipairs({7, 6, 0, 2, 1}) do
    for _, h in ipairs(usable) do
        if h.rm == rm_want and h.md == 0 and h.reg == 1 then  -- SIDT
            if not best["sidt_" .. reg_names[rm_want]] then
                best["sidt_" .. reg_names[rm_want]] = h
            end
        end
        if h.rm == rm_want and h.md == 0 and h.reg == 0 then  -- SGDT
            if not best["sgdt_" .. reg_names[rm_want]] then
                best["sgdt_" .. reg_names[rm_want]] = h
            end
        end
    end
end

for k, h in pairs(best) do
    print("[D] " .. k .. " at +0x" .. string.format("%06X", h.off) ..
        " ret@" .. h.retd)
end

print("")
print("=== PROBE 143w COMPLETE ===")
