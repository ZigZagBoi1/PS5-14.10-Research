-- CRASH_CLASS: LOW
-- PROBE 143y: Tiny SIDT scan — 16KB only, with explicit progress

print("=== PROBE 143y: SIDT TINY ===")

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

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=0x" .. string.format("%X%08X", ehi, elo))
local eboot = uint64(string.format("0x%X%08X", ehi, elo))

print("STEP1")
-- Scan 16KB
local hits = 0
local best_off = -1
local best_rm = -1
local best_reg = -1

for off = 0, 0x4000 - 4, 4 do
    local ok, raw = pcall(function() return memory.read_dword(eboot + off) end)
    if not ok then break end
    local dw = to_num(raw)

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256

    if b0 == 0x0F and b1 == 0x01 then
        local reg = math.floor(b2 / 8) % 8
        local md = math.floor(b2 / 64)
        if md ~= 3 and (reg == 0 or reg == 1) then
            hits = hits + 1
            if best_off == -1 then
                best_off = off
                best_rm = b2 % 8
                best_reg = reg
            end
        end
    end
end

print("STEP2 hits=" .. hits)
if best_off >= 0 then
    print("first at +0x" .. string.format("%X", best_off) .. " rm=" .. best_rm .. " reg=" .. best_reg)
end

-- Now scan LARGER but in stages
print("STEP3")
local scan_stopped = false
for chunk = 0x4000, 0x500000, 0x4000 do
    if scan_stopped then break end
    for off = chunk, chunk + 0x3FFC, 4 do
        local ok, raw = pcall(function() return memory.read_dword(eboot + off) end)
        if not ok then
            print("UNREAD at +0x" .. string.format("%X", off))
            scan_stopped = true
            break
        end
        local dw = to_num(raw)
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256

        if b0 == 0x0F and b1 == 0x01 then
            local reg = math.floor(b2 / 8) % 8
            local md = math.floor(b2 / 64)
            if md ~= 3 and (reg == 0 or reg == 1) then
                hits = hits + 1
                if best_off == -1 or (b2 % 8 == 7 and best_rm ~= 7) then
                    best_off = off
                    best_rm = b2 % 8
                    best_reg = reg
                end
            end
        end
    end

    if chunk % 0x100000 == 0 then
        print("@" .. string.format("0x%X", chunk) .. " total=" .. hits)
    end
end
print("STEP4 total=" .. hits)

if best_off >= 0 then
    print("BEST at +0x" .. string.format("%X", best_off) .. " rm=" .. best_rm .. " reg=" .. best_reg)
    -- Check for ret
    for scan = 3, 20 do
        local ok, b = pcall(function() return to_num(memory.read_byte(eboot + best_off + scan)) end)
        if ok and b == 0xC3 then
            print("RET at +" .. scan)
            -- Dump bytes
            local bytes = ""
            for j = 0, scan do
                local ok2, bv = pcall(function() return to_num(memory.read_byte(eboot + best_off + j)) end)
                if ok2 then bytes = bytes .. string.format("%02X ", bv) end
            end
            print("BYTES: " .. bytes)
            break
        end
    end
end

print("=== DONE ===")
