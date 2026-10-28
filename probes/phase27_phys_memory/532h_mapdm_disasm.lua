-- CRASH_CLASS: LOW
-- PROBE 532h: Disassemble MapDirectMemory wrapper
--
-- libkernel+0x15020 = sceKernelMapDirectMemory
-- libkernel is RX (not XO like system libs), so we can read it.
-- Read first 256 bytes of the function and decode x86-64 instructions.
-- Goal: find which syscall it calls and how args are arranged.
-- If the underlying syscall doesn't need the 7th arg (name),
-- we can call it directly with our 6-arg fcall.

print("=== PROBE 532h: MAPDM DISASM ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

-- Get libkernel base
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
print("lk=" .. q(lk))

-- MapDirectMemory at lk + 0x15020
local map_fn = lk + uint64(0x15020)
print("map_fn=" .. q(map_fn))

-- Read first 512 bytes as raw hex
print("")
print("[DISASM] Raw bytes (512B from map_fn):")
local map_fn_n = to_num(lk) + 0x15020

-- Check if readable
local test_byte = rd(map_fn_n)
if not test_byte then
    print("  FAULT — libkernel .text is XO, cannot read!")
    print("  (Need to use Ghidra on 13.60 capture instead)")
    print("=== 532h DONE ===")
    return
end

-- Dump as hex lines (16 bytes per line)
for line = 0, 31 do
    local addr = map_fn_n + line * 16
    local hex_str = string.format("+0x%03X: ", line * 16)
    for col = 0, 3 do
        local d = rd(addr + col * 4)
        if d then
            if d < 0 then d = d + 0x100000000 end
            -- Print bytes in order (little-endian dword → individual bytes)
            for byte_i = 0, 3 do
                local b = math.floor(d / (256 ^ byte_i)) % 256
                hex_str = hex_str .. string.format("%02X ", b)
            end
        else
            hex_str = hex_str .. "?? ?? ?? ?? "
        end
    end
    print("  " .. hex_str)
end

-- Also read AllocateDirectMemory for comparison
print("")
print("[ALLOC] Raw bytes (128B from alloc_fn):")
local alloc_fn_n = to_num(lk) + 0x17EF0
for line = 0, 7 do
    local addr = alloc_fn_n + line * 16
    local hex_str = string.format("+0x%03X: ", line * 16)
    for col = 0, 3 do
        local d = rd(addr + col * 4)
        if d then
            if d < 0 then d = d + 0x100000000 end
            for byte_i = 0, 3 do
                local b = math.floor(d / (256 ^ byte_i)) % 256
                hex_str = hex_str .. string.format("%02X ", b)
            end
        else
            hex_str = hex_str .. "?? ?? ?? ?? "
        end
    end
    print("  " .. hex_str)
end

-- Also dump GetDirectMemorySize for context
print("")
print("[GETDMS] Raw bytes (64B from lk+0x17810):")
local getdms_n = to_num(lk) + 0x17810
for line = 0, 3 do
    local addr = getdms_n + line * 16
    local hex_str = string.format("+0x%03X: ", line * 16)
    for col = 0, 3 do
        local d = rd(addr + col * 4)
        if d then
            if d < 0 then d = d + 0x100000000 end
            for byte_i = 0, 3 do
                local b = math.floor(d / (256 ^ byte_i)) % 256
                hex_str = hex_str .. string.format("%02X ", b)
            end
        else
            hex_str = hex_str .. "?? ?? ?? ?? "
        end
    end
    print("  " .. hex_str)
end

print("")
print("=== 532h DONE ===")
