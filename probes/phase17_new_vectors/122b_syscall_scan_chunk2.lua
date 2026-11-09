-- CRASH_CLASS: LOW
-- PROBE 122b: Syscall scan continuation — eboot 600KB-2MB
--
-- 122a found 0F 05 at +0x93CBD (in MOV displacement) and died at ~600KB.
-- This continues scanning from 600KB. Also decodes all ropchain gadgets.

print("=== PROBE 122b: SYSCALL SCAN CHUNK 2 + GADGET DECODE ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

collectgarbage("stop")

local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_size = safe_rd(info + 0x110) or 0

print(string.format("[*] eboot: 0x%08X_%08X  size=0x%X", text_hi, text_lo, text_size))

local function eboot_addr(off)
    local new_lo = text_lo + off
    local carry = 0
    if new_lo >= 0x100000000 then
        new_lo = new_lo - 0x100000000
        carry = 1
    end
    return uint64(string.format("0x%X%08X", text_hi + carry, new_lo))
end

local function read_byte(off)
    local dw = safe_rd(eboot_addr(off - (off % 4)))
    if not dw then return nil end
    local shift = off % 4
    return math.floor(dw / (256 ^ shift)) % 256
end

local function dump_bytes(off, count)
    local parts = {}
    for i = 0, count - 1 do
        local b = read_byte(off + i)
        if b then table.insert(parts, string.format("%02X", b))
        else table.insert(parts, "??") end
    end
    return table.concat(parts, " ")
end


-- ================================================================
-- SECTION A: Decode ropchain gadgets (from 42i known offsets)
-- ================================================================
print("")
print("--- SECTION A: Ropchain gadget decode ---")
print("")

-- All unique eboot offsets from 42i chain dump
local gadgets = {
    0x42, 0x471, 0x991, 0x992, 0x9A2, 0xE64,
    0xD77D, 0x1EEBB, 0x92C67, 0xC9DFE,
    0x136970, 0x141FC7, 0x3B02D7
}

for _, off in ipairs(gadgets) do
    if off < text_size then
        local bytes = dump_bytes(off, 16)
        print(string.format("  eboot+0x%05X: %s", off, bytes))

        -- Quick decode of common patterns
        local b0 = read_byte(off)
        local b1 = read_byte(off + 1)
        local b2 = read_byte(off + 2)
        local b3 = read_byte(off + 3)

        if b0 == 0xC3 then
            print("    → ret")
        elseif b0 == 0x58 and b1 == 0xC3 then
            print("    → pop rax; ret")
        elseif b0 == 0x5F and b1 == 0xC3 then
            print("    → pop rdi; ret")
        elseif b0 == 0x5E and b1 == 0xC3 then
            print("    → pop rsi; ret")
        elseif b0 == 0x5A and b1 == 0xC3 then
            print("    → pop rdx; ret")
        elseif b0 == 0x59 and b1 == 0xC3 then
            print("    → pop rcx; ret")
        elseif b0 == 0x31 and b1 == 0xC0 and b2 == 0xC3 then
            print("    → xor eax,eax; ret")
        elseif b0 == 0x48 and b1 == 0x89 and b2 == 0xF8 and b3 == 0xC3 then
            print("    → mov rax,rdi; ret")
        elseif b0 == 0x0F and b1 == 0x05 then
            print("    → syscall !")
        elseif b0 == 0x41 then
            -- REX.B prefix
            if b1 == 0x58 and b2 == 0xC3 then print("    → pop r8; ret")
            elseif b1 == 0x59 and b2 == 0xC3 then print("    → pop r9; ret")
            elseif b1 == 0x5A and b2 == 0xC3 then print("    → pop r10; ret")
            elseif b1 == 0x5B and b2 == 0xC3 then print("    → pop r11; ret")
            elseif b1 == 0x5E and b2 == 0xC3 then print("    → pop r14; ret")
            elseif b1 == 0x5F and b2 == 0xC3 then print("    → pop r15; ret")
            end
        elseif b0 == 0x48 and b1 == 0x31 and b2 == 0xC0 then
            print("    → xor rax,rax (+ more)")
        end
    end
end


-- ================================================================
-- SECTION B: Continue syscall scan from 0x96000 to 0x200000
-- ================================================================
print("")
print("--- SECTION B: Syscall scan 600KB-2MB ---")
print("")

local start_off = 0x96000  -- ~600KB, past where 122a died
local end_off = math.min(0x200000, text_size)
local found = 0

for off = start_off, end_off - 4, 4 do
    local dw = safe_rd(eboot_addr(off))
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        local positions = {}
        if b0 == 0x0F and b1 == 0x05 then table.insert(positions, off) end
        if b1 == 0x0F and b2 == 0x05 then table.insert(positions, off + 1) end
        if b2 == 0x0F and b3 == 0x05 then table.insert(positions, off + 2) end

        for _, pos in ipairs(positions) do
            found = found + 1
            print(string.format("  0F05 #%d at eboot+0x%X: %s",
                found, pos, dump_bytes(pos - 8, 20)))
            -- Check mov eax,imm; syscall pattern
            local bm5 = read_byte(pos - 5)
            local bm4 = read_byte(pos - 4)
            local bm3 = read_byte(pos - 3)
            local bm2 = read_byte(pos - 2)
            local bm1 = read_byte(pos - 1)
            local bp2 = read_byte(pos + 2)
            if bm5 == 0xB8 then
                local sysno = bm4 + bm3*256 + bm2*65536 + bm1*16777216
                print(string.format("    *** mov eax,%d; syscall ***", sysno))
                if bp2 == 0xC3 then
                    print(string.format("    *** GOLD: mov eax,%d; syscall; ret ***", sysno))
                end
            end
            if bp2 == 0xC3 then print("    (syscall; ret)") end
        end
    end

    if (off - start_off) % 200000 == 0 and off > start_off then
        print(string.format("  ... +%dK scanned, %d found ...",
            (off - start_off) / 1024, found))
    end
end

print(string.format("\n[B] Found %d 0F05 in 600KB-2MB range", found))


-- ================================================================
-- SECTION C: Quick gadget search — pop rdi;ret, mov rdi,rax;ret
-- ================================================================
print("")
print("--- SECTION C: Key gadget search (first 256KB) ---")
print("")

-- Search for pop rdi;ret (5F C3) and pop rsi;ret (5E C3) and pop rdx;ret (5A C3)
local key_gadgets = {}
local g_cap = math.min(0x40000, text_size)

for off = 0, g_cap - 4, 4 do
    local dw = safe_rd(eboot_addr(off))
    if dw then
        local b0 = dw % 256
        local b1 = math.floor(dw / 256) % 256
        local b2 = math.floor(dw / 65536) % 256
        local b3 = math.floor(dw / 16777216) % 256

        -- pop rdi;ret
        if b0 == 0x5F and b1 == 0xC3 then
            print(string.format("  pop rdi;ret at eboot+0x%X", off))
            table.insert(key_gadgets, {off=off, name="pop rdi;ret"})
        end
        if b1 == 0x5F and b2 == 0xC3 then
            print(string.format("  pop rdi;ret at eboot+0x%X", off+1))
            table.insert(key_gadgets, {off=off+1, name="pop rdi;ret"})
        end
        -- pop rsi;ret
        if b0 == 0x5E and b1 == 0xC3 then
            print(string.format("  pop rsi;ret at eboot+0x%X", off))
            table.insert(key_gadgets, {off=off, name="pop rsi;ret"})
        end
        -- pop rdx;ret
        if b0 == 0x5A and b1 == 0xC3 then
            print(string.format("  pop rdx;ret at eboot+0x%X", off))
            table.insert(key_gadgets, {off=off, name="pop rdx;ret"})
        end
        -- pop rcx;ret
        if b0 == 0x59 and b1 == 0xC3 then
            print(string.format("  pop rcx;ret at eboot+0x%X", off))
            table.insert(key_gadgets, {off=off, name="pop rcx;ret"})
        end
    end
end

print(string.format("[C] Found %d key gadgets in first 256KB", #key_gadgets))

print("")
print("=== PROBE 122b COMPLETE ===")
