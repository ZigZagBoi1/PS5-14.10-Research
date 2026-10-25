-- CRASH_CLASS: LOW
-- PROBE 530j: Find the real GOT by scanning between .text end and .data
--
-- 530i: dynlib_get_info reports eboot .data at 0x300180000 which is far from
-- .text at 0x051B60000. The GOT has zero GnmDriver pointers in that region.
--
-- On PS5, the real GOT/PLT is typically:
-- 1. Right after .text (in a separate RW segment)
-- 2. At known offsets from module base
--
-- Plan:
-- 1. Scan the gap between eboot .text end and the reported .data for readable
--    regions that contain module text pointers
-- 2. Also check: the eboot GOT might use RELATIVE relocations (IRELATIVE)
--    where the GOT entry contains an eboot .text address, not gnm .text
-- 3. Check if GnmDriver functions are called through a vtable/function ptr
--    stored in a global struct rather than through GOT

print("=== PROBE 530j: GOT HUNT ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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

local sc_593 = mk(593)
local function get_mod(handle)
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    pcall(function() sc_593(uint64(handle), ib) end)
    local text_lo = rd(N(ib) + 0x108) or 0
    local text_hi = rd(N(ib) + 0x10C) or 0
    if text_lo < 0 then text_lo = text_lo + 0x100000000 end
    if text_hi < 0 then text_hi = text_hi + 0x100000000 end
    local text_size = rd(N(ib) + 0x110) or 0
    if text_size < 0 then text_size = text_size + 0x100000000 end
    local data_lo = rd(N(ib) + 0x120) or 0
    local data_hi = rd(N(ib) + 0x124) or 0
    if data_lo < 0 then data_lo = data_lo + 0x100000000 end
    if data_hi < 0 then data_hi = data_hi + 0x100000000 end
    return {
        text_lo = text_lo, text_hi = text_hi, text_size = text_size,
        data_lo = data_lo, data_hi = data_hi,
        text_base = text_hi * 0x100000000 + text_lo,
        data_base = data_hi * 0x100000000 + data_lo,
    }
end

local eboot = get_mod(0)
local gnm = get_mod(56)
local lk = get_mod(0x2001)

local eboot_text_end = eboot.text_base + eboot.text_size
print(string.format("eboot: text=0x%X end=0x%X data=0x%X",
    eboot.text_base, eboot_text_end, eboot.data_base))
print(string.format("gnm:   text=0x%X+0x%X", gnm.text_base, gnm.text_size))
print(string.format("lk:    text=0x%X+0x%X", lk.text_base, lk.text_size))

-- ============================================================
-- [A] Probe the region right after eboot .text
-- PS5 ELFs have .rodata, .relro, .got, .data after .text
-- ============================================================
print("")
print("[A] Scan after eboot .text end")

-- Try reading pages after .text end
local pages_scanned = 0
local first_readable = -1
local first_fault = -1
local gnm_ptrs_found = {}

for page = 0, 63 do  -- scan up to 1 MB after .text
    local addr = eboot_text_end + page * 0x4000
    local v = rq(addr)
    if v then
        if first_readable == -1 then first_readable = page end
        -- Scan this page for gnm/lk pointers
        for off = 0, 0x4000 - 8, 8 do
            local qv = rq(addr + off)
            if qv then
                local vh, vl = get_hi_lo(qv)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                if vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm.text_lo + gnm.text_size then
                    table.insert(gnm_ptrs_found, {
                        addr = addr + off,
                        off_from_text_end = page * 0x4000 + off,
                        gnm_off = vl - gnm.text_lo
                    })
                end
            end
        end
        pages_scanned = pages_scanned + 1
    else
        if first_readable ~= -1 and first_fault == -1 then
            first_fault = page
        end
    end
end

print(string.format("  %d pages readable after .text", pages_scanned))
if first_readable >= 0 then
    print(string.format("  first readable: page %d (text_end+0x%X)", first_readable, first_readable * 0x4000))
end
if first_fault >= 0 then
    print(string.format("  first fault: page %d (text_end+0x%X)", first_fault, first_fault * 0x4000))
end
print(string.format("  GnmDriver pointers found: %d", #gnm_ptrs_found))

for i, p in ipairs(gnm_ptrs_found) do
    if i > 20 then print("  ... +" .. (#gnm_ptrs_found - 20) .. " more"); break end
    print(string.format("  text_end+0x%05X -> gnm+0x%04X", p.off_from_text_end, p.gnm_off))
end

-- ============================================================
-- [B] If no GOT found, scan .text for indirect call patterns
-- x86-64: FF 15 xx xx xx xx = CALL [rip + disp32]
-- The disp32 points to a GOT entry relative to next instruction
-- ============================================================
print("")
print("[B] Scan eboot .text for FF 15 (call [rip+disp]) patterns")

-- Only scan first 256 KB of .text for speed
local call_indirect = {}
local scan_text = math.min(eboot.text_size, 0x40000)

for off = 0, scan_text - 6, 1 do
    local b1 = rd(eboot.text_base + off)
    if b1 then
        local byte0 = b1 % 256
        local byte1 = math.floor(b1 / 256) % 256
        if byte0 == 0xFF and byte1 == 0x15 then
            -- disp32 is at off+2 (little-endian 32-bit signed)
            local disp_lo = rd(eboot.text_base + off + 2)
            if disp_lo then
                if disp_lo < 0 then disp_lo = disp_lo + 0x100000000 end
                -- Only low 32 bits matter, sign-extend
                local disp = disp_lo % 0x100000000
                if disp >= 0x80000000 then disp = disp - 0x100000000 end

                -- Target = rip + disp (rip = addr of next instruction = text_base + off + 6)
                local rip = eboot.text_base + off + 6
                local target = rip + disp

                -- Read what the GOT entry points to
                local got_val = rq(target)
                if got_val then
                    local vh, vl = get_hi_lo(got_val)
                    if vh < 0 then vh = vh + 0x100000000 end
                    if vl < 0 then vl = vl + 0x100000000 end
                    if vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm.text_lo + gnm.text_size then
                        table.insert(call_indirect, {
                            text_off = off,
                            got_addr = target,
                            gnm_off = vl - gnm.text_lo
                        })
                    end
                end
            end
        end
    end
end

print(string.format("  indirect calls to GnmDriver: %d (in first %d KB)", #call_indirect, scan_text / 1024))
for i, c in ipairs(call_indirect) do
    if i > 20 then break end
    print(string.format("  text+0x%06X: call [GOT@0x%X] -> gnm+0x%04X",
        c.text_off, c.got_addr, c.gnm_off))
end

-- ============================================================
-- [C] Also scan for GnmDriver function pointers on the HEAP
-- The game likely stores a GnmDriver context struct somewhere
-- ============================================================
print("")
print("[C] Scan heap area for GnmDriver pointers (quick 128 KB)")

local sc_477 = mk(477)
local heap_gnm = {}
-- Use the pipe object's address as heap reference
local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if rop_str then
    local rop_addr = N(uint64(rop_str))
    -- Scan 128 KB around rop address for gnm pointers
    local scan_start = rop_addr - 0x10000
    for off = 0, 0x20000 - 8, 8 do
        local v = rq(scan_start + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            if vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm.text_lo + gnm.text_size then
                table.insert(heap_gnm, {addr = scan_start + off, gnm_off = vl - gnm.text_lo})
            end
        end
    end
    print(string.format("  GnmDriver ptrs near heap: %d", #heap_gnm))
    for i, h in ipairs(heap_gnm) do
        if i > 10 then break end
        print(string.format("  0x%X -> gnm+0x%04X", h.addr, h.gnm_off))
    end
else
    print("  no rop reference found")
end

-- ============================================================
-- [D] Last resort: scan GnmDriver .data for the doorbell directly
-- On AMD GCN/RDNA, the doorbell is a 4-byte write to a mapped page
-- Look for non-zero values that could be MMIO addresses
-- ============================================================
print("")
print("[D] GnmDriver .data deep scan (4 KB)")

local sc_649 = mk(649)
local data_tb = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(3), uint64(data_tb)) end)
local gnm_data = rq(N(data_tb))
local gnm_data_n = N(gnm_data)
print("  gnm .data = " .. fmt(gnm_data))

-- Look for pointer-like values that could be MMIO mappings
local mmio_candidates = {}
for off = 0, 0x1000 - 8, 8 do
    local v = rq(gnm_data_n + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        -- Skip zeros, NID entries, and gnm text pointers
        if vh ~= 0 or vl ~= 0 then
            if vh < 0xFFFF4000 or vh > 0xFFFF5000 then
                if not (vh == gnm.text_hi and vl >= gnm.text_lo) then
                    -- Could be a pointer — try reading it
                    local ptr_addr = vh * 0x100000000 + vl
                    local test_rd = rd(ptr_addr)
                    local readable = test_rd ~= nil
                    if readable or (vh >= 1 and vh <= 0x20) then
                        table.insert(mmio_candidates, {
                            off = off, vh = vh, vl = vl, readable = readable,
                            first_dword = test_rd
                        })
                    end
                end
            end
        end
    end
end

print(string.format("  non-NID, non-text pointer candidates: %d", #mmio_candidates))
for i, m in ipairs(mmio_candidates) do
    if i > 15 then break end
    local tag = m.readable and string.format("R val=0x%X", m.first_dword < 0 and m.first_dword + 0x100000000 or m.first_dword) or "FAULT"
    print(string.format("  .data+0x%03X: 0x%08X%08X [%s]", m.off, m.vh, m.vl, tag))
end

print("")
print("=== 530j DONE ===")
