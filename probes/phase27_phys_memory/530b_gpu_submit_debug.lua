-- CRASH_CLASS: MODERATE
-- PROBE 530b: Debug GPU submit — fix addressing and descriptor format
--
-- 530a: ioctl 0xC0108102 returns 0 (ACCEPTED!) but DMA copy didn't happen.
-- Also: 0xC010810B returns 0 — unknown second ioctl.
--
-- Hypotheses:
-- 1. CPU VA != GPU VA — need to use physical addresses or GPU-mapped VAs
-- 2. Descriptor format wrong — ps5-hen might be for a different FW
-- 3. DMA_DATA flags wrong
-- 4. Need to use physical addrs (the phys from AllocateDirectMemory)
-- 5. Need a NOP or RELEASE_MEM packet after DMA_DATA for completion
--
-- New tests:
-- [A] Query ioctl 0xC010810B
-- [B] Submit with physical addresses in DMA_DATA
-- [C] Try COPY_DATA (0x40) instead of DMA_DATA (0x50)
-- [D] Try CP_DMA (0x41)
-- [E] Try NOP-only submit to verify pipeline works
-- [F] Read back ioctl output buffer for error codes

print("=== PROBE 530b: GPU SUBMIT DEBUG ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
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

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local sc_477 = mk(477)
local sc_73  = mk(73)
local sc_ioctl = mk(54)

local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    return N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
end

-- Get libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print("libkernel=" .. fmt(lk_base))
local alloc_fn = lk_base + uint64(0x17EF0)

local dm_fd = open_dev("/dev/dmem0")
local gc_fd = open_dev("/dev/gc")
print("dmem0=" .. dm_fd .. " gc=" .. gc_fd)

-- Allocate 3 buffers
local DMEM_SIZE = 0x4000  -- 1 page each (smaller = less waste)
local phys = {}
local va = {}

for i, label in ipairs({"src", "dst", "cmd"}) do
    local phys_out = memory.alloc(8)
    wq(N(phys_out), uint64(0))
    pcall(function()
        native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64("0x150000000"), uint64(DMEM_SIZE),
            uint64(DMEM_SIZE), uint64(0), uint64(N(phys_out)))
    end)
    phys[i] = rq(N(phys_out))
    local ph, pl = get_hi_lo(phys[i])
    if ph < 0 then ph = ph + 0x100000000 end
    if pl < 0 then pl = pl + 0x100000000 end

    local ok_m, rv_m = pcall(function()
        return sc_477(uint64(0), uint64(DMEM_SIZE), uint64(3), uint64(1),
                       uint64(dm_fd), uint64(string.format("0x%X%08X", ph, pl)))
    end)
    if ok_m and rv_m then
        local rh = get_hi_lo(rv_m)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then
            va[i] = N(rv_m)
        end
    end
    print(string.format("  %s: phys=%s va=%s", label, fmt(phys[i]), va[i] and string.format("0x%X", va[i]) or "FAIL"))
end

if not va[1] or not va[2] or not va[3] then print("ALLOC FAIL"); return end

-- Write pattern to src, zero dst
for off = 0, 0x3F, 4 do
    wd(va[1] + off, 0xDEADBEEF + off)
    wd(va[2] + off, 0)
end

-- ============================================================
-- [A] Query ioctl 0xC010810B
-- ============================================================
print("")
print("[A] ioctl 0xC010810B investigation")
local qbuf = memory.alloc(0x20)
for i = 0, 0x1F, 4 do wd(N(qbuf) + i, 0) end

local ok_q, rv_q = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC010810B), uint64(N(qbuf)))
end)
print(string.format("  rv=%d", rv_q and N(rv_q) or -999))
-- Dump output
for i = 0, 3 do
    local d = rd(N(qbuf) + i * 4)
    if d then
        if d < 0 then d = d + 0x100000000 end
        print(string.format("  [+%d] 0x%08X", i*4, d))
    end
end

-- ============================================================
-- [B] Submit using PHYSICAL addresses in DMA_DATA
-- ============================================================
print("")
print("[B] DMA_DATA with physical addresses")

local src_ph, src_pl = get_hi_lo(phys[1])
if src_ph < 0 then src_ph = src_ph + 0x100000000 end
if src_pl < 0 then src_pl = src_pl + 0x100000000 end
local dst_ph, dst_pl = get_hi_lo(phys[2])
if dst_ph < 0 then dst_ph = dst_ph + 0x100000000 end
if dst_pl < 0 then dst_pl = dst_pl + 0x100000000 end

-- Zero cmd buffer
for off = 0, 0x3F, 4 do wd(va[3] + off, 0) end

-- DMA_DATA with physical addressing
-- header: type3, count=5 (6 dwords payload), opcode=0x50
local hdr = 0xC0055002  -- (3<<30)|(5<<16)|(0x50<<8)|(1<<1)
-- DMA control: bit 0 = engine (0=ME, 1=PFP), bits[14:13]=src_cache, bits[26:25]=dst_cache
-- bit 20 = src_sel (0=addr, 1=GDS, 4=DATA), bit 29 = dst_sel
-- For addr-to-addr copy: src_sel=0, dst_sel=0
-- cp_sync=1 (bit 31)
local dma_ctl = 0x80000000  -- cp_sync only, everything else 0
wd(va[3] + 0x00, hdr)
wd(va[3] + 0x04, dma_ctl)
wd(va[3] + 0x08, src_pl)   -- src_addr_lo (physical)
wd(va[3] + 0x0C, src_ph)   -- src_addr_hi
wd(va[3] + 0x10, dst_pl)   -- dst_addr_lo (physical)
wd(va[3] + 0x14, dst_ph)   -- dst_addr_hi
wd(va[3] + 0x18, 64)       -- byte_count

print(string.format("  src_phys=0x%X%08X dst_phys=0x%X%08X", src_ph, src_pl, dst_ph, dst_pl))

-- Build descriptor — try different formats
-- Format 1: raw PM4 header + addr
local desc = memory.alloc(0x20)
-- Try simpler: just point directly to cmd buffer VA
local cmd_va_h, cmd_va_l = get_hi_lo(uint64(string.format("0x%X", va[3])))
if cmd_va_l < 0 then cmd_va_l = cmd_va_l + 0x100000000 end
if cmd_va_h < 0 then cmd_va_h = cmd_va_h + 0x100000000 end

-- ps5-hen descriptor format: {INDIRECT_BUF_hdr | addr_lo, addr_hi, size_dwords}
-- INDIRECT_BUF = opcode 0x3F, type 3
-- Header: (3<<30)|(2<<16)|(0x3F<<8) = 0xC0023F00
wd(N(desc) + 0, 0xC0023F00)
wd(N(desc) + 4, cmd_va_l)
wd(N(desc) + 8, cmd_va_h)
wd(N(desc) + 12, 7)  -- 7 dwords (1 hdr + 6 payload)

-- Submit struct: {pipe_id(4), count(4), desc_ptr(8)}
local sub = memory.alloc(0x10)
wd(N(sub), 0)       -- pipe 0
wd(N(sub) + 4, 1)   -- count 1
local desc_h, desc_l = get_hi_lo(desc)
if desc_l < 0 then desc_l = desc_l + 0x100000000 end
if desc_h < 0 then desc_h = desc_h + 0x100000000 end
wd(N(sub) + 8, desc_l)
wd(N(sub) + 12, desc_h)

local ok_s, rv_s = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
end)
print(string.format("  submit rv=%d", rv_s and N(rv_s) or -999))

-- Wait
local dummy = 0
for i = 1, 500000 do dummy = dummy + 1 end

local d0 = rd(va[2])
if d0 and d0 < 0 then d0 = d0 + 0x100000000 end
print(string.format("  dst[0]=0x%X (want 0xDEADBEEF) match=%s", d0 or 0, tostring(d0 == 0xDEADBEEF)))

-- ============================================================
-- [C] Submit NOP-only to verify the pipeline executes
-- ============================================================
print("")
print("[C] NOP-only submit")

-- Write a NOP followed by a RELEASE_MEM that writes a fence value
local fence = memory.alloc(8)
wq(N(fence), uint64(0))

for off = 0, 0x3F, 4 do wd(va[3] + off, 0) end

-- NOP packet: (3<<30)|(0<<16)|(0x10<<8) = 0xC0001000
wd(va[3] + 0x00, 0xC0001000)  -- NOP, 1 payload dword
wd(va[3] + 0x04, 0xDEAD)      -- padding

-- RELEASE_MEM (0x49): write a known value to our fence address
-- Header: (3<<30)|(5<<16)|(0x49<<8) = 0xC0054900
-- This tells the GPU to write a value to memory when it reaches this point
local fence_h, fence_l = get_hi_lo(uint64(string.format("0x%X", N(fence))))
if fence_l < 0 then fence_l = fence_l + 0x100000000 end
if fence_h < 0 then fence_h = fence_h + 0x100000000 end

wd(va[3] + 0x08, 0xC0054900)  -- RELEASE_MEM header
-- event_cntl: EVENT_INDEX=5 (write), EVENT_TYPE=0x28 (BOTTOM_OF_PIPE)
wd(va[3] + 0x0C, 0x00000528)  -- event_cntl
wd(va[3] + 0x10, fence_l)      -- addr_lo
wd(va[3] + 0x14, fence_h)      -- addr_hi
-- data: SEL=1 (32-bit write), data_lo=0xFEEDFACE
wd(va[3] + 0x18, 0x20000000)   -- data_sel=1 at bit29
wd(va[3] + 0x1C, 0xFEEDFACE)  -- data_lo

-- Descriptor for 8 dwords
wd(N(desc) + 12, 8)  -- 8 dwords now

local ok_n, rv_n = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
end)
print(string.format("  submit rv=%d", rv_n and N(rv_n) or -999))

for i = 1, 500000 do dummy = dummy + 1 end

local fv = rd(N(fence))
if fv and fv < 0 then fv = fv + 0x100000000 end
print(string.format("  fence=0x%X (want 0xFEEDFACE) match=%s", fv or 0, tostring(fv == 0xFEEDFACE)))

-- ============================================================
-- [D] Read ioctl output buffer after submit
-- ============================================================
print("")
print("[D] Submit output buffer inspection")
-- The ioctl is _IOWR so it reads AND writes. Check what it wrote back.
print("  sub struct after submit:")
for i = 0, 3 do
    local d = rd(N(sub) + i * 4)
    if d then
        if d < 0 then d = d + 0x100000000 end
        print(string.format("    [+%d] 0x%08X", i*4, d))
    end
end

-- ============================================================
-- [E] Try submit with cmd buffer itself as the descriptor
-- Maybe PS5 doesn't use INDIRECT_BUF — it reads the PM4 directly
-- ============================================================
print("")
print("[E] Direct PM4 submit (no INDIRECT_BUF)")

-- Put PM4 at start of cmd buffer
for off = 0, 0x3F, 4 do wd(va[3] + off, 0) end
wd(va[3] + 0x00, 0xC0001000)  -- NOP

-- Point desc directly at cmd buffer as PM4 stream, no INDIRECT_BUF wrapper
local sub2 = memory.alloc(0x10)
wd(N(sub2), 0)       -- pipe 0
wd(N(sub2) + 4, 1)   -- count 1 descriptor

-- Try: descriptor = {addr_lo, addr_hi, size_dwords, ???}
local desc2 = memory.alloc(0x20)
wd(N(desc2) + 0, cmd_va_l)   -- addr_lo
wd(N(desc2) + 4, cmd_va_h)   -- addr_hi
wd(N(desc2) + 8, 2)          -- size = 2 dwords
wd(N(desc2) + 12, 0)

local d2_h, d2_l = get_hi_lo(desc2)
if d2_l < 0 then d2_l = d2_l + 0x100000000 end
if d2_h < 0 then d2_h = d2_h + 0x100000000 end
wd(N(sub2) + 8, d2_l)
wd(N(sub2) + 12, d2_h)

local ok_e, rv_e = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub2)))
end)
print(string.format("  submit rv=%d", rv_e and N(rv_e) or -999))

-- ============================================================
-- [F] Try using cmd buffer PHYSICAL address in descriptor
-- ============================================================
print("")
print("[F] Descriptor with physical cmd address")

local cmd_ph, cmd_pl = get_hi_lo(phys[3])
if cmd_ph < 0 then cmd_ph = cmd_ph + 0x100000000 end
if cmd_pl < 0 then cmd_pl = cmd_pl + 0x100000000 end

local desc3 = memory.alloc(0x20)
wd(N(desc3) + 0, 0xC0023F00)  -- INDIRECT_BUF header
wd(N(desc3) + 4, cmd_pl)      -- physical addr lo
wd(N(desc3) + 8, cmd_ph)      -- physical addr hi
wd(N(desc3) + 12, 2)          -- 2 dwords

local d3_h, d3_l = get_hi_lo(desc3)
if d3_l < 0 then d3_l = d3_l + 0x100000000 end
if d3_h < 0 then d3_h = d3_h + 0x100000000 end

local sub3 = memory.alloc(0x10)
wd(N(sub3), 0)
wd(N(sub3) + 4, 1)
wd(N(sub3) + 8, d3_l)
wd(N(sub3) + 12, d3_h)

local ok_f, rv_f = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub3)))
end)
print(string.format("  submit rv=%d", rv_f and N(rv_f) or -999))

-- Cleanup
pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)
pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)

print("")
print("=== 530b DONE ===")
