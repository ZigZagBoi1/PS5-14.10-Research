-- CRASH_CLASS: MODERATE
-- PROBE 530a: GPU command submit via /dev/gc ioctl 0xC0108102
--
-- From ps5-hen gpu_dma.cpp, the GPU submit path is:
--   1. Build PM4 DMA_DATA packet (opcode 0x50) in a buffer
--   2. Build an INDIRECT_BUF descriptor (16 bytes) pointing to the cmd buffer
--   3. ioctl(gc_fd, 0xC0108102, {pipe_id, count, descriptors_ptr})
--
-- DMA_DATA uses GPU virtual addresses, not physical.
-- We test whether the submit ioctl is accepted from our game process,
-- and whether CPU VA == GPU VA for our dmem-mapped buffers.
--
-- Test plan:
--   [A] Allocate 3 dmem buffers via AllocateDirectMemory + mmap dmem0
--   [B] Write pattern to src, clear dst
--   [C] Build PM4 DMA_DATA in cmd buffer: copy src->dst (256 bytes)
--   [D] Build INDIRECT_BUF descriptor
--   [E] Submit via ioctl 0xC0108102 on /dev/gc
--   [F] Check if dst received the pattern
--   [G] Try heap buffers as alternative
--   [H] Scan nearby gc ioctls

print("=== PROBE 530a: GPU SUBMIT TEST ===")
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

-- Signal handlers
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local sc_477 = mk(477)
local sc_73  = mk(73)

local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
    end)
    return ok and N(rv) or -1
end

-- ============================================================
-- [A] Allocate direct memory
-- ============================================================
print("[A] Allocating direct memory")

-- Find libkernel (handle 0x2001 on PS5 14.10)
local lk_base = nil
local lk_handles = {0x2001, 1, 0x1}
for _, h in ipairs(lk_handles) do
    local ib2 = memory.alloc(0x200)
    wd(N(ib2), 0x160)
    local ok2, r2 = pcall(function() return mk(593)(uint64(h), ib2) end)
    if ok2 and N(r2) == 0 then
        local name = ""
        for i = 0, 31 do
            local b = rd(N(ib2) + 8 + i)
            if b then local c = b % 256; if c == 0 then break end
                if c >= 32 and c < 127 then name = name .. string.char(c) end
            end
        end
        if name:find("libkernel") or name:find("libSceLibcInternal") then
            local lo = rd(N(ib2) + 0x108) or 0
            local hi = rd(N(ib2) + 0x10C) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            lk_base = uint64(string.format("0x%X%08X", hi, lo))
            print("  " .. name .. " h=" .. h .. " base=" .. fmt(lk_base))
            break
        end
    end
end
-- Fallback: scan wider range
if not lk_base then
    for h = 0, 0x300 do
        local ib2 = memory.alloc(0x200)
        wd(N(ib2), 0x160)
        local ok2, r2 = pcall(function() return mk(593)(uint64(h), ib2) end)
        if ok2 and N(r2) == 0 then
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib2) + 8 + i)
                if b then local c = b % 256; if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") then
                local lo = rd(N(ib2) + 0x108) or 0
                local hi = rd(N(ib2) + 0x10C) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                lk_base = uint64(string.format("0x%X%08X", hi, lo))
                print("  libkernel h=" .. h .. " base=" .. fmt(lk_base))
                break
            end
        end
    end
end
if not lk_base then print("  libkernel NOT FOUND"); return end

local alloc_fn = lk_base + uint64(0x17EF0)
local DMEM_SIZE = 0x200000  -- 2 MiB

local dm_fd = open_dev("/dev/dmem0")
print("  dmem0 fd=" .. dm_fd)

local phys = {}
local va = {}

for i, label in ipairs({"src", "dst", "cmd"}) do
    local phys_out = memory.alloc(8)
    wq(N(phys_out), uint64(0))

    local ok_a, rv_a = pcall(function()
        return native.fcall_with_rax(alloc_fn, 0,
            uint64(0), uint64("0x150000000"), uint64(DMEM_SIZE),
            uint64(DMEM_SIZE), uint64(0), uint64(N(phys_out)))
    end)
    if not ok_a or N(rv_a) ~= 0 then
        print("  " .. label .. " alloc FAIL"); return
    end

    phys[i] = rq(N(phys_out))
    print("  " .. label .. " phys=" .. fmt(phys[i]))

    local ph, pl = get_hi_lo(phys[i])
    if ph < 0 then ph = ph + 0x100000000 end
    if pl < 0 then pl = pl + 0x100000000 end

    local ok_m, rv_m = pcall(function()
        return sc_477(uint64(0), uint64(DMEM_SIZE), uint64(3), uint64(1),
                       uint64(dm_fd), uint64(string.format("0x%X%08X", ph, pl)))
    end)
    if not ok_m or not rv_m then
        print("  " .. label .. " mmap FAIL"); return
    end
    local rh = get_hi_lo(rv_m)
    if rh < 0 then rh = rh + 0x100000000 end
    if rh == 0xFFFFFFFF then
        print("  " .. label .. " mmap -1"); return
    end
    va[i] = N(rv_m)
    print("  " .. label .. " va=" .. fmt(rv_m))
end

-- ============================================================
-- [B] Pattern in src, zeros in dst
-- ============================================================
print("")
print("[B] Writing pattern")
local PATTERN = 0xDEADBEEF
for off = 0, 0xFF, 4 do
    wd(va[1] + off, PATTERN + off)
    wd(va[2] + off, 0)
end
local s0 = rd(va[1])
if s0 and s0 < 0 then s0 = s0 + 0x100000000 end
print(string.format("  src[0]=0x%X dst[0]=%d", s0 or 0, rd(va[2]) or -1))

-- ============================================================
-- [C] PM4 DMA_DATA packet
-- ============================================================
print("")
print("[C] PM4 DMA_DATA")

-- Type3 header: (3<<30) | ((6-1)<<16) | (0x50<<8) | (1<<1) = 0xC0055002
local hdr = 0xC0055002
-- DMA header: cp_sync(31) | dst_cache(26:25)=2 | dst_vol(27) | src_cache(14:13)=2 | src_vol(15)
local dma_hdr = 0x8C00C000

local copy_len = 0x100

-- src VA
local src_u = uint64(string.format("0x%X", va[1]))
local sh, sl = get_hi_lo(src_u)
if sl < 0 then sl = sl + 0x100000000 end
if sh < 0 then sh = sh + 0x100000000 end
-- dst VA
local dst_u = uint64(string.format("0x%X", va[2]))
local dh, dl = get_hi_lo(dst_u)
if dl < 0 then dl = dl + 0x100000000 end
if dh < 0 then dh = dh + 0x100000000 end

wd(va[3] + 0x00, hdr)
wd(va[3] + 0x04, dma_hdr)
wd(va[3] + 0x08, sl)   -- src lo
wd(va[3] + 0x0C, sh)   -- src hi
wd(va[3] + 0x10, dl)   -- dst lo
wd(va[3] + 0x14, dh)   -- dst hi
wd(va[3] + 0x18, copy_len)

print(string.format("  hdr=0x%08X dma=0x%08X len=%d", hdr, dma_hdr, copy_len))
print(string.format("  src=0x%X%08X dst=0x%X%08X", sh, sl, dh, dl))

-- ============================================================
-- [D] INDIRECT_BUF descriptor (16 bytes)
-- ============================================================
print("")
print("[D] Descriptor")

-- ps5-hen format:
-- qword 0: (cmd_addr_lo << 32) | 0xC0023F00
-- qword 1: ((size_dwords & 0xFFFFF) << 32) | (cmd_addr_hi & 0xFFFF)

local cmd_u = uint64(string.format("0x%X", va[3]))
local ch, cl = get_hi_lo(cmd_u)
if cl < 0 then cl = cl + 0x100000000 end
if ch < 0 then ch = ch + 0x100000000 end

local desc_off = 0x100000  -- 1 MiB into cmd buffer (same allocation)
local desc_addr = va[3] + desc_off

-- qword 0: low dword = 0xC0023F00, high dword = cmd_addr_lo
wd(desc_addr + 0, 0xC0023F00)
wd(desc_addr + 4, cl)
-- qword 1: low dword = cmd_addr_hi, high dword = size_dwords
wd(desc_addr + 8, ch)
wd(desc_addr + 12, 7)   -- 7 dwords

print(string.format("  cmd=0x%X%08X desc_at=0x%X", ch, cl, desc_addr))
local dv0 = rq(desc_addr)
local dv1 = rq(desc_addr + 8)
print("  desc[0]=" .. fmt(dv0) .. " desc[1]=" .. fmt(dv1))

-- ============================================================
-- [E] Submit ioctl
-- ============================================================
print("")
print("[E] GPU submit")

local gc_fd = open_dev("/dev/gc")
print("  gc fd=" .. gc_fd)
if gc_fd < 0 or gc_fd > 200 then print("  FAIL open gc"); return end

-- submit struct: {u32 pipe_id, u32 count, u64 descriptors_ptr}
local sub = memory.alloc(0x10)
wd(N(sub), 0)      -- pipe 0
wd(N(sub) + 4, 1)  -- count 1
-- descriptors_ptr
local da_u = uint64(string.format("0x%X", desc_addr))
local dah, dal = get_hi_lo(da_u)
if dal < 0 then dal = dal + 0x100000000 end
if dah < 0 then dah = dah + 0x100000000 end
wd(N(sub) + 8, dal)
wd(N(sub) + 12, dah)

local sc_ioctl = mk(54)

local ok_io, rv_io = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
end)
local rvn = rv_io and N(rv_io) or -999
print(string.format("  pipe=0: ok=%s rv=%d", tostring(ok_io), rvn))

-- Try other pipes
if rvn ~= 0 then
    for _, pipe in ipairs({1, 2, 3, 7}) do
        wd(N(sub), pipe)
        local ok2, rv2 = pcall(function()
            return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub)))
        end)
        print(string.format("  pipe=%d: ok=%s rv=%d", pipe, tostring(ok2), rv2 and N(rv2) or -999))
    end
end

-- ============================================================
-- [F] Check dst
-- ============================================================
print("")
print("[F] Check dst buffer")
-- Busy wait
local dummy = 0
for i = 1, 200000 do dummy = dummy + 1 end

local d0 = rd(va[2])
local d4 = rd(va[2] + 4)
if d0 and d0 < 0 then d0 = d0 + 0x100000000 end
if d4 and d4 < 0 then d4 = d4 + 0x100000000 end
print(string.format("  dst[0]=0x%X (want 0x%X) match=%s", d0 or 0, PATTERN, tostring(d0 == PATTERN)))
print(string.format("  dst[4]=0x%X (want 0x%X)", d4 or 0, PATTERN + 4))

local nz = 0
for off = 0, 0xFF, 4 do
    local v = rd(va[2] + off)
    if v and v ~= 0 then nz = nz + 1 end
end
print("  non-zero dwords in dst: " .. nz .. "/64")

-- ============================================================
-- [G] Heap buffer test
-- ============================================================
print("")
print("[G] Heap cmd buffer")

local h_src = memory.alloc(0x200)
local h_dst = memory.alloc(0x200)
local h_cmd = memory.alloc(0x200)
local h_desc = memory.alloc(0x20)

for off = 0, 0x1F, 4 do
    wd(N(h_src) + off, 0xCAFE0000 + off)
    wd(N(h_dst) + off, 0)
end

-- src/dst addresses from heap
local hs_u = h_src
local hd_u = h_dst
local hsh, hsl = get_hi_lo(hs_u)
if hsl < 0 then hsl = hsl + 0x100000000 end
if hsh < 0 then hsh = hsh + 0x100000000 end
local hdh, hdl = get_hi_lo(hd_u)
if hdl < 0 then hdl = hdl + 0x100000000 end
if hdh < 0 then hdh = hdh + 0x100000000 end

wd(N(h_cmd) + 0x00, hdr)
wd(N(h_cmd) + 0x04, dma_hdr)
wd(N(h_cmd) + 0x08, hsl)
wd(N(h_cmd) + 0x0C, hsh)
wd(N(h_cmd) + 0x10, hdl)
wd(N(h_cmd) + 0x14, hdh)
wd(N(h_cmd) + 0x18, 0x20)

local hch, hcl = get_hi_lo(h_cmd)
if hcl < 0 then hcl = hcl + 0x100000000 end
if hch < 0 then hch = hch + 0x100000000 end

wd(N(h_desc) + 0, 0xC0023F00)
wd(N(h_desc) + 4, hcl)
wd(N(h_desc) + 8, hch)
wd(N(h_desc) + 12, 7)

local h_sub = memory.alloc(0x10)
wd(N(h_sub), 0)
wd(N(h_sub) + 4, 1)
local hda_h, hda_l = get_hi_lo(h_desc)
if hda_l < 0 then hda_l = hda_l + 0x100000000 end
if hda_h < 0 then hda_h = hda_h + 0x100000000 end
wd(N(h_sub) + 8, hda_l)
wd(N(h_sub) + 12, hda_h)

local ok_h, rv_h = pcall(function()
    return sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(h_sub)))
end)
print(string.format("  heap submit: ok=%s rv=%d", tostring(ok_h), rv_h and N(rv_h) or -999))

for i = 1, 200000 do dummy = dummy + 1 end
local hd0 = rd(N(h_dst))
if hd0 and hd0 < 0 then hd0 = hd0 + 0x100000000 end
print(string.format("  heap dst[0]=0x%X (want 0xCAFE0000)", hd0 or 0))

-- ============================================================
-- [H] gc ioctl scan
-- ============================================================
print("")
print("[H] gc ioctl scan (0xC0108100-0xC010810F)")
for cmd_off = 0, 15 do
    local cmd = 0xC0108100 + cmd_off
    local tb = memory.alloc(0x20)
    for i = 0, 0x1F, 4 do wd(N(tb) + i, 0) end

    local ok_t, rv_t = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(tb)))
    end)
    local rn = rv_t and N(rv_t) or -999
    -- Only print interesting ones
    if rn ~= -1 and rn ~= -999 then
        print(string.format("  0x%08X: rv=%d ***", cmd, rn))
    elseif not ok_t then
        print(string.format("  0x%08X: CRASH", cmd))
    else
        print(string.format("  0x%08X: rv=%d", cmd, rn))
    end
end

-- Also try 0x81 group with different sizes
print("")
print("[H2] gc ioctl size variants for cmd 2")
for sz_shift = 0, 8 do
    local sz = (1 + sz_shift) * 8
    -- _IOWR(0x81, 2, sz) = 0xC0008102 | (sz << 16)
    local cmd = 0xC0008102 + (sz * 0x10000)
    local tb = memory.alloc(0x100)
    for i = 0, 0x3F, 4 do wd(N(tb) + i, 0) end

    local ok_t, rv_t = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(tb)))
    end)
    local rn = rv_t and N(rv_t) or -999
    print(string.format("  sz=%d cmd=0x%08X: rv=%d", sz, cmd, rn))
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)
pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)

print("")
print("=== 530a DONE ===")
