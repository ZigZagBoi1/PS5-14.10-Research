-- CRASH_CLASS: LOW
-- PROBE 528x: Hunt for SDMA ring buffers and GPU doorbells
--
-- 528w: GFX command buffer at dmem0 offset 0 has zero DMA opcodes.
-- The GPU has separate SDMA (System DMA) engines with their own ring buffers.
-- SDMA opcodes are different from GFX PM4:
--   SDMA_OP_COPY = 1, SDMA_OP_FENCE = 5, SDMA_OP_POLL_REGMEM = 8
--   SDMA header: [31:28]=op, [27:26]=sub_op, [25:0]=varies
--
-- Strategy:
-- 1. Scan dmem0 for SDMA-shaped headers (not PM4 C0xxxxxx)
-- 2. Look for repeated SDMA_OP patterns
-- 3. Find GPU MMIO doorbells via /dev/gc at page-aligned offsets
-- 4. Check if we can locate the GPU's SDMA submission registers

print("=== PROBE 528x: SDMA RING HUNT ===")
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
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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
local PAGE = 0x4000

local function open_dev(name)
    local devpath = memory.alloc(0x30)
    for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
    wd(N(devpath) + #name, 0)
    return N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))
end

local function try_mmap(fd_n, offset, prot, flags)
    local phi = math.floor(offset / 0x100000000)
    local plo = offset % 0x100000000
    local off_u = uint64(string.format("0x%X%08X", phi, plo))
    local ok_m, rv = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(prot), uint64(flags), uint64(fd_n), off_u)
    end)
    if not ok_m or not rv then return nil end
    local rh = get_hi_lo(rv)
    if rh < 0 then rh = rh + 0x100000000 end
    if rh == 0xFFFFFFFF then return nil end
    return rv
end

local dm_fd = open_dev("/dev/dmem0")
print("dmem0 fd=" .. dm_fd)

-- ============================================================
-- [A] Sample 256 pages spread across first 1 GB for SDMA patterns
-- ============================================================
print("")
print("[A] SDMA signature scan (256 sample pages across 1 GB)")

-- SDMA opcodes have bits[31:28] as opcode, not 0xC0 prefix
-- SDMA_OP_NOP=0, COPY=1, WRITE=2, FENCE=5, TRAP=6, POLL=8, COND=9, CONST_FILL=11, TIMESTAMP=13
-- These look like 0x1xxxxxxx, 0x2xxxxxxx, 0x5xxxxxxx etc.
-- Unlike PM4 (0xC0xxxxxx), SDMA headers don't start with C0.

local sdma_candidates = {}
local pm4_pages = 0
local zero_pages = 0
local other_pages = 0

for i = 0, 255 do
    local offset = i * 4 * 1024 * 1024  -- every 4 MiB
    local rv = try_mmap(dm_fd, offset, 1, 1)
    if rv then
        local va = N(rv)
        local d0 = rd(va) or 0
        if d0 < 0 then d0 = d0 + 0x100000000 end
        local d1 = rd(va + 4) or 0
        if d1 < 0 then d1 = d1 + 0x100000000 end
        local d2 = rd(va + 8) or 0
        if d2 < 0 then d2 = d2 + 0x100000000 end
        local d3 = rd(va + 12) or 0
        if d3 < 0 then d3 = d3 + 0x100000000 end

        if d0 == 0 and d1 == 0 and d2 == 0 and d3 == 0 then
            zero_pages = zero_pages + 1
        else
            -- Check if PM4 (GFX)
            local is_pm4 = false
            local is_sdma = false
            local top = math.floor(d0 / 0x40000000) % 4
            if top == 3 then is_pm4 = true end

            -- Check for SDMA-like pattern: op in bits[31:28]
            local sdma_op = math.floor(d0 / 0x10000000)
            if sdma_op >= 1 and sdma_op <= 13 and not is_pm4 then
                is_sdma = true
                table.insert(sdma_candidates, {offset, d0, d1, d2, d3})
            end

            if is_pm4 then pm4_pages = pm4_pages + 1
            elseif not is_sdma then other_pages = other_pages + 1
            end

            -- Print non-zero non-PM4 pages
            if not is_pm4 and (d0 ~= 0 or d1 ~= 0) then
                if #sdma_candidates <= 30 or is_sdma then
                    print(string.format("  off=0x%08X: %08X %08X %08X %08X%s",
                        offset, d0, d1, d2, d3, is_sdma and " <SDMA?>" or ""))
                end
            end
        end
        pcall(function() sc_73(rv, uint64(PAGE)) end)
    end
end

print(string.format("  PM4=%d zero=%d SDMA?=%d other=%d",
    pm4_pages, zero_pages, #sdma_candidates, other_pages))

-- ============================================================
-- [B] Check the GPU mmap (sys 477 with fd=-1) for MMIO-like regions
-- This is how games typically access GPU doorbells
-- ============================================================
print("")
print("[B] GPU mmap via fd=-1 (anonymous, may hit MMIO)")

-- On AMD GPUs, doorbell pages are typically mmap'd with specific offsets
-- Try mmap with fd=-1 (MAP_ANON) and MAP_SHARED
-- The game process gets its doorbell page mapped by the kernel driver
local test_offsets = {0, 0x1000, 0x2000, 0x4000, 0x8000, 0x10000}
for _, off in ipairs(test_offsets) do
    -- MAP_ANON(0x1000) | MAP_SHARED(1)
    local ok_m, rv = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(3), uint64(0x1001), uint64(0xFFFFFFFF), uint64(off))
    end)
    if ok_m and rv then
        local rh = get_hi_lo(rv)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then
            local d = rd(N(rv)) or 0
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  anon off=0x%X: VA=%s d0=0x%08X", off, fmt(rv), d))
            pcall(function() sc_73(rv, uint64(PAGE)) end)
        end
    end
end

-- ============================================================
-- [C] VM map scan for GPU MMIO/doorbell regions
-- sys 674 returns all mapped regions — look for GPU-related ones
-- ============================================================
print("")
print("[C] VM map — look for GPU/doorbell/MMIO regions")

local sc_674 = mk(674)
local vmbuf = memory.alloc(0x10000)
local vmlenbuf = memory.alloc(8)
wq(N(vmlenbuf), uint64(0x10000))

local ok_vm, rv_vm = pcall(function()
    return sc_674(uint64(vmbuf), uint64(N(vmlenbuf)))
end)

if ok_vm then
    local vmrv = N(rv_vm)
    local used = rd(N(vmlenbuf)) or 0
    if used < 0 then used = used + 0x100000000 end
    print(string.format("  vm map rv=%d used=%d bytes", vmrv, used))

    -- The VM map format on PS5 is an array of entries
    -- Each entry: start(8) + end(8) + prot(4) + maxprot(4) + name(32) = 56 bytes
    -- But we don't know exact layout. Let's scan for distinctive patterns.
    -- GPU MMIO typically has names like "gpu", "gc", "doorbell", or special protections.
    -- Let's dump all regions and look for interesting names.

    -- Actually, let's just read qword pairs and look for small (MMIO-like) ranges
    -- MMIO BARs on AMD: typically at physical 0xFBxx_xxxx or similar
    -- In VA space they'd be mapped somewhere unusual

    -- Scan for entries with non-standard protections or small sizes
    local entries = {}
    local entry_size = 56  -- guess based on FreeBSD vm_map_entry
    if used > 0 then
        -- Try reading as: [start:8][end:8][prot:4][flags:4][name:32]
        for off = 0, math.min(used - entry_size, 0xF000), entry_size do
            local start_q = rq(N(vmbuf) + off)
            local end_q = rq(N(vmbuf) + off + 8)
            if start_q and end_q then
                local sh, sl = get_hi_lo(start_q)
                local eh, el = get_hi_lo(end_q)
                if sh < 0 then sh = sh + 0x100000000 end
                if sl < 0 then sl = sl + 0x100000000 end
                if eh < 0 then eh = eh + 0x100000000 end
                if el < 0 then el = el + 0x100000000 end

                -- Look for small (< 1 MB) non-zero regions
                if sh == eh and sl > 0 and el > sl then
                    local size = el - sl
                    if size > 0 and size < 0x100000 then
                        -- Read name bytes
                        local name = ""
                        for i = 0, 31 do
                            local b = rd(N(vmbuf) + off + 16 + i)
                            if b then
                                local c = b % 256
                                if c >= 32 and c < 127 then name = name .. string.char(c)
                                elseif c == 0 then break end
                            end
                        end
                        local prot = rd(N(vmbuf) + off + 16)
                        if prot then
                            if prot < 0 then prot = prot + 0x100000000 end
                        end
                        table.insert(entries, {sh, sl, size, name, prot or 0})
                        if #entries <= 20 then
                            print(string.format("  0x%X%08X sz=0x%X prot=0x%X name=%s",
                                sh, sl, size, prot or 0, name ~= "" and name or "(none)"))
                        end
                    end
                end
            end
        end
        print(string.format("  small regions found: %d", #entries))
    end
end

-- ============================================================
-- [D] Ioctl on /dev/gc — what commands does it accept?
-- GPU drivers expose submit/map/unmap via ioctl
-- ============================================================
print("")
print("[D] /dev/gc ioctl probe")

local gc_fd = open_dev("/dev/gc")
print("  gc fd=" .. gc_fd)

if gc_fd >= 0 and gc_fd < 200 then
    local sc_ioctl = mk(54)  -- ioctl
    local ioctl_buf = memory.alloc(0x200)

    -- Common AMD/Sony ioctl numbers for GPU
    -- On PS5, GNM uses ioctl to submit command buffers
    -- Try a few known command ranges
    local ioctls_to_try = {
        -- Sony GNM submit ioctl candidates (range from PS4 research)
        0xC0109200, 0xC0109201, 0xC0109202, 0xC0109203,
        0xC0109204, 0xC0109205, 0xC0109206, 0xC0109207,
        0xC0109208, 0xC0109209, 0xC010920A, 0xC010920B,
        -- Common ioctl for GPU submit
        0xC0089200, 0xC0089201,
        -- AMD DRM ioctls (if exposed)
        0xC0206440, 0xC0186441, 0xC0106442,
        -- Direct commands
        0x40089200, 0x80089200,
    }

    for _, cmd in ipairs(ioctls_to_try) do
        -- Zero the buffer
        for i = 0, 31, 4 do wd(N(ioctl_buf) + i, 0) end

        local ok_i, rv_i = pcall(function()
            return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(ioctl_buf))
        end)
        if ok_i then
            local ret = N(rv_i)
            if ret ~= -1 then
                print(string.format("  ioctl 0x%08X: rv=%d *** ACCEPTED ***", cmd, ret))
                -- Dump first 32 bytes of output
                for i = 0, 7 do
                    local d = rd(N(ioctl_buf) + i * 4)
                    if d then
                        if d < 0 then d = d + 0x100000000 end
                        if d ~= 0 then
                            print(string.format("    [+%d] 0x%08X", i*4, d))
                        end
                    end
                end
            end
        end
    end

    pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)
end

-- ============================================================
-- [E] Check /dev/dce (Display Controller Engine) mmap
-- DCE controls the display pipeline, also has DMA
-- ============================================================
print("")
print("[E] /dev/dce mmap + ioctl")

local dce_fd = open_dev("/dev/dce")
print("  dce fd=" .. dce_fd)

if dce_fd >= 0 and dce_fd < 200 then
    -- Try mmap at various offsets
    for _, off in ipairs({0, 0x4000, 0x8000, 0x10000, 0x100000}) do
        local rv = try_mmap(dce_fd, off, 1, 1)
        if rv then
            local d = rd(N(rv)) or 0
            if d < 0 then d = d + 0x100000000 end
            print(string.format("  mmap off=0x%X: VA=%s d0=0x%08X", off, fmt(rv), d))
            pcall(function() sc_73(rv, uint64(PAGE)) end)
        end
    end

    -- Try ioctls
    local sc_ioctl = mk(54)
    local ioctl_buf = memory.alloc(0x100)
    local dce_cmds = {0xC0109300, 0xC0109301, 0xC0089300, 0x40089300, 0x80089300}
    for _, cmd in ipairs(dce_cmds) do
        for i = 0, 15, 4 do wd(N(ioctl_buf) + i, 0) end
        local ok_i, rv_i = pcall(function()
            return sc_ioctl(uint64(dce_fd), uint64(cmd), uint64(ioctl_buf))
        end)
        if ok_i and N(rv_i) ~= -1 then
            print(string.format("  ioctl 0x%08X: rv=%d *** ACCEPTED ***", cmd, N(rv_i)))
        end
    end

    pcall(function() native.fcall_with_rax(stub, 6, uint64(dce_fd)) end)
end

pcall(function() native.fcall_with_rax(stub, 6, uint64(dm_fd)) end)

print("")
print("=== 528x DONE ===")
