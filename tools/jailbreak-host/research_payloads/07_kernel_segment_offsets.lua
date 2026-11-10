-- CRASH_CLASS: LOW
-- PROBE: 13.60 Kernel ELF Segment Offset Extraction
--
-- On a jailbroken 13.60 with kernel R/W (etaHEN), reads the kernel
-- ELF headers to extract the text-to-data segment offset.
--
-- WHY THIS MATTERS:
-- The 14.10 fault oracle gives us the kernel IMAGE BASE (start of .text).
-- The debug settings offsets (security_flags, target_id, qa_flags) are
-- relative to DATA_BASE. The gap between IMAGE_BASE and DATA_BASE is a
-- link-time constant: measuring it on 13.60 gives us the 14.10 value
-- (or close to it -- same kernel source, same linker).
--
-- WHAT WE READ:
-- 1. ELF header at kernel base: e_phoff, e_phentsize, e_phnum
-- 2. Each program header: p_type, p_offset, p_vaddr, p_memsz, p_flags
-- 3. Identify PT_LOAD segments: .text (PF_R|PF_X), .data (PF_R|PF_W)
-- 4. Compute: DATA_OFFSET = data_vaddr - text_vaddr
--
-- The ps5-payload-dev/sdk 13.60 offsets give us ground truth to validate:
--   security_flags = DATA_BASE + 0x0DA4064 (if the offset table is right)
--   We can read security_flags from kernel memory and verify.
--
-- prior art: 01_kernel_dump.lua, docs/DEBUG_SETTINGS_CHAIN_14_10.md

print("=== PAYLOAD 07: KERNEL SEGMENT OFFSETS ===")
print("FIRMWARE: 13.60 (jailbroken)")
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Helper: read a uint16 at addr
local function read_u16(addr)
    local v = safe_rd(addr)
    if v then return v % 0x10000 end
    return nil
end

-- Helper: read a uint64 at addr, return as hi,lo pair
local function read_u64(addr)
    local q = safe_rq(addr)
    if q then return get_hi_lo(q) end
    return nil, nil
end

local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("PID: " .. pid)

-- Step 1: Find kernel base using fault oracle (same as 14.10 method)
-- On 13.60 jailbroken, direct reads should work, but we still need
-- to find the base address (KASLR applies).
--
-- Known 13.60 offset for allproc from ps5-payload-dev/sdk:
-- allproc = DATA_BASE + 0x27EDCB8 (13.60 value)
-- We can verify by reading it and comparing to sysctl proc list.

print("")
print("=== STEP 1: FIND KERNEL BASE ===")

-- Try direct kernel reads at common base addresses
-- 13.60 kernel is typically around 0xFFFFFFFF8xxxxxxx
-- Scan in 2MB steps from 0xFFFFFFFF80000000

local SCAN_START_HI = 0xFFFFFFFF
local SCAN_START_LO = 0x80000000
local SCAN_STEP = 0x200000  -- 2 MB
local SCAN_COUNT = 256       -- 512 MB range

local kernel_base_hi = nil
local kernel_base_lo = nil

for i = 0, SCAN_COUNT - 1 do
    local lo = SCAN_START_LO + i * SCAN_STEP
    local hi = SCAN_START_HI
    -- Handle overflow
    if lo >= 0x100000000 then
        lo = lo - 0x100000000
        hi = hi + 1
        if hi >= 0x100000000 then hi = 0 end
    end

    local addr = uint64(string.format("0x%X%08X", hi, lo))
    local val = safe_rd(addr)
    if val then
        -- Check for ELF magic: 0x464C457F ("\x7FELF" in LE)
        if val == 0x464C457F then
            kernel_base_hi = hi
            kernel_base_lo = lo
            print(string.format("ELF MAGIC at 0x%X%08X", hi, lo))
            break
        end
        -- Also check for recognizable kernel bytes
        if i < 4 or i % 32 == 0 then
            print(string.format("  scan[%d] 0x%X%08X = 0x%08X", i, hi, lo, val))
        end
    end
end

if not kernel_base_hi then
    print("KERNEL BASE: NOT FOUND by ELF scan")
    print("Trying known 13.60 offsets from SDK...")

    -- ps5-payload-dev/sdk lists 13.60 as having these offsets:
    -- We try a few known base candidates
    local candidates = {
        {0xFFFFFFFF, 0x82200000},
        {0xFFFFFFFF, 0x84200000},
        {0xFFFFFFFF, 0x86200000},
        {0xFFFFFFFF, 0x88200000},
    }
    for _, c in ipairs(candidates) do
        local addr = uint64(string.format("0x%X%08X", c[1], c[2]))
        local val = safe_rd(addr)
        if val and val == 0x464C457F then
            kernel_base_hi = c[1]
            kernel_base_lo = c[2]
            print(string.format("ELF MAGIC at candidate 0x%X%08X", c[1], c[2]))
            break
        end
    end
end

if not kernel_base_hi then
    print("FATAL: Cannot find kernel base. etaHEN kernel R/W may not be active.")
    print("=== PAYLOAD 07 ABORTED ===")
    return
end

print(string.format("KERNEL_BASE = 0x%X%08X", kernel_base_hi, kernel_base_lo))

-- Step 2: Read ELF header
print("")
print("=== STEP 2: ELF HEADER ===")

local base_str = string.format("0x%X%08X", kernel_base_hi, kernel_base_lo)
local base = uint64(base_str)

-- ELF64 header layout:
-- +0x00: e_ident (16 bytes, magic + class + endian)
-- +0x10: e_type (2), e_machine (2)
-- +0x14: e_version (4)
-- +0x18: e_entry (8)
-- +0x20: e_phoff (8)   -- program header table offset
-- +0x28: e_shoff (8)   -- section header table offset
-- +0x30: e_flags (4)
-- +0x34: e_ehsize (2)
-- +0x36: e_phentsize (2)
-- +0x38: e_phnum (2)
-- +0x3A: e_shentsize (2)
-- +0x3C: e_shnum (2)
-- +0x3E: e_shstrndx (2)

local e_ident_0 = safe_rd(base)
local e_ident_4 = safe_rd(base + 4)
print(string.format("e_ident[0:3] = 0x%08X (expect 0x464C457F)", e_ident_0 or 0))
print(string.format("e_ident[4:7] = 0x%08X (class=%d, data=%d)",
    e_ident_4 or 0,
    (e_ident_4 or 0) % 256,          -- EI_CLASS: 2 = 64-bit
    math.floor((e_ident_4 or 0) / 256) % 256))  -- EI_DATA: 1 = LE

local e_type = read_u16(base + 0x10)
local e_machine = read_u16(base + 0x12)
print(string.format("e_type = %d (expect 2=ET_EXEC or 0xFE00=OS-specific)", e_type or 0))
print(string.format("e_machine = %d (expect 62=EM_X86_64)", e_machine or 0))

local e_entry_hi, e_entry_lo = read_u64(base + 0x18)
if e_entry_hi then
    print(string.format("e_entry = 0x%X%08X", e_entry_hi, e_entry_lo))
end

local e_phoff_hi, e_phoff_lo = read_u64(base + 0x20)
if e_phoff_hi then
    print(string.format("e_phoff = 0x%X%08X", e_phoff_hi, e_phoff_lo))
end

local e_shoff_hi, e_shoff_lo = read_u64(base + 0x28)
if e_shoff_hi then
    print(string.format("e_shoff = 0x%X%08X", e_shoff_hi, e_shoff_lo))
end

local e_phentsize = read_u16(base + 0x36)
local e_phnum = read_u16(base + 0x38)
print(string.format("e_phentsize = %d (expect 56)", e_phentsize or 0))
print(string.format("e_phnum = %d", e_phnum or 0))

-- Step 3: Read program headers
print("")
print("=== STEP 3: PROGRAM HEADERS ===")

if not e_phoff_lo or not e_phentsize or not e_phnum then
    print("FATAL: Cannot read ELF header fields")
    print("=== PAYLOAD 07 ABORTED ===")
    return
end

-- Program header table is at kernel_base + e_phoff
-- Each entry is e_phentsize bytes (typically 56 for ELF64)
--
-- ELF64 Phdr layout (56 bytes):
-- +0x00: p_type (4)     -- 1=PT_LOAD, 6=PT_PHDR, etc
-- +0x04: p_flags (4)    -- PF_X=1, PF_W=2, PF_R=4
-- +0x08: p_offset (8)   -- offset in file
-- +0x10: p_vaddr (8)    -- virtual address
-- +0x18: p_paddr (8)    -- physical address
-- +0x20: p_filesz (8)   -- size in file
-- +0x28: p_memsz (8)    -- size in memory
-- +0x30: p_align (8)    -- alignment

local PT_LOAD = 1
local PF_X = 1
local PF_W = 2
local PF_R = 4

local text_vaddr_hi, text_vaddr_lo = nil, nil
local text_offset_hi, text_offset_lo = nil, nil
local text_memsz_hi, text_memsz_lo = nil, nil
local data_vaddr_hi, data_vaddr_lo = nil, nil
local data_offset_hi, data_offset_lo = nil, nil
local data_memsz_hi, data_memsz_lo = nil, nil

local phdr_base_lo = kernel_base_lo + e_phoff_lo
local phdr_base_hi = kernel_base_hi + e_phoff_hi
if phdr_base_lo >= 0x100000000 then
    phdr_base_lo = phdr_base_lo - 0x100000000
    phdr_base_hi = phdr_base_hi + 1
end

for i = 0, math.min(e_phnum - 1, 31) do  -- cap at 32 to avoid runaway
    local ph_addr = uint64(string.format("0x%X%08X",
        phdr_base_hi, phdr_base_lo + i * e_phentsize))

    local p_type = safe_rd(ph_addr)
    local p_flags = safe_rd(ph_addr + 4)

    if p_type then
        local p_offset_hi, p_offset_lo = read_u64(ph_addr + 0x08)
        local p_vaddr_hi, p_vaddr_lo = read_u64(ph_addr + 0x10)
        local p_memsz_hi, p_memsz_lo = read_u64(ph_addr + 0x28)

        local flags_str = ""
        if p_flags then
            if p_flags % 2 >= 1 then flags_str = flags_str .. "X" end
            if math.floor(p_flags / 2) % 2 >= 1 then flags_str = flags_str .. "W" end
            if math.floor(p_flags / 4) % 2 >= 1 then flags_str = flags_str .. "R" end
        end

        print(string.format("PHDR[%d]: type=%d flags=0x%X(%s)", i, p_type or 0, p_flags or 0, flags_str))
        if p_vaddr_hi then
            print(string.format("  vaddr=0x%X%08X offset=0x%X%08X memsz=0x%X%08X",
                p_vaddr_hi, p_vaddr_lo,
                p_offset_hi or 0, p_offset_lo or 0,
                p_memsz_hi or 0, p_memsz_lo or 0))
        end

        -- Identify text segment (PT_LOAD + RX, no W)
        if p_type == PT_LOAD and p_flags and
           math.floor(p_flags / 4) % 2 >= 1 and  -- R
           p_flags % 2 >= 1 and                   -- X
           math.floor(p_flags / 2) % 2 == 0 then  -- not W
            text_vaddr_hi = p_vaddr_hi
            text_vaddr_lo = p_vaddr_lo
            text_offset_hi = p_offset_hi
            text_offset_lo = p_offset_lo
            text_memsz_hi = p_memsz_hi
            text_memsz_lo = p_memsz_lo
            print("  *** TEXT SEGMENT ***")
        end

        -- Identify data segment (PT_LOAD + RW, no X)
        if p_type == PT_LOAD and p_flags and
           math.floor(p_flags / 4) % 2 >= 1 and  -- R
           math.floor(p_flags / 2) % 2 >= 1 and  -- W
           p_flags % 2 == 0 then                  -- not X
            data_vaddr_hi = p_vaddr_hi
            data_vaddr_lo = p_vaddr_lo
            data_offset_hi = p_offset_hi
            data_offset_lo = p_offset_lo
            data_memsz_hi = p_memsz_hi
            data_memsz_lo = p_memsz_lo
            print("  *** DATA SEGMENT ***")
        end
    end
end

-- Step 4: Compute the gap
print("")
print("=== STEP 4: SEGMENT GAP ===")

if text_vaddr_hi and data_vaddr_hi then
    -- DATA_OFFSET = data_vaddr - text_vaddr
    local gap_lo = data_vaddr_lo - text_vaddr_lo
    local gap_hi = data_vaddr_hi - text_vaddr_hi
    if gap_lo < 0 then
        gap_lo = gap_lo + 0x100000000
        gap_hi = gap_hi - 1
    end

    print(string.format("TEXT_VADDR  = 0x%X%08X (size 0x%X%08X)",
        text_vaddr_hi, text_vaddr_lo, text_memsz_hi, text_memsz_lo))
    print(string.format("DATA_VADDR  = 0x%X%08X (size 0x%X%08X)",
        data_vaddr_hi, data_vaddr_lo, data_memsz_hi, data_memsz_lo))
    print(string.format("DATA_OFFSET = 0x%X%08X (data_vaddr - text_vaddr)", gap_hi, gap_lo))
    print("")
    print("On 14.10: DATA_BASE = IMAGE_BASE + DATA_OFFSET")
    print("  where IMAGE_BASE comes from the fault oracle")
    print("  and DATA_OFFSET is the value above (or close to it)")

    -- Step 5: Validate against known 13.60 offsets
    print("")
    print("=== STEP 5: VALIDATION ===")

    -- On 13.60, security_flags should be at data_vaddr + 0x0DA4064
    -- (using the 14.10 offset as approximation; 13.60 may differ)
    -- ps5-payload-dev/sdk 13.60 has its own offset table; we use it
    -- to validate that we found the right segments.

    -- Read security_flags region
    local sf_lo = data_vaddr_lo + 0x0DA4064
    local sf_hi = data_vaddr_hi
    if sf_lo >= 0x100000000 then
        sf_lo = sf_lo - 0x100000000
        sf_hi = sf_hi + 1
    end

    local sf_addr = uint64(string.format("0x%X%08X", sf_hi, sf_lo))
    local sf_val = safe_rd(sf_addr)
    print(string.format("security_flags_region (14.10 offset) = 0x%08X", sf_val or 0))

    -- Read target_id at +0x09 from security_flags
    local tid_lo = sf_lo + 0x09
    local tid_hi = sf_hi
    -- target_id is a single byte at this offset; read as dword and mask
    local tid_addr = uint64(string.format("0x%X%08X", tid_hi, tid_lo))
    -- Actually, we should read the byte at security_flags + 0x09
    -- safe_rd returns a dword, so read from security_flags and shift
    local sf_plus8 = safe_rd(uint64(string.format("0x%X%08X", sf_hi, sf_lo + 8)))
    if sf_plus8 then
        local target_id_byte = sf_plus8 % 256  -- byte at +0x08 from sf_base
        -- Actually +0x09 from sf_base means byte 1 of the dword at +0x08
        target_id_byte = math.floor(sf_plus8 / 256) % 256
        print(string.format("target_id (14.10 offset) = 0x%02X", target_id_byte))
        print("  0x81=Retail, 0x82=TestKit, 0x83=DevKit")
        print("  If 0x81 or 0x83, these are 13.60 offsets (retail PS5)")
    end

    -- Read qa_flags at security_flags + 0x24
    local qa_lo = sf_lo + 0x24
    local qa_hi = sf_hi
    local qa_addr = uint64(string.format("0x%X%08X", qa_hi, qa_lo))
    local qa_val = safe_rd(qa_addr)
    print(string.format("qa_flags (14.10 offset) = 0x%08X", qa_val or 0))
    print("  bit 0 = debug menu enable")

    -- Try 13.60-specific offsets if the above looked wrong
    -- ps5-payload-dev/sdk 13.60: security_flags offset may differ
    -- We can also try reading allproc
    local ap_offset = 0x27EDCB8  -- 13.60 allproc offset (from sdk)
    local ap_lo = data_vaddr_lo + ap_offset
    local ap_hi = data_vaddr_hi
    if ap_lo >= 0x100000000 then
        ap_lo = ap_lo - 0x100000000
        ap_hi = ap_hi + 1
    end
    local ap_addr = uint64(string.format("0x%X%08X", ap_hi, ap_lo))
    local ap_val = safe_rq(ap_addr)
    if ap_val then
        local aph, apl = get_hi_lo(ap_val)
        print(string.format("allproc (13.60 offset) = 0x%X%08X", aph, apl))
        if aph >= 0xFFFF8000 then
            print("  LOOKS LIKE KERNEL POINTER -- allproc offset validated")
        else
            print("  NOT a kernel pointer -- 13.60 offset may be wrong for this build")
        end
    end
else
    print("INCOMPLETE: could not identify both text and data segments")
    if text_vaddr_hi then
        print(string.format("  TEXT found: 0x%X%08X", text_vaddr_hi, text_vaddr_lo))
    end
    if data_vaddr_hi then
        print(string.format("  DATA found: 0x%X%08X", data_vaddr_hi, data_vaddr_lo))
    end
end

-- Step 6: Dump all program headers as hex for offline analysis
print("")
print("=== STEP 6: RAW PHDR DUMP ===")
for i = 0, math.min(e_phnum - 1, 31) do
    local row = string.format("PHDR_RAW[%d]: ", i)
    for j = 0, e_phentsize - 1, 4 do
        local ph_off = phdr_base_lo + i * e_phentsize + j
        local v = safe_rd(uint64(string.format("0x%X%08X", phdr_base_hi, ph_off)))
        if v then
            row = row .. string.format("%08X ", v)
        else
            row = row .. "???????? "
        end
    end
    print(row)
end

print("")
print("=== PAYLOAD 07 COMPLETE ===")
