-- CRASH_CLASS: LOW
-- PROBE 510a: find the real ELF header base and parse dynamic section
--
-- 508a showed text_addr from 593 starts with "/lib/exec/ld-elf." — that's
-- the PT_INTERP string, not the ELF header. The ELF header (\x7FELF) is
-- at the start of the first PT_LOAD segment, which is mapped before .text.
--
-- Strategy:
-- 1. Use sys 674 (VM map) to find all eboot-adjacent RX regions
-- 2. Scan backwards from text_addr in 0x4000 (16KB) page steps for \x7FELF
-- 3. Once found, parse PHDR for PT_DYNAMIC
-- 4. Parse DT_STRTAB / DT_SYMTAB / Sony NID tags

print("=== PROBE 510a: find ELF base + dynamic section ===")
print("")

------------------------------------------------------------------ helpers
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_hex(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local function read_str(addr, maxlen)
    maxlen = maxlen or 64
    local s = ""
    for i = 0, maxlen - 1 do
        local b = safe_rd(addr + i)
        if not b then break end
        local c = b % 256
        if c == 0 then break end
        if c >= 32 and c < 127 then
            s = s .. string.char(c)
        else
            s = s .. string.format("\\x%02x", c)
        end
    end
    return s
end

local sc20  = make_syscall(20)
local sc593 = make_syscall(593)
local sc674 = make_syscall(674)

local pid = to_num(sc20())
print("pid: " .. pid)

-- get text_addr
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local text_addr = safe_rq(info + 0x108)
local text_size = safe_rd(info + 0x110)
local data_addr = safe_rq(info + 0x118)

print("text_addr: " .. fmt_hex(text_addr) .. " size=0x" .. string.format("%X", text_size or 0))
print("data_addr: " .. fmt_hex(data_addr))

------------------------------------------------------------------ [A] Use VM map to find eboot regions
print("")
print("[A] Scanning VM map (674) for eboot-adjacent regions...")

local vm_out = memory.alloc(0x20000)  -- 128KB for vm map data
local vm_count_buf = memory.alloc(4)
safe_wd(vm_count_buf, 0)

-- sys 674: (output_buf, count_ptr, max_count)
local ok674, ret674 = pcall(function()
    return sc674(uint64(to_num(vm_out)), uint64(to_num(vm_count_buf)), uint64(500))
end)

local vm_count = safe_rd(vm_count_buf)
print("  674 ret=" .. (ok674 and to_num(ret674) or "FAIL") .. " count=" .. (vm_count or 0))

-- record layout: +0x00 start, +0x08 end, +0x18 prot, +0x20 name (varies)
-- Actual record size = 72 bytes (from CLAUDE.md: 72-byte records)
local RECSZ = 72
local text_h, text_l = get_hi_lo(text_addr)

-- find all regions near text_addr
local eboot_regions = {}
if vm_count and vm_count > 0 then
    for i = 0, vm_count - 1 do
        local rec = vm_out + i * RECSZ
        local start_addr = safe_rq(rec)
        local end_addr = safe_rq(rec + 8)
        local prot = safe_rd(rec + 0x18)
        local name = read_str(rec + 0x20, 32)

        if start_addr and end_addr then
            local sh, sl = get_hi_lo(start_addr)
            local eh, el = get_hi_lo(end_addr)

            -- is this near eboot?
            if sh == text_h and sl >= (text_l - 0x100000) and sl <= (text_l + (text_size or 0) + 0x200000) then
                local entry = {start=start_addr, e=end_addr, prot=prot or 0, name=name}
                table.insert(eboot_regions, entry)
                print(string.format("  %s - %s prot=0x%X \"%s\"",
                    fmt_hex(start_addr), fmt_hex(end_addr), prot or 0, name))
            end
        end
    end
end

print("  eboot-adjacent regions: " .. #eboot_regions)

------------------------------------------------------------------ [B] Scan backward from text_addr for \x7FELF magic
print("")
print("[B] Scanning backward from text_addr for ELF magic...")

local elf_base = nil
local PAGE = 0x4000  -- 16KB pages on PS5

-- scan up to 1MB backward
for step = 0, 64 do
    local addr = text_addr - uint64(step * PAGE)
    local magic = safe_rd(addr)

    if magic == 0x464C457F then  -- \x7FELF
        elf_base = addr
        print(string.format("  FOUND ELF magic at text_addr - 0x%X = %s",
            step * PAGE, fmt_hex(addr)))
        break
    end

    -- also check if addr is readable at all
    if not magic and step > 0 then
        print(string.format("  unreadable at text_addr - 0x%X, stopping", step * PAGE))
        break
    end
end

-- also scan the first few pages of each eboot-adjacent RX region
if not elf_base then
    print("  not found backward, trying region starts...")
    for _, reg in ipairs(eboot_regions) do
        if reg.prot == 5 or reg.prot == 4 then  -- RX or R
            local magic = safe_rd(reg.start)
            if magic == 0x464C457F then
                elf_base = reg.start
                print("  FOUND ELF magic at region start: " .. fmt_hex(reg.start))
                break
            end
        end
    end
end

-- PS5 OELF might not use standard magic — check for SCE magic
if not elf_base then
    print("  no standard ELF magic found")
    print("  checking for SCE/OELF format...")

    -- SCE header magic: 4F 15 3D 1D (OELF) or others
    for step = 0, 16 do
        local addr = text_addr - uint64(step * PAGE)
        local magic = safe_rd(addr)
        if magic then
            -- check for known PS4/PS5 header signatures
            if magic == 0x1D3D154F then  -- OELF
                elf_base = addr
                print(string.format("  FOUND OELF magic at text_addr - 0x%X = %s",
                    step * PAGE, fmt_hex(addr)))
                break
            end
            -- print first dword at each page for reference
            if step <= 4 then
                print(string.format("  page -%d: magic=0x%08X \"%s\"",
                    step, magic, read_str(addr, 16)))
            end
        end
    end
end

------------------------------------------------------------------ [C] If found, parse ELF headers
if elf_base then
    print("")
    print("[C] Parsing ELF header at " .. fmt_hex(elf_base) .. "...")

    -- ELF64 header fields
    local e_type = safe_rd(elf_base + 0x10)
    local e_machine = safe_rd(elf_base + 0x12)
    local e_phoff = safe_rq(elf_base + 0x20)
    local e_phentsize = (safe_rd(elf_base + 0x36) or 0) % 65536
    local e_phnum = (safe_rd(elf_base + 0x38) or 0) % 65536

    print(string.format("  e_type=0x%X e_machine=0x%X", (e_type or 0) % 65536, (e_machine or 0) % 65536))
    print(string.format("  e_phoff=%s e_phentsize=%d e_phnum=%d",
        fmt_hex(e_phoff), e_phentsize, e_phnum))

    if e_phentsize == 0 then e_phentsize = 0x38 end

    -- scan program headers
    local dyn_vaddr = nil
    local dyn_filesz = 0

    if e_phnum > 0 and e_phnum < 30 then
        print("  Program headers:")
        for i = 0, e_phnum - 1 do
            local ph = elf_base + e_phoff + uint64(i * e_phentsize)
            local p_type = safe_rd(ph)
            local p_flags = safe_rd(ph + 4)
            local p_vaddr = safe_rq(ph + 0x10)
            local p_filesz = safe_rq(ph + 0x20)

            local tname = ""
            if p_type == 0 then tname = "NULL"
            elseif p_type == 1 then tname = "LOAD"
            elseif p_type == 2 then tname = "DYNAMIC"
            elseif p_type == 3 then tname = "INTERP"
            elseif p_type == 4 then tname = "NOTE"
            elseif p_type == 6 then tname = "PHDR"
            elseif p_type == 7 then tname = "TLS"
            elseif p_type then
                if p_type >= 0x60000000 then tname = string.format("OS/0x%X", p_type)
                else tname = string.format("?0x%X", p_type) end
            end

            if p_type and p_type ~= 0 then
                print(string.format("    [%d] type=%s flags=0x%X vaddr=%s filesz=%s",
                    i, tname, p_flags or 0, fmt_hex(p_vaddr), fmt_hex(p_filesz)))
            end

            if p_type == 2 then
                dyn_vaddr = p_vaddr
                dyn_filesz = to_num(p_filesz)
                print("        *** PT_DYNAMIC ***")
            end
        end
    end

    -- [D] Parse dynamic section
    if dyn_vaddr then
        print("")
        print("[D] Dynamic section at vaddr " .. fmt_hex(dyn_vaddr) .. "...")

        -- try absolute and base-relative
        local dyn = dyn_vaddr
        local test = safe_rd(dyn)
        if not test then
            dyn = elf_base + dyn_vaddr
            test = safe_rd(dyn)
        end

        if test then
            print("  readable at " .. fmt_hex(dyn))

            local dt_strtab = nil
            local dt_strsz = 0
            local dt_symtab = nil
            local dt_syment = 0
            local sony_nid = nil

            local max_ent = math.min(math.floor(dyn_filesz / 16), 300)
            for i = 0, max_ent - 1 do
                local tag = safe_rq(dyn + i * 16)
                local val = safe_rq(dyn + i * 16 + 8)
                local t = to_num(tag)

                if t == 0 then break end

                local tname = ""
                if t == 5 then tname = "DT_STRTAB"; dt_strtab = val
                elseif t == 6 then tname = "DT_SYMTAB"; dt_symtab = val
                elseif t == 10 then tname = "DT_STRSZ"; dt_strsz = to_num(val)
                elseif t == 11 then tname = "DT_SYMENT"; dt_syment = to_num(val)
                elseif t == 4 then tname = "DT_HASH"
                elseif t == 3 then tname = "DT_PLTGOT"
                elseif t == 23 then tname = "DT_JMPREL"
                elseif t >= 0x61000000 and t <= 0x6FFFFFFF then
                    tname = string.format("SCE/0x%X", t)
                    -- known Sony tags:
                    -- 0x61000035 = SCE_FINGERPRINT
                    -- 0x61000037 = SCE_ORIGINAL_FILENAME
                    -- 0x61000039 = SCE_MODULE_INFO
                    -- 0x6100003B = SCE_MODULE_ATTR
                    -- 0x6100003D = SCE_EXPORT_LIB
                    -- 0x6100003F = SCE_IMPORT_LIB
                    -- 0x61000041 = SCE_EXPORT_LIB_ATTR
                    -- 0x61000043 = SCE_IMPORT_LIB_ATTR
                    -- 0x61000047 = SCE_HASH_SIZE
                    -- 0x61000049 = SCE_SYMTAB
                    -- 0x6100004B = SCE_SYMTABSZ
                    -- 0x6100004D = SCE_STRTAB
                    -- 0x6100004F = SCE_STRTABSZ
                    if t == 0x61000049 then tname = "SCE_SYMTAB"
                    elseif t == 0x6100004D then tname = "SCE_STRTAB"; dt_strtab = val
                    elseif t == 0x6100004F then tname = "SCE_STRTABSZ"; dt_strsz = to_num(val)
                    elseif t == 0x6100004B then tname = "SCE_SYMTABSZ"
                    elseif t == 0x61000039 then tname = "SCE_MODULE_INFO"
                    elseif t == 0x6100003D then tname = "SCE_EXPORT_LIB"
                    elseif t == 0x6100003F then tname = "SCE_IMPORT_LIB"
                    end
                end

                if tname ~= "" then
                    print(string.format("    [%d] %s = %s", i, tname, fmt_hex(val)))
                end
            end

            -- [E] Read SCE strtab
            if dt_strtab then
                print("")
                print("[E] Reading strtab at " .. fmt_hex(dt_strtab) .. " (size=" .. dt_strsz .. ")...")

                local strtab = dt_strtab
                local test1 = safe_rd(strtab)
                if not test1 then
                    strtab = elf_base + dt_strtab
                    test1 = safe_rd(strtab)
                end

                if test1 then
                    print("  readable at " .. fmt_hex(strtab))
                    local pos = 0
                    local count = 0
                    local max_read = math.min(dt_strsz, 8192)
                    if max_read == 0 then max_read = 4096 end

                    while pos < max_read and count < 50 do
                        local s = read_str(strtab + pos, 128)
                        if #s > 0 then
                            print(string.format("    [%d] +0x%X: \"%s\"", count, pos, s))
                            count = count + 1
                            -- advance past the string + NUL
                            local real_len = 0
                            for ci = 0, 127 do
                                local b = safe_rd(strtab + pos + ci)
                                if not b or b % 256 == 0 then
                                    real_len = ci + 1
                                    break
                                end
                                real_len = ci + 1
                            end
                            pos = pos + real_len
                        else
                            pos = pos + 1
                        end
                    end
                else
                    print("  UNREADABLE")
                end
            end
        else
            print("  UNREADABLE at both absolute and relative")
        end
    end
else
    print("")
    print("[C] No ELF/OELF header found")
    print("  PS5 eboot may use a different mapping strategy")
    print("  or headers are in a non-readable segment")
end

------------------------------------------------------------------ [F] Alternative: scan sys 649 member outputs
print("")
print("[F] sys 649 module member addresses (may contain export table)...")

local sc649 = make_syscall(649)
local out649 = memory.alloc(0x100)

-- member types 1-8 on handle 0 (eboot)
for mtype = 1, 8 do
    for j = 0, 0xFC, 4 do safe_wd(out649 + j, 0) end
    local ok, ret = pcall(function()
        return sc649(uint64(0), uint64(mtype), uint64(to_num(out649)))
    end)
    if ok and to_num(ret) == 0 then
        local v0 = safe_rq(out649)
        local v1 = safe_rq(out649 + 8)
        local v2 = safe_rq(out649 + 16)
        print(string.format("  handle=0 member=%d: %s %s %s",
            mtype, fmt_hex(v0), fmt_hex(v1), fmt_hex(v2)))
    end
end

-- also check the +0x128 field from 593 (0x459BC000) — might be .rodata or init
local extra_addr = safe_rq(info + 0x128)
if extra_addr then
    print("")
    print("[G] Field +0x128 from 593: " .. fmt_hex(extra_addr))
    local magic = safe_rd(extra_addr)
    if magic then
        print(string.format("  first dword: 0x%08X \"%s\"", magic, read_str(extra_addr, 16)))
        -- check if this is the ELF header
        if magic == 0x464C457F then
            print("  *** THIS IS THE ELF HEADER! ***")
        end
    else
        print("  UNREADABLE (might be XO or unmapped)")
    end
end

print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))
print("")
print("=== PROBE 510a COMPLETE ===")
