-- CRASH_CLASS: LOW
-- PROBE 508a: scan module export tables in memory to find NID format
--
-- Since 591 (dlsym) rejects every name format we tried, and we can't
-- compute SHA1 in Lua, we take a different approach: read the module's
-- in-memory export/symbol table directly.
--
-- The dynlib_get_info(593) struct has fields beyond the documented ones.
-- The ELF program headers in the module's memory should contain the
-- dynamic section, which has DT_SYMTAB, DT_STRTAB, DT_HASH/DT_GNU_HASH
-- pointers. For PS4/PS5 modules (PRX), the symbol table contains NID
-- strings that the runtime linker resolved. If we can read those, we
-- know the exact encoding 591 expects.
--
-- Strategy:
-- 1. Read deep dynlib_get_info(593) struct for undocumented pointers
-- 2. Parse eboot's ELF dynamic section (eboot .text is RX, readable)
-- 3. If we find DT_STRTAB/DT_SYMTAB, dump NID strings

print("=== PROBE 508a: module NID table scan ===")
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

-- read a NUL-terminated string from memory (max 64 chars)
local function read_str(addr, maxlen)
    maxlen = maxlen or 64
    local s = ""
    for i = 0, maxlen - 1 do
        local b = safe_rd(addr + i)
        if not b then break end
        local c = b % 256
        if c == 0 then break end
        s = s .. string.char(c)
    end
    return s
end

-- read a byte
local function safe_rb(addr)
    local d = safe_rd(addr)
    if not d then return nil end
    return d % 256
end

local sc20  = make_syscall(20)
local sc593 = make_syscall(593)
local sc674 = make_syscall(674)  -- VM map

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ [A] deep scan of dynlib_get_info struct
print("")
print("[A] Deep scan of dynlib_get_info(593) for handle 0 (eboot)...")

local info = memory.alloc(0x200)
for i = 0, 0x1FC, 4 do safe_wd(info + i, 0) end
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)

-- dump all qwords in the struct looking for pointers
print("  Full struct dump (qwords with nonzero hi byte):")
for off = 0, 0x158, 8 do
    local val = safe_rq(info + off)
    if val then
        local h, l = get_hi_lo(val)
        if h ~= 0 then
            print(string.format("    +0x%03X: %s", off, fmt_hex(val)))
        end
    end
end

-- Known layout:
-- +0x000: size (0x160)
-- +0x008: name (char[256])
-- +0x108: text_addr (lo), +0x10C: text_addr (hi)
-- +0x110: text_size
-- +0x118: data_addr (lo), +0x11C: data_addr (hi)
-- +0x120: data_size
-- but there might be more fields after these

local text_addr = safe_rq(info + 0x108)
local text_size = safe_rd(info + 0x110)
local data_addr = safe_rq(info + 0x118)
local data_size = safe_rd(info + 0x120)

print(string.format("  text: %s size=0x%X", fmt_hex(text_addr), text_size or 0))
print(string.format("  data: %s size=0x%X", fmt_hex(data_addr), data_size or 0))

-- Check fields past 0x120 for more pointers
print("  Fields past data_size:")
for off = 0x128, 0x158, 8 do
    local val = safe_rq(info + off)
    if val then
        local h, l = get_hi_lo(val)
        -- print even if zero
        print(string.format("    +0x%03X: %s", off, fmt_hex(val)))
    end
end

------------------------------------------------------------------ [B] scan eboot .text for ELF dynamic section
print("")
print("[B] Scanning eboot headers for ELF dynamic section...")

-- eboot is RX, so we can read its headers
local eboot = text_addr
if not eboot then
    print("  FATAL: no eboot base")
    return
end

-- ELF header at eboot base
local magic = safe_rd(eboot)
print(string.format("  ELF magic: 0x%08X %s", magic or 0,
    magic == 0x464C457F and "[OK]" or "[NOT ELF]"))

if magic ~= 0x464C457F then
    -- PS5 uses a modified format — the magic may differ
    -- Try reading first 16 bytes
    print("  First 16 bytes:")
    for i = 0, 12, 4 do
        local v = safe_rd(eboot + i)
        print(string.format("    +%d: 0x%08X", i, v or 0))
    end
    -- Even if not standard ELF, continue scanning
end

-- e_phoff at +0x20 (for ELF64)
local e_phoff_lo = safe_rd(eboot + 0x20)
local e_phoff_hi = safe_rd(eboot + 0x24)
local e_phentsize = safe_rd(eboot + 0x36)
local e_phnum = safe_rd(eboot + 0x38)

if e_phoff_lo then e_phoff_lo = e_phoff_lo % 65536 * 65536 + e_phoff_lo end

print(string.format("  e_phoff=0x%X%08X e_phentsize=%d e_phnum=%d",
    e_phoff_hi or 0, e_phoff_lo or 0,
    (e_phentsize or 0) % 65536, (e_phnum or 0) % 65536))

-- Read phoff properly
local phoff = safe_rq(eboot + 0x20)
local phentsize = (safe_rd(eboot + 0x36) or 0) % 65536
local phnum = (safe_rd(eboot + 0x38) or 0) % 65536

if phentsize == 0 then phentsize = 0x38 end  -- ELF64 default

print(string.format("  phoff=%s phentsize=%d phnum=%d",
    fmt_hex(phoff), phentsize, phnum))

-- scan program headers looking for PT_DYNAMIC (type=2)
local dyn_addr = nil
local dyn_size = 0
if phnum > 0 and phnum < 20 then
    for i = 0, phnum - 1 do
        local ph_base = eboot + phoff + uint64(i * phentsize)
        local p_type = safe_rd(ph_base)
        if p_type then
            local p_flags = safe_rd(ph_base + 4)
            local p_offset = safe_rq(ph_base + 8)
            local p_vaddr = safe_rq(ph_base + 0x10)
            local p_filesz = safe_rq(ph_base + 0x20)
            print(string.format("  phdr[%d]: type=%d flags=0x%X vaddr=%s filesz=%s",
                i, p_type, p_flags or 0, fmt_hex(p_vaddr), fmt_hex(p_filesz)))
            if p_type == 2 then  -- PT_DYNAMIC
                dyn_addr = eboot + p_vaddr
                dyn_size = to_num(p_filesz)
                print("    *** PT_DYNAMIC found! ***")
            end
        end
    end
end

------------------------------------------------------------------ [C] parse PT_DYNAMIC for DT_STRTAB / DT_SYMTAB
if dyn_addr then
    print("")
    print("[C] Parsing dynamic section at " .. fmt_hex(dyn_addr) .. "...")

    local dt_strtab = nil
    local dt_strsz = 0
    local dt_symtab = nil
    local dt_syment = 0
    local dt_hash = nil
    local dt_gnu_hash = nil
    local dt_pltgot = nil
    local dt_rela = nil
    local dt_relasz = 0
    local nid_table_addr = nil

    -- each entry: {d_tag: i64, d_val: u64} = 16 bytes
    local max_entries = math.min(math.floor(dyn_size / 16), 200)
    for i = 0, max_entries - 1 do
        local tag_val = safe_rq(dyn_addr + i * 16)
        local val = safe_rq(dyn_addr + i * 16 + 8)
        local tag = to_num(tag_val)

        if tag == 0 then break end  -- DT_NULL

        -- print interesting tags
        local tag_name = ""
        if tag == 5 then tag_name = "DT_STRTAB"; dt_strtab = val
        elseif tag == 6 then tag_name = "DT_SYMTAB"; dt_symtab = val
        elseif tag == 10 then tag_name = "DT_STRSZ"; dt_strsz = to_num(val)
        elseif tag == 11 then tag_name = "DT_SYMENT"; dt_syment = to_num(val)
        elseif tag == 4 then tag_name = "DT_HASH"; dt_hash = val
        elseif tag == 3 then tag_name = "DT_PLTGOT"; dt_pltgot = val
        elseif tag == 7 then tag_name = "DT_RELA"; dt_rela = val
        elseif tag == 8 then tag_name = "DT_RELASZ"; dt_relasz = to_num(val)
        -- Sony-specific tags might be in 0x61000000+ range
        elseif tag >= 0x61000000 then tag_name = "SONY?"
        end

        if tag_name ~= "" then
            print(string.format("    [%d] tag=0x%X (%s) val=%s",
                i, tag, tag_name, fmt_hex(val)))
        end

        -- PS4/PS5 use tag 0x61000035 for the NID table
        if tag == 0x61000035 or tag == 0x61000037 then
            nid_table_addr = val
            print(string.format("    *** NID TABLE TAG 0x%X = %s ***", tag, fmt_hex(val)))
        end
    end

    -- [D] Try to read strtab
    if dt_strtab then
        print("")
        print("[D] Reading DT_STRTAB at " .. fmt_hex(dt_strtab) .. " (size=" .. dt_strsz .. ")...")

        -- DT_STRTAB value is usually an offset relative to module base
        -- Try both: as-is (if it looks like an absolute address) and base+offset
        local strtab_abs = dt_strtab
        local strtab_rel = eboot + dt_strtab

        -- check which one is readable
        local test1 = safe_rb(strtab_abs)
        local test2 = safe_rb(strtab_rel)
        print(string.format("    strtab as absolute: first byte=%s", test1 and string.format("0x%02X", test1) or "UNREADABLE"))
        print(string.format("    strtab as base+offset: first byte=%s", test2 and string.format("0x%02X", test2) or "UNREADABLE"))

        local strtab = nil
        if test1 then strtab = strtab_abs
        elseif test2 then strtab = strtab_rel
        end

        if strtab then
            -- dump first 20 strings
            print("    First strings in strtab:")
            local pos = 0
            local count = 0
            local max_read = math.min(dt_strsz, 4096)
            while pos < max_read and count < 30 do
                local s = read_str(strtab + pos, 128)
                if #s > 0 then
                    print(string.format("      [%d] +0x%X: \"%s\"", count, pos, s))
                    count = count + 1
                    pos = pos + #s + 1
                else
                    pos = pos + 1
                end
            end
        end
    end

    -- [E] Try to read symtab
    if dt_symtab then
        print("")
        print("[E] Reading DT_SYMTAB at " .. fmt_hex(dt_symtab) .. "...")
        if dt_syment == 0 then dt_syment = 24 end  -- ELF64 Sym default

        local symtab_abs = dt_symtab
        local symtab_rel = eboot + dt_symtab

        local test1 = safe_rd(symtab_abs)
        local test2 = safe_rd(symtab_rel)

        local symtab = nil
        if test1 then symtab = symtab_abs
        elseif test2 then symtab = symtab_rel
        end

        if symtab then
            print("    First 20 symbol entries (syment=" .. dt_syment .. "):")
            local strtab_for_names = nil
            if dt_strtab then
                local t1 = safe_rb(dt_strtab)
                local t2 = safe_rb(eboot + dt_strtab)
                if t1 then strtab_for_names = dt_strtab
                elseif t2 then strtab_for_names = eboot + dt_strtab end
            end

            for i = 0, 19 do
                local sym = symtab + uint64(i * dt_syment)
                local st_name = safe_rd(sym)       -- offset into strtab
                local st_info = safe_rb(sym + 4)
                local st_other = safe_rb(sym + 5)
                local st_shndx = safe_rd(sym + 6)
                local st_value = safe_rq(sym + 8)
                local st_size = safe_rq(sym + 16)

                if st_name then
                    local name = ""
                    if strtab_for_names and st_name > 0 then
                        name = read_str(strtab_for_names + st_name, 80)
                    end
                    local bind = math.floor((st_info or 0) / 16)
                    local stype = (st_info or 0) % 16
                    print(string.format("      [%d] name_off=0x%X bind=%d type=%d val=%s \"%s\"",
                        i, st_name, bind, stype, fmt_hex(st_value), name))
                end
            end
        else
            print("    symtab UNREADABLE at either address")
        end
    end

    -- [F] Sony-specific NID table
    if nid_table_addr then
        print("")
        print("[F] Reading Sony NID table at " .. fmt_hex(nid_table_addr) .. "...")
        local nid_tab = nid_table_addr
        local test1 = safe_rd(nid_tab)
        if not test1 then
            nid_tab = eboot + nid_table_addr
            test1 = safe_rd(nid_tab)
        end
        if test1 then
            print("    First 10 entries:")
            for i = 0, 9 do
                local val = safe_rq(nid_tab + i * 8)
                print(string.format("      [%d] %s", i, fmt_hex(val)))
            end
        end
    end
else
    print("")
    print("[C] No PT_DYNAMIC found, trying fallback...")

    -- Fallback: use the VM map (674) to find data segments, then scan for
    -- DT_STRTAB/DT_SYMTAB patterns in data
    print("  Scanning eboot data segment for pointer-like values...")
    if data_addr then
        local scan_size = math.min(data_size or 0x10000, 0x10000)
        print(string.format("  data at %s, scanning %d bytes", fmt_hex(data_addr), scan_size))

        -- look for a qword that points into eboot .text range
        local text_h, text_l = get_hi_lo(text_addr)
        local count = 0
        for off = 0, scan_size - 8, 8 do
            local val = safe_rq(data_addr + off)
            if val then
                local vh, vl = get_hi_lo(val)
                -- is this pointing into eboot?
                if vh == text_h and vl >= text_l and vl < text_l + (text_size or 0) then
                    if count < 20 then
                        print(string.format("    data+0x%X: %s (eboot+0x%X)",
                            off, fmt_hex(val), vl - text_l))
                    end
                    count = count + 1
                end
            end
        end
        print("    total eboot-pointing qwords in data: " .. count)
    end
end

------------------------------------------------------------------ [G] try 591 with strtab entries if we found them
print("")
print("[G] Summary")
print("  If strtab strings were found above, try them with 591 in a follow-up probe.")
print("  The NID encoding format should be visible in the strtab dump.")

print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]"))
print("")
print("=== PROBE 508a COMPLETE ===")
