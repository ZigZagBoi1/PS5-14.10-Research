-- CRASH_CLASS: LOW
-- PROBE 552j: Parse eboot ELF imports to find MapDirectMemory
--
-- The eboot is RX (readable). Parse its ELF structures:
--   1. ELF header → program headers
--   2. PT_DYNAMIC → dynamic section
--   3. DT_JMPREL/DT_SYMTAB/DT_STRTAB → PLT relocations
--   4. Enumerate all GOT entries pointing to libkernel
--   5. Cross-reference with known addresses

print("=== PROBE 552j: eboot ELF import analysis ===")
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

-- eboot info
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local eb = N(eboot)
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- libkernel info
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
local lk_sz = rd(N(ib2) + 0x110) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_sz < 0 then lk_sz = lk_sz + 0x100000000 end
local lk_base = lk_lo + lk_hi * 0x100000000
local lk_end = lk_base + lk_sz
print(string.format("libkernel=0x%X%08X size=0x%X", lk_hi, lk_lo, lk_sz))

-- Step 1: Read ELF header
print("")
print("[1] ELF Header")
local magic = rd(eb)
print(string.format("  magic: 0x%X %s", magic or 0,
    magic == 0x464C457F and "(ELF)" or "(NOT ELF!)"))
if magic ~= 0x464C457F then
    -- PS5 might use OELF/SELF format, try scanning for PT_DYNAMIC directly
    print("  Not standard ELF, trying alternative scan")
end

-- e_phoff (offset 0x20 in ELF64), e_phentsize (0x36), e_phnum (0x38)
local phoff = rq(eb + 0x20)
local phent_raw = rd(eb + 0x36)
local phent = phent_raw and (phent_raw % 0x10000) or 0
local phnum = phent_raw and math.floor(phent_raw / 0x10000) or 0
print(string.format("  e_phoff=%s e_phentsize=%d e_phnum=%d",
    phoff and fmt(phoff) or "nil", phent, phnum))

-- Step 2: Find PT_DYNAMIC (type=2)
print("")
print("[2] Program Headers — looking for PT_DYNAMIC")
local dyn_addr = nil
local dyn_size = 0

if phoff and phent > 0 and phnum > 0 and phnum < 100 then
    local ph_base = eb + N(phoff)
    for i = 0, phnum - 1 do
        local ph = ph_base + i * phent
        local p_type = rd(ph)
        if p_type then
            local p_vaddr = rq(ph + 0x10)
            local p_filesz = rq(ph + 0x20)
            if p_type == 2 then  -- PT_DYNAMIC
                dyn_addr = eb + N(p_vaddr)
                dyn_size = N(p_filesz)
                print(string.format("  PT_DYNAMIC at vaddr=%s filesz=0x%X",
                    p_vaddr and fmt(p_vaddr) or "nil", dyn_size))
            end
            -- Also show PT_LOAD and PT_SCE_* types
            if p_type == 1 or p_type == 2 or p_type >= 0x60000000 then
                local p_flags = rd(ph + 0x04)
                print(string.format("  [%d] type=0x%X vaddr=%s filesz=%s flags=0x%X",
                    i, p_type, p_vaddr and fmt(p_vaddr) or "nil",
                    p_filesz and fmt(p_filesz) or "nil", p_flags or 0))
            end
        end
    end
end

if not dyn_addr then
    print("  PT_DYNAMIC not found!")
    -- Try scanning for DT_NEEDED pattern in known data area
    print("  Trying brute-force scan for dynamic section...")
    -- The dynamic section contains DT_NEEDED (1), DT_HASH (4), DT_STRTAB (5),
    -- DT_SYMTAB (6), etc. as consecutive Elf64_Dyn entries (16 bytes each: tag+val)
    -- Look for a sequence starting with DT_NEEDED (tag=1)
end

-- Step 3: Parse dynamic section
print("")
print("[3] Dynamic Section")

if dyn_addr then
    local dt_symtab = nil
    local dt_strtab = nil
    local dt_strsz = 0
    local dt_jmprel = nil
    local dt_pltrelsz = 0
    local dt_pltgot = nil
    local dt_rela = nil
    local dt_relasz = 0

    local max_entries = math.min(dyn_size / 16, 200)
    for i = 0, max_entries - 1 do
        local tag = rq(dyn_addr + i * 16)
        local val = rq(dyn_addr + i * 16 + 8)
        if not tag then break end
        local t = N(tag)
        if t == 0 then break end  -- DT_NULL
        if t == 5 then dt_strtab = eb + N(val)   -- DT_STRTAB
        elseif t == 6 then dt_symtab = eb + N(val) -- DT_SYMTAB
        elseif t == 10 then dt_strsz = N(val)      -- DT_STRSZ
        elseif t == 23 then dt_jmprel = eb + N(val) -- DT_JMPREL
        elseif t == 2 then dt_pltrelsz = N(val)    -- DT_PLTRELSZ
        elseif t == 3 then dt_pltgot = eb + N(val) -- DT_PLTGOT
        elseif t == 7 then dt_rela = eb + N(val)   -- DT_RELA
        elseif t == 8 then dt_relasz = N(val)       -- DT_RELASZ
        end
        -- Print interesting entries
        if t <= 30 or t >= 0x60000000 then
            print(string.format("  DT[%d] tag=0x%X val=%s", i, t, fmt(val)))
        end
    end

    print("")
    print(string.format("  SYMTAB=%s STRTAB=%s (sz=0x%X)",
        dt_symtab and fmt(uint64(dt_symtab)) or "nil",
        dt_strtab and fmt(uint64(dt_strtab)) or "nil", dt_strsz))
    print(string.format("  JMPREL=%s (sz=0x%X) PLTGOT=%s",
        dt_jmprel and fmt(uint64(dt_jmprel)) or "nil", dt_pltrelsz,
        dt_pltgot and fmt(uint64(dt_pltgot)) or "nil"))

    -- Step 4: Read string table sample
    if dt_strtab and dt_strsz > 0 then
        print("")
        print("[4] String table sample (first 512 bytes)")
        local sample = ""
        local strs = {}
        local current = ""
        for i = 0, math.min(511, dt_strsz - 1) do
            local b = rd(dt_strtab + i)
            if b then
                local c = b % 256
                if c == 0 then
                    if #current > 0 then
                        table.insert(strs, {off = i - #current, s = current})
                        if #strs <= 30 then
                            print(string.format("    [%d] %s", i - #current, current))
                        end
                    end
                    current = ""
                elseif c >= 32 and c < 127 then
                    current = current .. string.char(c)
                else
                    current = current .. "?"
                end
            end
        end
        print(string.format("  %d strings found in first 512 bytes", #strs))
    end

    -- Step 5: Parse PLT relocations and find libkernel GOT entries
    if dt_jmprel and dt_pltrelsz > 0 and dt_symtab then
        print("")
        print("[5] PLT relocations → libkernel GOT entries")
        local num_relocs = dt_pltrelsz / 24  -- Elf64_Rela is 24 bytes
        local lk_imports = {}

        for i = 0, num_relocs - 1 do
            local r_offset = rq(dt_jmprel + i * 24)      -- GOT slot
            local r_info = rq(dt_jmprel + i * 24 + 8)     -- symbol + type
            if r_offset and r_info then
                -- Read the resolved GOT value
                local got_slot = eb + N(r_offset)
                local resolved = rq(got_slot)
                if resolved then
                    local rh, rl = get_hi_lo(resolved)
                    if rh < 0 then rh = rh + 0x100000000 end
                    if rl < 0 then rl = rl + 0x100000000 end
                    local raddr = rl + rh * 0x100000000
                    -- Check if resolved address is in libkernel range
                    if raddr >= lk_base and raddr < lk_end then
                        local lk_off = raddr - lk_base
                        -- Get symbol name
                        local sym_idx = N(r_info) / 0x100000000
                        if sym_idx ~= math.floor(sym_idx) then
                            sym_idx = math.floor(N(r_info) / 0x100000000)
                        end
                        -- Actually r_info upper 32 bits = symbol index
                        local info_h, info_l = get_hi_lo(r_info)
                        if info_h < 0 then info_h = info_h + 0x100000000 end
                        sym_idx = info_h

                        local sym_name = ""
                        if dt_strtab and dt_symtab then
                            -- Elf64_Sym is 24 bytes: st_name(4), st_info(1), st_other(1), st_shndx(2), st_value(8), st_size(8)
                            local sym_entry = dt_symtab + sym_idx * 24
                            local st_name = rd(sym_entry)
                            if st_name and dt_strtab then
                                local name = ""
                                for ci = 0, 63 do
                                    local cb = rd(dt_strtab + st_name + ci)
                                    if cb then
                                        local cc = cb % 256
                                        if cc == 0 then break end
                                        if cc >= 32 and cc < 127 then
                                            name = name .. string.char(cc)
                                        end
                                    end
                                end
                                sym_name = name
                            end
                        end

                        table.insert(lk_imports, {
                            off = lk_off,
                            name = sym_name,
                            got = N(r_offset)
                        })
                        print(string.format("    lk+0x%05X  %s  (GOT+0x%X)",
                            lk_off, sym_name ~= "" and sym_name or "(unnamed)", N(r_offset)))
                    end
                end
            end
        end
        print(string.format("  %d libkernel imports found", #lk_imports))

        -- Highlight known functions
        print("")
        print("  Known offsets:")
        print("    +0x17EF0 = AllocateDirectMemory (confirmed)")
        print("    +0x17810 = GetDirectMemorySize (confirmed)")
        print("    +0x15020 = ??? (KILLS process)")
        for _, imp in ipairs(lk_imports) do
            if imp.off == 0x17EF0 or imp.off == 0x17810 or imp.off == 0x15020 then
                print(string.format("    → +0x%05X matches: %s", imp.off, imp.name))
            end
        end
    end
end

print("")
print("DONE")
