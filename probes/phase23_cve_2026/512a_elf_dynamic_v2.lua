-- CRASH_CLASS: LOW
-- PROBE 512a: find ELF base via VM map + parse dynamic section (v2)
--
-- 510a failed because sys 674 arg layout was wrong (3 args instead of 5).
-- Correct layout from 55e/55f: (buf, stride=72, max_records, &count, mode=0x40000000)
--
-- Strategy to avoid stdout corruption:
-- 1. Do ALL memory operations FIRST, store results in Lua variables
-- 2. Print ALL results LAST from Lua variables only
-- 3. NO memory reads interleaved with prints

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

-- ============================================================
-- PHASE 1: Gather ALL data into Lua variables (no printing)
-- ============================================================
local results = {}  -- accumulate all output lines

local pid = to_num(sc20())
table.insert(results, "pid: " .. pid)

-- get text_addr / data_addr
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local text_addr = safe_rq(info + 0x108)
local text_size = safe_rd(info + 0x110)
local data_addr = safe_rq(info + 0x118)
local data_size = safe_rd(info + 0x120)
local field_128 = safe_rq(info + 0x128)

table.insert(results, "text_addr: " .. fmt_hex(text_addr) .. " size=0x" .. string.format("%X", text_size or 0))
table.insert(results, "data_addr: " .. fmt_hex(data_addr) .. " size=0x" .. string.format("%X", data_size or 0))
table.insert(results, "+0x128: " .. fmt_hex(field_128))

-- ============================================================
-- [A] VM map with CORRECT 5-arg layout
-- ============================================================
local STRIDE = 72
local MAX_RECORDS = 500
local vm_buf = memory.alloc(STRIDE * MAX_RECORDS)
local vm_countp = memory.alloc(16)
safe_wq(vm_countp, uint64(0))

local ok674, ret674 = pcall(function()
    return sc674(uint64(to_num(vm_buf)), uint64(STRIDE), uint64(MAX_RECORDS),
                 uint64(to_num(vm_countp)), uint64(0x40000000))
end)

local vm_ret = ok674 and to_num(ret674) or -999
local vm_count = safe_rd(vm_countp)

table.insert(results, "")
table.insert(results, "[A] VM map (674): ret=" .. vm_ret .. " count=" .. (vm_count or 0))

-- find eboot regions
local eboot_regions = {}
local text_h, text_l = get_hi_lo(text_addr)

if vm_count and vm_count > 0 and vm_count < MAX_RECORDS then
    for i = 0, vm_count - 1 do
        local rec = vm_buf + i * STRIDE
        local start_a = safe_rq(rec)
        local end_a   = safe_rq(rec + 8)
        local prot    = safe_rd(rec + 0x18)
        local name    = read_str(rec + 0x20, 32)

        if start_a and end_a then
            local sh, sl = get_hi_lo(start_a)
            -- find regions near eboot (within 2MB before to end of data+2MB)
            local data_h, data_l = get_hi_lo(data_addr)
            local data_end = data_l + (data_size or 0) + 0x200000

            if sh == text_h and sl >= (text_l - 0x200000) and sl <= data_end then
                table.insert(eboot_regions, {
                    start = start_a, e = end_a,
                    prot = prot or 0, name = name,
                    line = string.format("  %s - %s prot=0x%X \"%s\"",
                        fmt_hex(start_a), fmt_hex(end_a), prot or 0, name)
                })
            end
        end
    end
end

table.insert(results, "eboot-adjacent regions: " .. #eboot_regions)
for _, r in ipairs(eboot_regions) do
    table.insert(results, r.line)
end

-- ============================================================
-- [B] Scan backward from text_addr for ELF magic
-- ============================================================
local elf_base = nil
local elf_base_info = nil
local PAGE = 0x4000

-- first check if text_addr itself or text_addr-PAGE has the ELF magic
-- also check the start of each eboot-adjacent region with prot=4 or 5
local scan_targets = {}

-- backward from text_addr
for step = 0, 64 do
    table.insert(scan_targets, {
        addr = text_addr - uint64(step * PAGE),
        label = string.format("text-%d*page", step)
    })
end

-- start of all readable eboot regions
for _, r in ipairs(eboot_regions) do
    if r.prot == 4 or r.prot == 5 then
        table.insert(scan_targets, {addr = r.start, label = "region_" .. fmt_hex(r.start)})
    end
end

for _, t in ipairs(scan_targets) do
    local magic = safe_rd(t.addr)
    if not magic then
        if t.label:sub(1,5) == "text-" then
            elf_base_info = "unreadable at " .. t.label
            break  -- stop backward scan
        end
    elseif magic == 0x464C457F then  -- \x7FELF
        elf_base = t.addr
        elf_base_info = "FOUND \\x7FELF at " .. t.label .. " = " .. fmt_hex(t.addr)
        break
    elseif magic == 0x1D3D154F then  -- OELF magic
        elf_base = t.addr
        elf_base_info = "FOUND OELF at " .. t.label .. " = " .. fmt_hex(t.addr)
        break
    end
end

table.insert(results, "")
table.insert(results, "[B] ELF scan: " .. (elf_base_info or "no magic found"))

-- also dump first dword at text_addr-0 through text_addr-4*PAGE
local page_dwords = {}
for step = 0, 4 do
    local addr = text_addr - uint64(step * PAGE)
    local d = safe_rd(addr)
    if d then
        table.insert(page_dwords, string.format("  text-0x%X: 0x%08X", step * PAGE, d))
    else
        table.insert(page_dwords, string.format("  text-0x%X: UNREADABLE", step * PAGE))
    end
end
for _, l in ipairs(page_dwords) do table.insert(results, l) end

-- ============================================================
-- [C] Parse ELF headers if found
-- ============================================================
local dyn_entries = {}
local strtab_strings = {}

if elf_base then
    local e_type = safe_rd(elf_base + 0x10)
    local e_machine = safe_rd(elf_base + 0x12)
    local e_phoff = safe_rq(elf_base + 0x20)
    local e_phentsize = (safe_rd(elf_base + 0x36) or 0) % 65536
    local e_phnum = (safe_rd(elf_base + 0x38) or 0) % 65536
    if e_phentsize == 0 then e_phentsize = 0x38 end

    table.insert(results, "")
    table.insert(results, string.format("[C] ELF header: type=0x%X machine=0x%X phoff=%s phentsz=%d phnum=%d",
        (e_type or 0) % 65536, (e_machine or 0) % 65536, fmt_hex(e_phoff), e_phentsize, e_phnum))

    local dyn_vaddr = nil
    local dyn_filesz = 0

    if e_phnum > 0 and e_phnum < 30 then
        for i = 0, e_phnum - 1 do
            local ph = elf_base + e_phoff + uint64(i * e_phentsize)
            local p_type = safe_rd(ph)
            local p_flags = safe_rd(ph + 4)
            local p_vaddr = safe_rq(ph + 0x10)
            local p_filesz = safe_rq(ph + 0x20)

            if p_type and p_type ~= 0 then
                local tname = ""
                if p_type == 1 then tname = "LOAD"
                elseif p_type == 2 then tname = "DYNAMIC"
                elseif p_type == 3 then tname = "INTERP"
                elseif p_type == 4 then tname = "NOTE"
                elseif p_type == 6 then tname = "PHDR"
                elseif p_type == 7 then tname = "TLS"
                elseif p_type >= 0x60000000 then tname = string.format("OS/0x%X", p_type)
                else tname = string.format("?0x%X", p_type) end

                table.insert(results, string.format("  [%d] %s flags=0x%X vaddr=%s filesz=%s",
                    i, tname, p_flags or 0, fmt_hex(p_vaddr), fmt_hex(p_filesz)))

                if p_type == 2 then
                    dyn_vaddr = p_vaddr
                    dyn_filesz = to_num(p_filesz)
                end
            end
        end
    end

    -- [D] Parse dynamic section
    if dyn_vaddr then
        -- try absolute first, then base-relative
        local dyn = dyn_vaddr
        local test_d = safe_rd(dyn)
        if not test_d then
            dyn = elf_base + dyn_vaddr
            test_d = safe_rd(dyn)
        end

        if test_d then
            table.insert(results, "")
            table.insert(results, "[D] Dynamic at " .. fmt_hex(dyn))

            local dt_strtab = nil
            local dt_strsz = 0

            local max_ent = math.min(math.floor(dyn_filesz / 16), 200)
            if max_ent == 0 then max_ent = 200 end

            for i = 0, max_ent - 1 do
                local tag = safe_rq(dyn + i * 16)
                local val = safe_rq(dyn + i * 16 + 8)
                local t = to_num(tag)
                if t == 0 then break end

                local tname = nil
                if t == 5 then tname = "DT_STRTAB"
                elseif t == 6 then tname = "DT_SYMTAB"
                elseif t == 10 then tname = "DT_STRSZ"
                elseif t == 11 then tname = "DT_SYMENT"
                elseif t == 4 then tname = "DT_HASH"
                elseif t == 3 then tname = "DT_PLTGOT"
                elseif t == 23 then tname = "DT_JMPREL"
                elseif t == 0x61000049 then tname = "SCE_SYMTAB"
                elseif t == 0x6100004B then tname = "SCE_SYMTABSZ"
                elseif t == 0x6100004D then tname = "SCE_STRTAB"
                elseif t == 0x6100004F then tname = "SCE_STRTABSZ"
                elseif t == 0x61000035 then tname = "SCE_FINGERPRINT"
                elseif t == 0x61000037 then tname = "SCE_ORIG_FILENAME"
                elseif t == 0x61000039 then tname = "SCE_MODULE_INFO"
                elseif t == 0x6100003B then tname = "SCE_MODULE_ATTR"
                elseif t == 0x6100003D then tname = "SCE_EXPORT_LIB"
                elseif t == 0x6100003F then tname = "SCE_IMPORT_LIB"
                elseif t == 0x61000041 then tname = "SCE_EXPORT_LIB_ATTR"
                elseif t == 0x61000043 then tname = "SCE_IMPORT_LIB_ATTR"
                elseif t == 0x61000047 then tname = "SCE_HASH_SIZE"
                elseif t >= 0x61000000 and t <= 0x6FFFFFFF then
                    tname = string.format("SCE/0x%X", t)
                end

                if tname then
                    table.insert(dyn_entries, string.format("  [%d] %s = %s", i, tname, fmt_hex(val)))

                    if t == 0x6100004D or t == 5 then
                        dt_strtab = val
                    end
                    if t == 0x6100004F or t == 10 then
                        dt_strsz = to_num(val)
                    end
                end
            end

            -- [E] Read strtab
            if dt_strtab then
                local strtab = dt_strtab
                local test_s = safe_rd(strtab)
                if not test_s then
                    strtab = elf_base + dt_strtab
                    test_s = safe_rd(strtab)
                end

                if test_s then
                    table.insert(strtab_strings, "[E] Strtab at " .. fmt_hex(strtab) .. " (sz=" .. dt_strsz .. ")")
                    local pos = 0
                    local count = 0
                    local max_read = math.min(dt_strsz, 4096)
                    if max_read == 0 then max_read = 2048 end

                    while pos < max_read and count < 40 do
                        local s = read_str(strtab + pos, 128)
                        if #s > 0 then
                            table.insert(strtab_strings, string.format("  [%d] +0x%X: \"%s\"", count, pos, s))
                            count = count + 1
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
                    table.insert(strtab_strings, "[E] Strtab UNREADABLE at both " .. fmt_hex(dt_strtab) .. " and base-relative")
                end
            end
        end
    end
else
    table.insert(results, "")
    table.insert(results, "[C] No ELF header found")

    -- [ALT] try field +0x128 from 593
    if field_128 then
        local f128_magic = safe_rd(field_128)
        if f128_magic then
            table.insert(results, string.format("[ALT] +0x128=%s first_dword=0x%08X \"%s\"",
                fmt_hex(field_128), f128_magic, read_str(field_128, 16)))
            if f128_magic == 0x464C457F then
                table.insert(results, "  *** +0x128 IS the ELF header! ***")
            end
        else
            table.insert(results, "[ALT] +0x128=" .. fmt_hex(field_128) .. " UNREADABLE")
        end
    end
end

-- ============================================================
-- [F] sys 649 module member addresses
-- ============================================================
local sc649 = make_syscall(649)
local out649 = memory.alloc(0x100)
local member_lines = {}

for mtype = 1, 8 do
    for j = 0, 0xFC, 4 do safe_wd(out649 + j, 0) end
    local ok, ret = pcall(function()
        return sc649(uint64(0), uint64(mtype), uint64(to_num(out649)))
    end)
    if ok and to_num(ret) == 0 then
        local v0 = safe_rq(out649)
        local v1 = safe_rq(out649 + 8)
        local v2 = safe_rq(out649 + 16)
        table.insert(member_lines, string.format("  handle=0 m=%d: %s %s %s",
            mtype, fmt_hex(v0), fmt_hex(v1), fmt_hex(v2)))
    end
end

-- verification
local pid2 = to_num(sc20())

-- ============================================================
-- PRINT EVERYTHING (no more memory ops after this)
-- ============================================================
io.write("=== PROBE 512a: ELF base + dynamic section (v2) ===\n\n")

for _, line in ipairs(results) do io.write(line .. "\n") end
for _, line in ipairs(dyn_entries) do io.write(line .. "\n") end
for _, line in ipairs(strtab_strings) do io.write(line .. "\n") end

io.write("\n[F] sys 649 members:\n")
for _, line in ipairs(member_lines) do io.write(line .. "\n") end

io.write("\npid: " .. pid2 .. (pid2 == pid and " [OK]" or " [CHANGED!]") .. "\n")
io.write("\n=== PROBE 512a COMPLETE ===\n")
io.flush()
