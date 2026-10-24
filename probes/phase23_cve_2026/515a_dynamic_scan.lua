-- CRASH_CLASS: LOW
-- PROBE 515a: find .dynamic section by scanning eboot data segment
--
-- 514a confirmed:
--   text_addr = 0x3C7F0000 starts with "/lib" (PT_INTERP, not ELF header)
--   data_addr = 0x3CFF0000 p=0x3 (RW)
--   sys 674 works: 323 VM regions
--   ELF/OELF header is NOT mapped in memory
--
-- Strategy: scan the data segment for DT_* tag patterns.
-- .dynamic is an array of {uint64 tag, uint64 value} entries.
-- We look for known tags: DT_STRTAB(5), DT_SYMTAB(6), DT_HASH(4),
-- and SCE tags (0x61000049 etc). Terminated by DT_NULL(0).

print("=== PROBE 515a: .dynamic section scan ===")

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
            s = s .. "."
        end
    end
    return s
end

local sc20  = make_syscall(20)
local sc593 = make_syscall(593)
local sc674 = make_syscall(674)

local pid = to_num(sc20())
print("pid: " .. pid)

-- get eboot addresses
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local text_addr = safe_rq(info + 0x108)
local data_addr = safe_rq(info + 0x118)
local text_size = safe_rd(info + 0x110)
local data_size = safe_rd(info + 0x120)
print("text: " .. fmt_hex(text_addr) .. " sz=0x" .. string.format("%X", text_size or 0))
print("data: " .. fmt_hex(data_addr) .. " sz=0x" .. string.format("%X", data_size or 0))

-- ============================================================
-- [A] List eboot-adjacent VM regions from sys 674
-- ============================================================
print("")
print("[A] VM regions near eboot")

local STRIDE = 72
local MAX_REC = 400
local vm_buf = memory.alloc(STRIDE * MAX_REC)
local vm_countp = memory.alloc(16)
safe_wq(vm_countp, uint64(0))

local ok674, ret674 = pcall(function()
    return sc674(uint64(to_num(vm_buf)), uint64(STRIDE), uint64(MAX_REC),
                 uint64(to_num(vm_countp)), uint64(0x40000000))
end)
local vm_ret = ok674 and to_num(ret674) or -999
local vm_count = safe_rd(vm_countp)
print("674: ret=" .. vm_ret .. " count=" .. (vm_count or 0))

local text_h, text_l = get_hi_lo(text_addr)
local data_h, data_l = get_hi_lo(data_addr)
local data_end_l = data_l + (data_size or 0)

local eb_regions = {}
if vm_count and vm_count > 0 then
    for i = 0, math.min(vm_count, MAX_REC) - 1 do
        local rec = vm_buf + i * STRIDE
        local s = safe_rq(rec)
        local e = safe_rq(rec + 8)
        local p = safe_rd(rec + 0x18)
        if s and e then
            local sh, sl = get_hi_lo(s)
            -- regions in the eboot address range (2MB before text to 2MB after data end)
            if sh == text_h and sl >= (text_l - 0x400000) and sl <= (data_end_l + 0x400000) then
                local nm = read_str(rec + 0x20, 24)
                table.insert(eb_regions, {s=s, e=e, p=p or 0, name=nm})
            end
        end
    end
end

for _, r in ipairs(eb_regions) do
    local sz = to_num(r.e) - to_num(r.s)
    print(string.format("  %s-%s p=%d sz=0x%X \"%s\"",
        fmt_hex(r.s), fmt_hex(r.e), r.p, sz, r.name))
end
print("  total eboot regions: " .. #eb_regions)

-- ============================================================
-- [B] Scan data segment for .dynamic section
-- ============================================================
print("")
print("[B] Scanning data segment for .dynamic")

-- .dynamic is 16-byte aligned entries {tag(8), val(8)}
-- Scan for a sequence where we see DT_STRTAB(5) or DT_SYMTAB(6) or SCE tags
-- These are rare enough that finding 2+ in a 16-byte stride means .dynamic

local dyn_addr = nil
local scan_step = 0x10  -- 16-byte aligned
local scan_limit = math.min(data_size or 0x100000, 0x100000)

-- scan in chunks to avoid too many operations between prints
local chunk = 0x1000  -- 4KB per chunk
local chunks_done = 0

for off = 0, scan_limit - 16, chunk do
    local found_in_chunk = false
    local limit = math.min(chunk, scan_limit - off)

    for sub = 0, limit - 16, scan_step do
        local addr = data_addr + uint64(off + sub)
        local tag_lo = safe_rd(addr)
        local tag_hi = safe_rd(addr + 4)

        if not tag_lo then break end

        -- check for known DT tags at this position
        if tag_hi == 0 and (tag_lo == 4 or tag_lo == 5 or tag_lo == 6 or tag_lo == 10 or tag_lo == 23) then
            -- standard DT tag found, verify next entry is also a valid tag
            local next_tag_lo = safe_rd(addr + 16)
            local next_tag_hi = safe_rd(addr + 20)
            if next_tag_lo and next_tag_hi == 0 and next_tag_lo >= 1 and next_tag_lo <= 35 then
                dyn_addr = addr
                found_in_chunk = true
                break
            end
            -- also check if it's preceded by valid tags
            if not found_in_chunk then
                local prev_tag_lo = safe_rd(addr - 16)
                local prev_tag_hi = safe_rd(addr - 12)
                if prev_tag_lo and prev_tag_hi == 0 and prev_tag_lo >= 1 and prev_tag_lo <= 35 then
                    dyn_addr = addr - uint64(16)
                    found_in_chunk = true
                    break
                end
            end
        end

        -- SCE tags: hi = 0x61000000
        if tag_hi == 0x61000000 and tag_lo >= 0x35 and tag_lo <= 0x5F then
            dyn_addr = addr
            found_in_chunk = true
            break
        end
    end

    if found_in_chunk then break end

    chunks_done = chunks_done + 1
    if chunks_done % 64 == 0 then
        print("  scanned 0x" .. string.format("%X", off + chunk) .. "...")
    end
end

if not dyn_addr then
    print("  .dynamic NOT found in data segment")

    -- try scanning backward from data_addr start (maybe in gap between text and data)
    print("  trying gap between text_end and data...")
    local text_end = text_addr + uint64(text_size or 0)
    for off = 0, 0x100000, scan_step do
        local addr = text_end + uint64(off)
        local tag_lo = safe_rd(addr)
        local tag_hi = safe_rd(addr + 4)
        if not tag_lo then break end
        if tag_hi == 0 and (tag_lo == 5 or tag_lo == 6) then
            local next_lo = safe_rd(addr + 16)
            local next_hi = safe_rd(addr + 20)
            if next_lo and next_hi == 0 and next_lo >= 1 and next_lo <= 35 then
                dyn_addr = addr
                break
            end
        end
        if tag_hi == 0x61000000 and tag_lo >= 0x35 and tag_lo <= 0x5F then
            dyn_addr = addr
            break
        end
    end
end

if dyn_addr then
    -- walk backward to find the start of .dynamic
    for back = 1, 200 do
        local prev = dyn_addr - uint64(16)
        local t_lo = safe_rd(prev)
        local t_hi = safe_rd(prev + 4)
        if not t_lo then break end
        -- a valid DT entry has tag > 0
        if t_hi == 0 and t_lo == 0 then break end  -- DT_NULL = start boundary
        if t_hi == 0 and t_lo >= 1 and t_lo <= 0x7FFFFFFF then
            dyn_addr = prev
        elseif t_hi >= 0x60000000 and t_hi <= 0x7FFFFFFF then
            dyn_addr = prev
        else
            break
        end
    end

    print("  .dynamic at " .. fmt_hex(dyn_addr))
    print("")

    -- ============================================================
    -- [C] Parse dynamic entries
    -- ============================================================
    print("[C] Dynamic entries:")

    local dt_strtab = nil
    local dt_strsz = 0
    local dt_symtab = nil
    local sce_strtab = nil
    local sce_strsz = 0

    for i = 0, 199 do
        local tag = safe_rq(dyn_addr + i * 16)
        local val = safe_rq(dyn_addr + i * 16 + 8)
        local t = to_num(tag)
        if t == 0 then
            print(string.format("  [%d] DT_NULL", i))
            break
        end

        local th, tl = get_hi_lo(tag)
        local tname = nil

        if th == 0 then
            if tl == 1 then tname = "NEEDED"
            elseif tl == 2 then tname = "PLTRELSZ"
            elseif tl == 3 then tname = "PLTGOT"
            elseif tl == 4 then tname = "HASH"
            elseif tl == 5 then tname = "STRTAB"; dt_strtab = val
            elseif tl == 6 then tname = "SYMTAB"; dt_symtab = val
            elseif tl == 7 then tname = "RELA"
            elseif tl == 8 then tname = "RELASZ"
            elseif tl == 9 then tname = "RELAENT"
            elseif tl == 10 then tname = "STRSZ"; dt_strsz = to_num(val)
            elseif tl == 11 then tname = "SYMENT"
            elseif tl == 12 then tname = "INIT"
            elseif tl == 13 then tname = "FINI"
            elseif tl == 20 then tname = "PLTREL"
            elseif tl == 21 then tname = "DEBUG"
            elseif tl == 23 then tname = "JMPREL"
            elseif tl == 25 then tname = "INIT_ARRAY"
            elseif tl == 27 then tname = "INIT_ARRAYSZ"
            elseif tl == 26 then tname = "FINI_ARRAY"
            elseif tl == 28 then tname = "FINI_ARRAYSZ"
            elseif tl == 30 then tname = "FLAGS"
            elseif tl == 0x6FFFFFFB then tname = "FLAGS_1"
            elseif tl == 0x6FFFFFF0 then tname = "VERSYM"
            elseif tl == 0x6FFFFFFE then tname = "VERNEED"
            elseif tl == 0x6FFFFFFF then tname = "VERNEEDNUM"
            else tname = string.format("DT_%d", tl)
            end
        else
            if th == 0x61000000 then
                if tl == 0x35 then tname = "SCE_FINGERPRINT"
                elseif tl == 0x37 then tname = "SCE_ORIG_FILENAME"
                elseif tl == 0x39 then tname = "SCE_MODULE_INFO"
                elseif tl == 0x3B then tname = "SCE_MODULE_ATTR"
                elseif tl == 0x3D then tname = "SCE_EXPORT_LIB"
                elseif tl == 0x3F then tname = "SCE_IMPORT_LIB"
                elseif tl == 0x41 then tname = "SCE_EXPORT_LIB_ATTR"
                elseif tl == 0x43 then tname = "SCE_IMPORT_LIB_ATTR"
                elseif tl == 0x47 then tname = "SCE_HASH_SIZE"
                elseif tl == 0x49 then tname = "SCE_SYMTAB"
                elseif tl == 0x4B then tname = "SCE_SYMTABSZ"
                elseif tl == 0x4D then tname = "SCE_STRTAB"; sce_strtab = val
                elseif tl == 0x4F then tname = "SCE_STRTABSZ"; sce_strsz = to_num(val)
                else tname = string.format("SCE_0x%X", tl)
                end
            else
                tname = string.format("0x%X%08X", th, tl)
            end
        end

        print(string.format("  [%d] %s = %s", i, tname, fmt_hex(val)))
    end

    -- ============================================================
    -- [D] Read strtab (prefer SCE strtab, fall back to standard)
    -- ============================================================
    local strtab = sce_strtab or dt_strtab
    local strsz = sce_strsz > 0 and sce_strsz or dt_strsz

    if strtab then
        print("")
        print("[D] Strtab at " .. fmt_hex(strtab) .. " sz=" .. strsz)

        -- try reading directly first, then base-relative
        local test = safe_rd(strtab)
        if not test then
            print("  direct read failed, trying base-relative")
            strtab = text_addr + strtab
            test = safe_rd(strtab)
        end

        if test then
            local pos = 0
            local count = 0
            local max_read = math.min(strsz, 2048)
            if max_read == 0 then max_read = 1024 end

            while pos < max_read and count < 30 do
                local s = read_str(strtab + uint64(pos), 80)
                if #s > 0 then
                    print(string.format("  [%d] +0x%X: \"%s\"", count, pos, s))
                    count = count + 1
                    -- advance past the string
                    local slen = 0
                    for ci = 0, 79 do
                        local b = safe_rd(strtab + uint64(pos + ci))
                        if not b or b % 256 == 0 then slen = ci + 1; break end
                        slen = ci + 1
                    end
                    pos = pos + slen
                else
                    pos = pos + 1
                end
            end
        else
            print("  strtab UNREADABLE")
        end
    end
else
    print("  .dynamic NOT found anywhere")

    -- fallback: dump first 256 bytes of data segment as hex
    print("")
    print("[ALT] First 128 bytes of data segment:")
    for off = 0, 124, 4 do
        local d = safe_rd(data_addr + off)
        if d then
            print(string.format("  +0x%02X: 0x%08X", off, d))
        end
    end
end

-- ============================================================
-- [E] Final verification
-- ============================================================
print("")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 515a COMPLETE ===")
