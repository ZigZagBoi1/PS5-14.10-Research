-- CRASH_CLASS: LOW
-- PROBE 517a: hunt .dynamic via SCE-specific tags + known strings
--
-- 516a false positive: two consecutive 0x8 values in rodata matched
-- "3 valid tags" heuristic. Real .dynamic has unique SCE tags
-- (0x61000035 = SCE_FINGERPRINT) that are unmistakable.
--
-- Strategy A: scan ALL readable regions for SCE tag 0x61000035-0x6100005F
-- Strategy B: scan for known library name strings ("libkernel", "libSce")
-- Strategy C: dump hex at key offsets for manual analysis

print("=== PROBE 517a: .dynamic SCE tag hunt ===")

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

local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc593(uint64(0), info) end)
local text_addr = safe_rq(info + 0x108)
local data_addr = safe_rq(info + 0x118)
print("text: " .. fmt_hex(text_addr) .. " data: " .. fmt_hex(data_addr))

-- ============================================================
-- [A] Get eboot VM regions
-- ============================================================
print("")
print("[A] Eboot regions")

local STRIDE = 72
local MAX_REC = 400
local vm_buf = memory.alloc(STRIDE * MAX_REC)
local vm_countp = memory.alloc(16)
safe_wq(vm_countp, uint64(0))
pcall(function()
    sc674(uint64(to_num(vm_buf)), uint64(STRIDE), uint64(MAX_REC),
          uint64(to_num(vm_countp)), uint64(0x40000000))
end)
local vm_count = safe_rd(vm_countp) or 0

local text_h, text_l = get_hi_lo(text_addr)
local regions = {}

for i = 0, math.min(vm_count, MAX_REC) - 1 do
    local rec = vm_buf + i * STRIDE
    local s = safe_rq(rec)
    local e = safe_rq(rec + 8)
    local p = safe_rd(rec + 0x18)
    if s and e then
        local sh, sl = get_hi_lo(s)
        if sh == text_h and sl >= (text_l - 0x400000) and sl <= (text_l + 0xA00000) then
            local sz = to_num(e) - to_num(s)
            table.insert(regions, {s = s, e = e, p = p or 0, sz = sz})
            print(string.format("  %s-%s p=%d sz=0x%X", fmt_hex(s), fmt_hex(e), p or 0, sz))
        end
    end
end

-- ============================================================
-- [B] Strategy A: scan for SCE tags (0x61000035-0x6100005F)
-- These values are unique to .dynamic and near-impossible as random data.
-- Scan at 16-byte alignment (each .dynamic entry is 16 bytes).
-- ============================================================
print("")
print("[B] SCE tag scan (0x61000035+)")

local sce_hits = {}

for ri, r in ipairs(regions) do
    if r.p == 1 or r.p == 3 or r.p == 5 then
        local label = "p=" .. r.p
        local scan_max = r.sz
        -- for text (p=5), only scan last 128KB (unlikely at start)
        if r.p == 5 then
            scan_max = math.min(r.sz, 0x20000)
        end
        -- for data/rodata, scan full region
        if r.p == 1 or r.p == 3 then
            scan_max = math.min(r.sz, 0x200000)
        end

        local start_off = 0
        if r.p == 5 and r.sz > 0x20000 then
            start_off = r.sz - 0x20000
        end

        for off = start_off, start_off + scan_max - 16, 16 do
            local addr = r.s + uint64(off)
            local lo = safe_rd(addr)
            local hi = safe_rd(addr + 4)
            if not lo then break end

            -- check for SCE tag: hi=0, lo in SCE range
            if hi == 0 and lo >= 0x61000035 and lo <= 0x6100005F then
                local val = safe_rq(addr + 8)
                table.insert(sce_hits, {addr = addr, tag = lo, val = val, region = ri})
                print(string.format("  HIT: %s tag=0x%X val=%s (%s)",
                    fmt_hex(addr), lo, fmt_hex(val), label))
            end

            -- progress every 256KB
            if off > start_off and (off - start_off) % 0x40000 == 0 then
                print(string.format("  ...%s +0x%X", label, off - start_off))
            end
        end
    end
end
print("  total SCE hits: " .. #sce_hits)

-- ============================================================
-- [C] If SCE tags found, walk the full .dynamic from the first hit
-- ============================================================
if #sce_hits > 0 then
    print("")
    print("[C] Walking .dynamic from first SCE hit")

    local hit_addr = sce_hits[1].addr

    -- walk backward to find .dynamic start
    local dyn_start = hit_addr
    for back = 1, 300 do
        local prev = dyn_start - uint64(16)
        local t_lo = safe_rd(prev)
        local t_hi = safe_rd(prev + 4)
        if not t_lo then break end
        if t_hi == 0 and t_lo == 0 then break end
        -- accept standard tags (1-30), GNU tags (0x6FFFFFxx), SCE tags
        local valid = false
        if t_hi == 0 then
            if t_lo >= 1 and t_lo <= 30 then valid = true end
            if t_lo >= 0x6FFFFFF0 and t_lo <= 0x6FFFFFFF then valid = true end
            if t_lo >= 0x61000035 and t_lo <= 0x6100005F then valid = true end
        end
        if valid then
            dyn_start = prev
        else
            break
        end
    end

    print("  start: " .. fmt_hex(dyn_start))
    print("")
    print("[D] .dynamic entries:")

    local dt_strtab = nil
    local dt_strsz = 0
    local sce_strtab = nil
    local sce_strsz = 0

    for i = 0, 199 do
        local tag = safe_rq(dyn_start + i * 16)
        local val = safe_rq(dyn_start + i * 16 + 8)
        local t = to_num(tag)
        if t == 0 then
            print(string.format("  [%d] DT_NULL", i))
            break
        end

        local tname
        if     t == 1 then tname = "NEEDED"
        elseif t == 2 then tname = "PLTRELSZ"
        elseif t == 3 then tname = "PLTGOT"
        elseif t == 4 then tname = "HASH"
        elseif t == 5 then tname = "STRTAB"; dt_strtab = val
        elseif t == 6 then tname = "SYMTAB"
        elseif t == 7 then tname = "RELA"
        elseif t == 8 then tname = "RELASZ"
        elseif t == 9 then tname = "RELAENT"
        elseif t == 10 then tname = "STRSZ"; dt_strsz = to_num(val)
        elseif t == 11 then tname = "SYMENT"
        elseif t == 12 then tname = "INIT"
        elseif t == 13 then tname = "FINI"
        elseif t == 14 then tname = "SONAME"
        elseif t == 20 then tname = "PLTREL"
        elseif t == 23 then tname = "JMPREL"
        elseif t == 25 then tname = "INIT_ARRAY"
        elseif t == 26 then tname = "FINI_ARRAY"
        elseif t == 27 then tname = "INIT_ARRAYSZ"
        elseif t == 28 then tname = "FINI_ARRAYSZ"
        elseif t == 30 then tname = "FLAGS"
        elseif t == 0x6FFFFFFB then tname = "FLAGS_1"
        elseif t == 0x6FFFFFF0 then tname = "VERSYM"
        elseif t == 0x6FFFFFFE then tname = "VERNEED"
        elseif t == 0x6FFFFFFF then tname = "VERNEEDNUM"
        elseif t == 0x61000035 then tname = "SCE_FINGERPRINT"
        elseif t == 0x61000037 then tname = "SCE_ORIG_FILENAME"
        elseif t == 0x61000039 then tname = "SCE_MODULE_INFO"
        elseif t == 0x6100003B then tname = "SCE_MODULE_ATTR"
        elseif t == 0x6100003D then tname = "SCE_EXPORT_LIB"
        elseif t == 0x6100003F then tname = "SCE_IMPORT_LIB"
        elseif t == 0x61000041 then tname = "SCE_EXPORT_LIB_ATTR"
        elseif t == 0x61000043 then tname = "SCE_IMPORT_LIB_ATTR"
        elseif t == 0x61000045 then tname = "SCE_HASH"
        elseif t == 0x61000047 then tname = "SCE_HASH_SIZE"
        elseif t == 0x61000049 then tname = "SCE_SYMTAB"
        elseif t == 0x6100004B then tname = "SCE_SYMTABSZ"
        elseif t == 0x6100004D then tname = "SCE_STRTAB"; sce_strtab = val
        elseif t == 0x6100004F then tname = "SCE_STRTABSZ"; sce_strsz = to_num(val)
        else tname = string.format("tag_0x%X", t)
        end

        print(string.format("  [%d] %s = %s", i, tname, fmt_hex(val)))
    end

    -- ============================================================
    -- [E] Read strtab
    -- ============================================================
    local strtab = sce_strtab or dt_strtab
    local strsz = sce_strsz > 0 and sce_strsz or dt_strsz

    if strtab then
        print("")
        print("[E] Strtab at " .. fmt_hex(strtab) .. " sz=" .. strsz)

        -- try direct, then base-relative
        local test = safe_rd(strtab)
        if not test then
            strtab = text_addr + strtab
            test = safe_rd(strtab)
            if test then print("  (base-relative, resolved to " .. fmt_hex(strtab) .. ")") end
        end

        if test then
            local pos = 0
            local count = 0
            local max_read = math.min(strsz > 0 and strsz or 2048, 2048)

            while pos < max_read and count < 30 do
                local s = read_str(strtab + uint64(pos), 80)
                if #s > 0 then
                    print(string.format("  [%d] +0x%X: \"%s\"", count, pos, s))
                    count = count + 1
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
            print("  UNREADABLE")
        end
    end
else
    -- ============================================================
    -- [C-ALT] No SCE tags found — try string search
    -- ============================================================
    print("")
    print("[C] No SCE tags. String search for 'libk' in data regions")

    -- search for "libk" (0x6B62696C in little-endian) = libkernel
    local target = 0x6B62696C  -- "libk"
    local str_hits = {}

    for ri, r in ipairs(regions) do
        if r.p == 3 then
            local scan_max = math.min(r.sz, 0x200000)
            for off = 0, scan_max - 4, 4 do
                local d = safe_rd(r.s + off)
                if not d then break end
                if d == target then
                    local addr = r.s + uint64(off)
                    local s = read_str(addr, 40)
                    table.insert(str_hits, {addr = addr, str = s})
                    print("  HIT: " .. fmt_hex(addr) .. " \"" .. s .. "\"")
                end
                if off > 0 and off % 0x80000 == 0 then
                    print("    ...data +0x" .. string.format("%X", off))
                end
            end
        end
    end
    print("  string hits: " .. #str_hits)

    -- also search rodata for "libk"
    print("")
    print("[D] String search in rodata")
    for ri, r in ipairs(regions) do
        if r.p == 1 then
            local scan_max = math.min(r.sz, 0x100000)
            for off = 0, scan_max - 4, 4 do
                local d = safe_rd(r.s + off)
                if not d then break end
                if d == target then
                    local addr = r.s + uint64(off)
                    local s = read_str(addr, 40)
                    print("  HIT: " .. fmt_hex(addr) .. " \"" .. s .. "\"")
                end
            end
        end
    end

    -- dump hex at 516a's false positive for analysis
    print("")
    print("[E] Hex at 516a false positive (rodata+0x1030)")
    for ri, r in ipairs(regions) do
        if r.p == 1 then
            local base = r.s + uint64(0x1000)
            for off = 0, 0xF8, 8 do
                local q = safe_rq(base + off)
                if q then
                    print(string.format("  +0x%04X: %s", 0x1000 + off, fmt_hex(q)))
                end
            end
            break
        end
    end

    -- dump first 256 bytes of each data region
    print("")
    print("[F] Data region starts")
    for ri, r in ipairs(regions) do
        if r.p == 3 then
            print("  --- " .. fmt_hex(r.s) .. " ---")
            for off = 0, 0x78, 8 do
                local q = safe_rq(r.s + off)
                if q then
                    print(string.format("  +0x%02X: %s", off, fmt_hex(q)))
                end
            end
        end
    end
end

print("")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 517a COMPLETE ===")
