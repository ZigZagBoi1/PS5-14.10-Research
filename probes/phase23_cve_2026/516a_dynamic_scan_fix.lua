-- CRASH_CLASS: LOW
-- PROBE 516a: find .dynamic — fix SCE tag detection bug
--
-- 515a bug: checked tag_hi == 0x61000000 for SCE tags, but ALL DT tags
-- fit in 32 bits (tag_lo = 0x61000035, tag_hi = 0). Fixed here.
--
-- Also: scan ALL 4 eboot regions (including .rodata p=1 and second data),
-- not just the first data segment. And raise scan limit to cover full regions.
--
-- Eboot layout (from 515a):
--   0x30EB0000-0x31344000 p=5 sz=0x494000  .text (RX)
--   0x314B0000-0x314C8000 p=1 sz=0x18000   .rodata (R)
--   0x316B0000-0x317F4000 p=3 sz=0x144000  .data (RW)
--   0x317F4000-0x31830000 p=3 sz=0x3C000   .bss/data2 (RW)

print("=== PROBE 516a: .dynamic scan (fixed) ===")

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
-- [A] Dump dynlib_get_info struct for pointers we haven't checked
-- ============================================================
print("")
print("[A] dynlib_get_info struct scan")
local interesting = {}
for off = 0, 0x158, 8 do
    local val = safe_rq(info + off)
    if val then
        local vh, vl = get_hi_lo(val)
        -- only show non-zero values
        if vh ~= 0 or vl ~= 0 then
            local th, tl = get_hi_lo(text_addr)
            -- flag if in eboot range
            local tag = ""
            if vh == th and vl >= tl - 0x400000 and vl <= tl + 0x800000 then
                tag = " [EBOOT]"
            end
            table.insert(interesting, string.format("  +0x%03X: %s%s", off, fmt_hex(val), tag))
        end
    end
end
for _, l in ipairs(interesting) do print(l) end

-- ============================================================
-- [B] Get eboot VM regions via sys 674
-- ============================================================
print("")
print("[B] Eboot VM regions")

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
            table.insert(regions, {s = s, e = e, p = p or 0,
                sz = to_num(e) - to_num(s)})
        end
    end
end

for _, r in ipairs(regions) do
    print(string.format("  %s-%s p=%d sz=0x%X", fmt_hex(r.s), fmt_hex(r.e), r.p, r.sz))
end

-- ============================================================
-- [C] Scan writable + readable regions for .dynamic
-- ============================================================
print("")
print("[C] Scanning for .dynamic")

-- is_dyn_tag: returns true if this looks like a valid DT tag
local function is_dyn_tag(lo, hi)
    if hi ~= 0 then return false end
    -- standard DT tags 1-30
    if lo >= 1 and lo <= 30 then return true end
    -- DT_FLAGS_1 etc in 0x6FFFFFxx range
    if lo >= 0x6FFFFFF0 and lo <= 0x6FFFFFFF then return true end
    -- SCE tags 0x61000035-0x6100005F
    if lo >= 0x61000035 and lo <= 0x6100005F then return true end
    return false
end

local dyn_found = nil

-- scan all readable/writable regions (p=1 or p=3)
for _, r in ipairs(regions) do
    if r.p == 1 or r.p == 3 then
        print("  scanning " .. fmt_hex(r.s) .. " p=" .. r.p .. " sz=0x" .. string.format("%X", r.sz))

        local scan_max = math.min(r.sz, 0x200000)
        for off = 0, scan_max - 16, 16 do
            local addr = r.s + uint64(off)
            local t_lo = safe_rd(addr)
            local t_hi = safe_rd(addr + 4)

            if not t_lo then break end

            if is_dyn_tag(t_lo, t_hi) then
                -- check if next entry is also a valid tag or DT_NULL
                local n_lo = safe_rd(addr + 16)
                local n_hi = safe_rd(addr + 20)
                if n_lo then
                    if (n_hi == 0 and n_lo == 0) or is_dyn_tag(n_lo, n_hi) then
                        -- also check entry after that
                        local nn_lo = safe_rd(addr + 32)
                        local nn_hi = safe_rd(addr + 36)
                        if nn_lo and ((nn_hi == 0 and nn_lo == 0) or is_dyn_tag(nn_lo, nn_hi)) then
                            dyn_found = addr
                            print("  FOUND at " .. fmt_hex(addr) .. " offset=0x" .. string.format("%X", off))
                            break
                        end
                    end
                end
            end

            if off > 0 and off % 0x40000 == 0 then
                print("    ...0x" .. string.format("%X", off))
            end
        end

        if dyn_found then break end
    end
end

-- also scan the text segment's last 0x10000 bytes (some linkers put .dynamic there)
if not dyn_found then
    for _, r in ipairs(regions) do
        if r.p == 5 and r.sz > 0x10000 then
            print("  scanning end of text " .. fmt_hex(r.s) .. " (last 64KB)")
            local start_off = r.sz - 0x10000
            for off = start_off, r.sz - 16, 16 do
                local addr = r.s + uint64(off)
                local t_lo = safe_rd(addr)
                local t_hi = safe_rd(addr + 4)
                if not t_lo then break end
                if is_dyn_tag(t_lo, t_hi) then
                    local n_lo = safe_rd(addr + 16)
                    local n_hi = safe_rd(addr + 20)
                    if n_lo and ((n_hi == 0 and n_lo == 0) or is_dyn_tag(n_lo, n_hi)) then
                        local nn_lo = safe_rd(addr + 32)
                        local nn_hi = safe_rd(addr + 36)
                        if nn_lo and ((nn_hi == 0 and nn_lo == 0) or is_dyn_tag(nn_lo, nn_hi)) then
                            dyn_found = addr
                            print("  FOUND at " .. fmt_hex(addr) .. " (text end)")
                            break
                        end
                    end
                end
            end
            if dyn_found then break end
        end
    end
end

if not dyn_found then
    print("  NOT FOUND in any eboot region")

    -- dump first 64 qwords of each RW region as hex for manual inspection
    print("")
    print("[C-ALT] Hex dump of data region starts:")
    for _, r in ipairs(regions) do
        if r.p == 3 then
            print("  --- " .. fmt_hex(r.s) .. " ---")
            for off = 0, 0xF8, 8 do
                local q = safe_rq(r.s + off)
                if q then
                    print(string.format("  +0x%02X: %s", off, fmt_hex(q)))
                end
            end
        end
    end

    -- also dump rodata start
    for _, r in ipairs(regions) do
        if r.p == 1 then
            print("  --- rodata " .. fmt_hex(r.s) .. " ---")
            for off = 0, 0x78, 8 do
                local q = safe_rq(r.s + off)
                if q then
                    print(string.format("  +0x%02X: %s", off, fmt_hex(q)))
                end
            end
        end
    end
else
    -- walk backward to find start
    for back = 1, 300 do
        local prev = dyn_found - uint64(16)
        local t_lo = safe_rd(prev)
        local t_hi = safe_rd(prev + 4)
        if not t_lo then break end
        if t_hi == 0 and t_lo == 0 then break end
        if is_dyn_tag(t_lo, t_hi) then
            dyn_found = prev
        else
            break
        end
    end

    print("")
    print("[D] .dynamic at " .. fmt_hex(dyn_found))

    local dt_strtab = nil
    local dt_strsz = 0
    local sce_strtab = nil
    local sce_strsz = 0

    for i = 0, 199 do
        local tag = safe_rq(dyn_found + i * 16)
        local val = safe_rq(dyn_found + i * 16 + 8)
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

        local test = safe_rd(strtab)
        if not test then
            strtab = text_addr + strtab
            test = safe_rd(strtab)
            if test then print("  (base-relative)") end
        end

        if test then
            local pos = 0
            local count = 0
            local max_read = math.min(strsz, 2048)
            if max_read == 0 then max_read = 1024 end

            while pos < max_read and count < 25 do
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
end

print("")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 516a COMPLETE ===")
