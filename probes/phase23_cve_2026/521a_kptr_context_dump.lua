-- CRASH_CLASS: LOW
-- PROBE 521a: context dump around "kernel pointer" values
--
-- 520a found 5081 values matching 0xFFFF8xxx in module data.
-- The arithmetic progression (+0x30 hi, +0x14 lo) and 7+ TB range
-- suggest these may NOT be kernel pointers but Sony import tables
-- or encoded metadata.
--
-- This probe dumps CONTEXT around the values to identify the
-- actual data structure:
-- [A] Full hex dump of first 512 bytes of one module's data
-- [B] Stride analysis: are "kptrs" at regular intervals?
-- [C] Structure identification: what's adjacent to each "kptr"?
-- [D] Compare "kptr" high bits vs module handle (correlation?)
-- [E] Check if values differ between two modules (same pattern?)
-- [F] Stability: re-derive same values to confirm they're static

print("=== PROBE 521a: kptr context dump ===")
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

local pid = to_num(sc20())
print("pid: " .. pid)

-- get a few modules for comparison
local mod_info = memory.alloc(0x200)
local function get_mod(h)
    for j = 0, 0x15C, 4 do safe_wd(mod_info + j, 0) end
    safe_wd(mod_info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), mod_info) end)
    if ok and to_num(ret) == 0 then
        local mt = safe_rq(mod_info + 0x108)
        local md = safe_rq(mod_info + 0x118)
        local dsz_raw = safe_rq(mod_info + 0x120)
        local dsz = 0
        if dsz_raw then
            local _, dl = get_hi_lo(dsz_raw)
            dsz = dl
        end
        local name = read_str(mod_info + 8, 48)
        return {handle = h, text = mt, data = md, name = name, dsz = dsz}
    end
    return nil
end

-- pick 3 modules: small (h=2), medium (h=49), large (h=159)
local m2 = get_mod(2)
local m49 = get_mod(49)
local m159 = get_mod(159)
print("")
if m2 then print("mod2: h=2 \"" .. m2.name .. "\" data=" .. fmt_hex(m2.data) .. " dsz=0x" .. string.format("%X", m2.dsz)) end
if m49 then print("mod49: h=49 \"" .. m49.name .. "\" data=" .. fmt_hex(m49.data) .. " dsz=0x" .. string.format("%X", m49.dsz)) end
if m159 then print("mod159: h=159 \"" .. m159.name .. "\" data=" .. fmt_hex(m159.data) .. " dsz=0x" .. string.format("%X", m159.dsz)) end
print("")

-- ============================================================
-- [A] Full hex dump: first 512 bytes of h=2 data
-- Mark "kptr" qwords with ***
-- ============================================================
print("[A] Hex dump: h=2 first 512B data")
if m2 and m2.data then
    for off = 0, 0x1F8, 8 do
        local q = safe_rq(m2.data + off)
        if not q then
            print(string.format("  +0x%03X: UNREADABLE", off))
            break
        end
        local qh, ql = get_hi_lo(q)
        local tag = ""
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then tag = " ***KPTR***" end
        if qh == 0xFFFFFFFF then tag = " [sentinel]" end
        if qh == 0 and ql == 0 then tag = " [zero]" end
        print(string.format("  +0x%03X: 0x%08X_%08X%s", off, qh, ql, tag))
    end
end
print("")

-- ============================================================
-- [B] Stride analysis: find first 20 "kptrs" and compute strides
-- ============================================================
print("[B] Stride analysis (h=2)")
if m2 and m2.data then
    local kptr_offsets = {}
    local scan_sz = math.min(m2.dsz > 0 and m2.dsz or 0x10000, 0x20000)

    for off = 0, scan_sz - 8, 8 do
        local q = safe_rq(m2.data + off)
        if not q then break end
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
            table.insert(kptr_offsets, off)
            if #kptr_offsets >= 20 then break end
        end
    end

    print("  first 20 kptr offsets:")
    local strides = {}
    for i, off in ipairs(kptr_offsets) do
        local stride_str = ""
        if i > 1 then
            local s = off - kptr_offsets[i - 1]
            stride_str = string.format(" stride=%d(0x%X)", s, s)
            strides[s] = (strides[s] or 0) + 1
        end
        -- read the kptr value too
        local q = safe_rq(m2.data + off)
        local qh, ql = get_hi_lo(q)
        print(string.format("    [%2d] +0x%04X: 0x%08X_%08X%s",
            i, off, qh, ql, stride_str))
    end

    print("  stride distribution:")
    for s, cnt in pairs(strides) do
        print(string.format("    stride=0x%X: %d times", s, cnt))
    end
end
print("")

-- ============================================================
-- [C] Context around first kptr: 64 bytes before + 64 after
-- This reveals the enclosing structure
-- ============================================================
print("[C] Context around first kptr (h=2)")
if m2 and m2.data then
    -- find first kptr
    local first_off = nil
    local scan_sz = math.min(m2.dsz > 0 and m2.dsz or 0x10000, 0x20000)
    for off = 0, scan_sz - 8, 8 do
        local q = safe_rq(m2.data + off)
        if not q then break end
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
            first_off = off
            break
        end
    end

    if first_off then
        print("  first kptr at +0x" .. string.format("%04X", first_off))
        print("  context (-0x40 to +0x40):")

        local ctx_start = math.max(0, first_off - 0x40)
        local ctx_end = first_off + 0x40
        for off = ctx_start, ctx_end, 8 do
            local q = safe_rq(m2.data + off)
            if q then
                local qh, ql = get_hi_lo(q)
                local tag = ""
                if off == first_off then tag = " <<<KPTR>>>" end
                if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF and off ~= first_off then tag = " ***KPTR***" end
                if qh == 0 and ql == 0 then tag = " [zero]" end

                -- also show as two dwords for structure analysis
                local d0 = safe_rd(m2.data + off)
                local d1 = safe_rd(m2.data + off + 4)
                print(string.format("    +0x%04X: 0x%08X_%08X  (d0=0x%08X d1=0x%08X)%s",
                    off, qh, ql, d0 or 0, d1 or 0, tag))
            end
        end
    end
end
print("")

-- ============================================================
-- [D] Cross-module comparison: first 5 kptrs from 3 different modules
-- Check if high-bits correlate with module handle
-- ============================================================
print("[D] Cross-module kptr comparison")
local test_mods = {m2, m49, m159}
for _, m in ipairs(test_mods) do
    if m and m.data then
        print("  h=" .. m.handle .. " \"" .. m.name:sub(1, 25) .. "\":")
        local cnt = 0
        local scan_sz = math.min(m.dsz > 0 and m.dsz or 0x10000, 0x20000)
        for off = 0, scan_sz - 8, 8 do
            if cnt >= 5 then break end
            local q = safe_rq(m.data + off)
            if not q then break end
            local qh, ql = get_hi_lo(q)
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                cnt = cnt + 1
                -- decompose: hi_nibbles for pattern analysis
                local n4 = math.floor(qh / 0x10000) -- top 16 bits
                local n3 = qh % 0x10000              -- bottom 16 bits of hi
                print(string.format("    [%d] +0x%04X: hi=0x%04X_%04X lo=0x%08X",
                    cnt, off, n4, n3, ql))
            end
        end
    end
end
print("")

-- ============================================================
-- [E] Check eboot data region: does it have the same pattern?
-- (eboot had 0 kptrs in 519a — why?)
-- ============================================================
print("[E] Eboot (h=0) data: first 256B as qwords")
local m0 = get_mod(0)
if m0 and m0.data then
    for off = 0, 0xF8, 8 do
        local q = safe_rq(m0.data + off)
        if not q then break end
        local qh, ql = get_hi_lo(q)
        local tag = ""
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then tag = " ***KPTR***" end
        print(string.format("  +0x%02X: 0x%08X_%08X%s", off, qh, ql, tag))
    end
end
print("")

-- ============================================================
-- [F] Deeper structure: around kptr #10 in h=2 (skip first cluster)
-- ============================================================
print("[F] Deeper context: kptr #10 in h=2")
if m2 and m2.data then
    local cnt = 0
    local scan_sz = math.min(m2.dsz > 0 and m2.dsz or 0x10000, 0x20000)
    for off = 0, scan_sz - 8, 8 do
        local q = safe_rq(m2.data + off)
        if not q then break end
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
            cnt = cnt + 1
            if cnt == 10 then
                print("  kptr#10 at +0x" .. string.format("%04X", off))
                local ctx_start = math.max(0, off - 0x30)
                local ctx_end = off + 0x30
                for coff = ctx_start, ctx_end, 8 do
                    local cq = safe_rq(m2.data + coff)
                    if cq then
                        local ch, cl = get_hi_lo(cq)
                        local tag = ""
                        if coff == off then tag = " <<<KPTR>>>" end
                        if ch >= 0xFFFF8000 and ch < 0xFFFFFFFF and coff ~= off then tag = " ***KPTR***" end
                        print(string.format("    +0x%04X: 0x%08X_%08X%s", coff, ch, cl, tag))
                    end
                end
                break
            end
        end
    end
end
print("")

-- ============================================================
-- [G] Value decomposition: are the kptrs structured?
-- Split each value into components and look for patterns
-- ============================================================
print("[G] Value decomposition (first 15 kptrs h=2)")
if m2 and m2.data then
    local cnt = 0
    local scan_sz = math.min(m2.dsz > 0 and m2.dsz or 0x10000, 0x20000)
    local prev_hi = nil
    local prev_lo = nil

    for off = 0, scan_sz - 8, 8 do
        if cnt >= 15 then break end
        local q = safe_rq(m2.data + off)
        if not q then break end
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
            cnt = cnt + 1
            local delta_hi = prev_hi and string.format("%+d", qh - prev_hi) or "-"
            local delta_lo = prev_lo and string.format("%+d", ql - prev_lo) or "-"
            print(string.format("  [%2d] hi=0x%08X lo=0x%08X  dHi=%s dLo=%s",
                cnt, qh, ql, delta_hi, delta_lo))
            prev_hi = qh
            prev_lo = ql
        end
    end
end
print("")

-- ============================================================
-- [H] Check: do module text addresses overlap with kptr values?
-- If kptr hi bits match module text hi bits, they might be
-- encoded module references, not kernel pointers
-- ============================================================
print("[H] Module text vs kptr range overlap check")
-- enumerate all modules quickly and collect text high words
local text_his = {}
for h = 0, 512 do
    local m = get_mod(h)
    if m and m.text then
        local th, tl = get_hi_lo(m.text)
        text_his[th] = m.name:sub(1, 20)
    end
end

print("  module text high words:")
for th, name in pairs(text_his) do
    print(string.format("    0x%08X -> \"%s\"", th, name))
end
print("")

-- now check if any kptr high word matches a module text high word
print("  kptr high words from h=2 (first 10):")
if m2 and m2.data then
    local cnt = 0
    for off = 0, 0x10000 - 8, 8 do
        if cnt >= 10 then break end
        local q = safe_rq(m2.data + off)
        if not q then break end
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
            cnt = cnt + 1
            local match = text_his[qh] or "NO MATCH"
            print(string.format("    hi=0x%08X -> %s", qh, match))
        end
    end
end
print("")

local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 521a COMPLETE ===")
