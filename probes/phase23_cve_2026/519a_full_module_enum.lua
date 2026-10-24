-- CRASH_CLASS: LOW
-- PROBE 519a: enumerate ALL loaded modules + deep data scan
--
-- 518a only found 6 modules with handles 0-40, but 39 exist.
-- PS5 uses sparse handle allocation. Scan 0-512 to find them all,
-- especially libkernel which is most likely to have kernel data.
-- Then scan each module's data region for real kernel pointers
-- (0xFFFF8xxx pattern, NOT 0xFFFFFFFF sentinels).

print("=== PROBE 519a: full module enum ===")

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

-- ============================================================
-- [A] Enumerate ALL modules (handles 0-512)
-- ============================================================
print("")
print("[A] Module enumeration (handles 0-512)")

local modules = {}
local mod_info = memory.alloc(0x200)

for h = 0, 512 do
    -- clear struct
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
                local mr = safe_rq(mod_info + 0x128)

                -- extract sizes from packed fields
                local tsz_raw = safe_rq(mod_info + 0x110)
                local dsz_raw = safe_rq(mod_info + 0x120)
                local tsz = 0
                local dsz = 0
                if tsz_raw then
                    local th2, tl2 = get_hi_lo(tsz_raw)
                    tsz = tl2  -- low 32 bits = size
                end
                if dsz_raw then
                    local dh2, dl2 = get_hi_lo(dsz_raw)
                    dsz = dl2
                end

                table.insert(modules, {
                    handle = h, text = mt, data = md, rodata = mr,
                    name = name, tsz = tsz, dsz = dsz
                })
            end
        end
    end

    -- progress every 128 handles
    if h > 0 and h % 128 == 0 then
        print("  ...handle " .. h .. " found=" .. #modules)
    end
end

print("  total modules: " .. #modules)
print("")

-- print all modules sorted by handle
for i, m in ipairs(modules) do
    local data_str = m.data and fmt_hex(m.data) or "nil"
    print(string.format("  [h=%d] %s tsz=0x%X dsz=0x%X \"%s\"",
        m.handle, fmt_hex(m.text), m.tsz, m.dsz, m.name))
end

-- ============================================================
-- [B] Deep scan: read data regions looking for real kernel pointers
-- Real kernel pointer: hi >= 0xFFFF8000 AND hi < 0xFFFFFFFF
-- (exclude 0xFFFFFFFF which is sentinel/bitmask)
-- ============================================================
print("")
print("[B] Kernel pointer scan (all module data)")

local kptr_total = 0

for _, m in ipairs(modules) do
    if m.data then
        local dh, dl = get_hi_lo(m.data)
        if dl > 0 then
            local scan_sz = math.min(m.dsz > 0 and m.dsz or 0x10000, 0x40000)
            local mod_kptrs = 0

            for off = 0, scan_sz - 8, 8 do
                local q = safe_rq(m.data + off)
                if not q then break end

                local qh, ql = get_hi_lo(q)
                -- real kernel pointer: high word in kernel range but NOT sentinel
                if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                    mod_kptrs = mod_kptrs + 1
                    kptr_total = kptr_total + 1
                    if mod_kptrs <= 5 then
                        print(string.format("  KPTR h=%d +0x%X: %s \"%s\"",
                            m.handle, off, fmt_hex(q), m.name))
                    end
                end
            end

            if mod_kptrs > 5 then
                print(string.format("  ... +%d more in \"%s\"", mod_kptrs - 5, m.name))
            end
        end
    end
end

if kptr_total == 0 then
    print("  ZERO real kernel pointers across all module data")
end

-- ============================================================
-- [C] Special check: libkernel if found
-- Look for "libkernel" in module names and scan its full data
-- ============================================================
print("")
print("[C] libkernel check")

local libkernel = nil
for _, m in ipairs(modules) do
    if m.name:find("libkernel") or m.name:find("Kernel") then
        libkernel = m
        break
    end
end

if libkernel then
    print("  FOUND: h=" .. libkernel.handle .. " \"" .. libkernel.name .. "\"")
    print("  text=" .. fmt_hex(libkernel.text) .. " data=" .. fmt_hex(libkernel.data))

    -- dump first 256 bytes of libkernel data
    if libkernel.data then
        print("  data region dump:")
        for off = 0, 0xF8, 8 do
            local q = safe_rq(libkernel.data + off)
            if q then
                local qh, ql = get_hi_lo(q)
                local tag = ""
                if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then tag = " *** KPTR ***" end
                if qh == 0xFFFFFFFF then tag = " [sentinel]" end
                print(string.format("    +0x%02X: %s%s", off, fmt_hex(q), tag))
            else
                print(string.format("    +0x%02X: UNREADABLE", off))
                break
            end
        end
    end
else
    print("  NOT FOUND in handles 0-512")
    -- list modules with "lib" in name
    print("  modules containing 'lib':")
    for _, m in ipairs(modules) do
        if m.name:find("lib") then
            print("    h=" .. m.handle .. " \"" .. m.name .. "\"")
        end
    end
end

-- ============================================================
-- [D] Check for interesting module data patterns
-- Look for modules with writable data that's NOT all zeros
-- ============================================================
print("")
print("[D] Module data activity check")

for _, m in ipairs(modules) do
    if m.data then
        local dh, dl = get_hi_lo(m.data)
        if dl > 0 then
            local nonzero = 0
            local sample_sz = math.min(m.dsz > 0 and m.dsz or 0x1000, 0x1000)
            for off = 0, sample_sz - 8, 8 do
                local q = safe_rq(m.data + off)
                if not q then break end
                local qh, ql = get_hi_lo(q)
                if qh ~= 0 or ql ~= 0 then
                    nonzero = nonzero + 1
                end
            end
            if nonzero > 0 then
                print(string.format("  h=%d nonzero=%d/%d \"%s\"",
                    m.handle, nonzero, sample_sz / 8, m.name))
            end
        end
    end
end

print("")
local pid2 = to_num(sc20())
print("pid: " .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("")
print("=== PROBE 519a COMPLETE ===")
