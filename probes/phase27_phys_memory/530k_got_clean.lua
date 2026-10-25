-- CRASH_CLASS: LOW
-- PROBE 530k: Find eboot GOT (clean, no byte-scan)
--
-- 530i: .data at 0x300180000 had 0 gnm pointers.
-- 530j: truncated output from heavy scan.
--
-- Simple approach: scan 16 pages after eboot .text end for qwords
-- that point into any loaded module's text range.

print("=== PROBE 530k: GOT CLEAN ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc_593 = mk(593)
local PAGE = 0x4000

local function get_mod(handle)
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    pcall(function() sc_593(uint64(handle), ib) end)
    local tl = rd(N(ib) + 0x108) or 0
    local th = rd(N(ib) + 0x10C) or 0
    if tl < 0 then tl = tl + 0x100000000 end
    if th < 0 then th = th + 0x100000000 end
    local ts = rd(N(ib) + 0x110) or 0
    if ts < 0 then ts = ts + 0x100000000 end
    return { text_hi = th, text_lo = tl, text_size = ts,
             text_base = th * 0x100000000 + tl }
end

-- Build module table
local modules = {}
local mod_handles = {0, 0x2001}
-- Scan for more handles
for h = 1, 100 do
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    local ok = pcall(function() sc_593(uint64(h), ib) end)
    local tl = rd(N(ib) + 0x108)
    if tl and tl ~= 0 then
        table.insert(mod_handles, h)
    end
end

for _, h in ipairs(mod_handles) do
    local m = get_mod(h)
    if m.text_size > 0 then
        table.insert(modules, {h = h, text_hi = m.text_hi, text_lo = m.text_lo,
                                text_size = m.text_size, text_base = m.text_base})
    end
end
print(string.format("loaded %d modules", #modules))

local eboot = get_mod(0)
local gnm = get_mod(56)
print(string.format("eboot text=0x%X+0x%X", eboot.text_base, eboot.text_size))
print(string.format("gnm   text=0x%X+0x%X", gnm.text_base, gnm.text_size))

-- ============================================================
-- [A] Scan 16 pages (256 KB) after eboot .text end
-- ============================================================
print("")
print("[A] After eboot .text")

local eboot_end = eboot.text_base + eboot.text_size
local gnm_count = 0
local any_module_count = 0

for page = 0, 15 do
    local paddr = eboot_end + page * PAGE
    local first = rq(paddr)
    if first == nil then
        print(string.format("  page %d (text_end+0x%X): FAULT", page, page * PAGE))
    else
        local gnm_in_page = 0
        local mod_in_page = 0
        for off = 0, PAGE - 8, 8 do
            local v = rq(paddr + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                -- Check if it points to GnmDriver
                if vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm.text_lo + gnm.text_size then
                    gnm_in_page = gnm_in_page + 1
                    gnm_count = gnm_count + 1
                    if gnm_count <= 20 then
                        print(string.format("  *** GOT: text_end+0x%05X -> gnm+0x%04X",
                            page * PAGE + off, vl - gnm.text_lo))
                    end
                end
                -- Check any module
                for _, m in ipairs(modules) do
                    if vh == m.text_hi and vl >= m.text_lo and vl < m.text_lo + m.text_size then
                        mod_in_page = mod_in_page + 1
                        break
                    end
                end
            end
        end
        if mod_in_page > 0 or gnm_in_page > 0 then
            print(string.format("  page %d (text_end+0x%X): %d gnm, %d any_module",
                page, page * PAGE, gnm_in_page, mod_in_page))
        end
        any_module_count = any_module_count + mod_in_page
    end
end

print(string.format("  TOTAL: %d gnm GOT entries, %d any-module entries", gnm_count, any_module_count))

-- ============================================================
-- [B] If still 0, try the .data region but with a wider scan
-- The .data at 0x300180000 - scan first 1 MB
-- ============================================================
if gnm_count == 0 then
    print("")
    print("[B] Wider .data scan (1 MB)")

    local data_base = eboot.text_hi * 0x100000000 + rd(get_mod(0).text_lo) -- wrong, recalc
    -- Actually get .data properly
    local eib = memory.alloc(0x200)
    wd(N(eib), 0x160)
    pcall(function() sc_593(uint64(0), eib) end)
    local dl = rd(N(eib) + 0x120) or 0
    local dh = rd(N(eib) + 0x124) or 0
    if dl < 0 then dl = dl + 0x100000000 end
    if dh < 0 then dh = dh + 0x100000000 end
    local data_addr = dh * 0x100000000 + dl

    print(string.format("  .data at 0x%X%08X", dh, dl))

    -- Check if readable
    local test = rq(data_addr)
    if test == nil then
        print("  .data FAULT — trying pages around it")
        -- Try reading at known offsets
        for off = 0, 0x100000, PAGE do
            local t2 = rq(data_addr + off)
            if t2 then
                print(string.format("  readable at .data+0x%X", off))
                break
            end
        end
    else
        local gnm_d = 0
        for off = 0, 0x100000 - 8, 0x8 do
            local v = rq(data_addr + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                if vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm.text_lo + gnm.text_size then
                    gnm_d = gnm_d + 1
                    if gnm_d <= 10 then
                        print(string.format("  .data+0x%06X -> gnm+0x%04X", off, vl - gnm.text_lo))
                    end
                end
            end
        end
        print(string.format("  gnm ptrs in 1 MB .data: %d", gnm_d))
    end
end

-- ============================================================
-- [C] Check the GnmDriver .data for a DOORBELL pointer
-- Look for readable pointers, and try writing to them
-- ============================================================
print("")
print("[C] GnmDriver .data doorbell search")

local sc_649 = mk(649)
local dtb = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(3), uint64(dtb)) end)
local gnm_data = rq(N(dtb))
local gdn = N(gnm_data)

-- Collect all readable non-NID pointers
local ptrs = {}
for off = 0, 0x1000 - 8, 8 do
    local v = rq(gdn + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        -- Skip zero, NID range, gnm text
        if (vh ~= 0 or vl ~= 0) and
           (vh < 0xFFFF4000 or vh > 0xFFFF5000) and
           not (vh == gnm.text_hi and vl >= gnm.text_lo and vl < gnm.text_lo + gnm.text_size) then
            local ptr = vh * 0x100000000 + vl
            local test = rd(ptr)
            if test ~= nil then
                if test < 0 then test = test + 0x100000000 end
                table.insert(ptrs, {off = off, vh = vh, vl = vl, val = test})
            end
        end
    end
end

print(string.format("  readable non-NID pointers: %d", #ptrs))
for _, p in ipairs(ptrs) do
    print(string.format("  .data+0x%03X: ptr=0x%08X%08X -> [0]=0x%08X", p.off, p.vh, p.vl, p.val))
    -- Read a few more dwords at the target
    local vals = {}
    for i = 1, 3 do
        local d = rd(p.vh * 0x100000000 + p.vl + i * 4)
        if d then
            if d < 0 then d = d + 0x100000000 end
            table.insert(vals, string.format("0x%X", d))
        end
    end
    if #vals > 0 then
        print(string.format("           -> [4..12]: %s", table.concat(vals, " ")))
    end
end

-- ============================================================
-- [D] Check non-zero dwords in GnmDriver .data that could be
-- doorbell offsets or GPU register offsets (small integers)
-- ============================================================
print("")
print("[D] GnmDriver .data small integers")
for off = 0, 0x400 - 4, 4 do
    local d = rd(gdn + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        if d > 0 and d < 0x10000 then  -- small positive integer
            print(string.format("  .data+0x%03X: %d (0x%X)", off, d, d))
        end
    end
end

print("")
print("=== 530k DONE ===")
