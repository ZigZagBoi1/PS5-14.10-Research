-- CRASH_CLASS: LOW
-- PROBE 530l: Minimal GOT finder + doorbell search
--
-- Previous probes had output corruption. This one uses ONLY
-- string.format for ALL output (no raw data ever printed).

print("=== PROBE 530l: MINIMAL GOT ===")
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
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sc_593 = mk(593)
local PAGE = 0x4000

local function get_mod_info(handle)
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    pcall(function() sc_593(uint64(handle), ib) end)
    local tl = rd(N(ib) + 0x108) or 0
    local th = rd(N(ib) + 0x10C) or 0
    if tl < 0 then tl = tl + 0x100000000 end
    if th < 0 then th = th + 0x100000000 end
    local ts = rd(N(ib) + 0x110) or 0
    if ts < 0 then ts = ts + 0x100000000 end
    local dl = rd(N(ib) + 0x120) or 0
    local dh = rd(N(ib) + 0x124) or 0
    if dl < 0 then dl = dl + 0x100000000 end
    if dh < 0 then dh = dh + 0x100000000 end
    return th, tl, ts, dh, dl
end

local eb_th, eb_tl, eb_ts, eb_dh, eb_dl = get_mod_info(0)
local gn_th, gn_tl, gn_ts = get_mod_info(56)

print(string.format("eboot text=0x%X%08X size=0x%X", eb_th, eb_tl, eb_ts))
print(string.format("eboot data=0x%X%08X", eb_dh, eb_dl))
print(string.format("gnm   text=0x%X%08X size=0x%X", gn_th, gn_tl, gn_ts))

local eb_base = eb_th * 0x100000000 + eb_tl
local eb_end = eb_base + eb_ts
local gn_base = gn_th * 0x100000000 + gn_tl
local gn_end = gn_base + gn_ts
local eb_data = eb_dh * 0x100000000 + eb_dl

-- ============================================================
-- [A] Scan pages after eboot .text for GnmDriver pointers
-- ============================================================
print("")
print("[A] Scanning after eboot .text")

local got_entries = {}
local readable_pages = 0
local fault_pages = 0

for page = 0, 63 do
    local paddr = eb_end + page * PAGE
    local test = rq(paddr)
    if test == nil then
        fault_pages = fault_pages + 1
    else
        readable_pages = readable_pages + 1
        for off = 0, PAGE - 8, 8 do
            local v = rq(paddr + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh < 0 then vh = vh + 0x100000000 end
                if vl < 0 then vl = vl + 0x100000000 end
                if vh == gn_th and vl >= gn_tl and vl < gn_tl + gn_ts then
                    table.insert(got_entries, {
                        addr = paddr + off,
                        page = page,
                        page_off = off,
                        gnm_off = vl - gn_tl
                    })
                end
            end
        end
    end
end

print(string.format("  readable=%d fault=%d gnm_GOT=%d", readable_pages, fault_pages, #got_entries))

for i, g in ipairs(got_entries) do
    if i > 25 then
        print(string.format("  ... +%d more", #got_entries - 25))
        break
    end
    print(string.format("  page%d+0x%04X -> gnm+0x%04X", g.page, g.page_off, g.gnm_off))
end

-- ============================================================
-- [B] Scan eboot .data region for gnm pointers (1 MB)
-- ============================================================
print("")
print("[B] eboot .data scan")

local data_test = rq(eb_data)
if data_test == nil then
    print("  .data FAULT at base")
    -- Try probing pages
    local first_ok = -1
    for p2 = 0, 255 do
        local t2 = rq(eb_data + p2 * PAGE)
        if t2 ~= nil then
            first_ok = p2
            break
        end
    end
    if first_ok >= 0 then
        print(string.format("  first readable at .data+0x%X (page %d)", first_ok * PAGE, first_ok))
    else
        print("  .data fully inaccessible (256 pages)")
    end
else
    print("  .data readable at base")
    local gnm_in_data = 0
    for off = 0, 0x100000 - 8, 8 do
        local v = rq(eb_data + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vl < 0 then vl = vl + 0x100000000 end
            if vh == gn_th and vl >= gn_tl and vl < gn_tl + gn_ts then
                gnm_in_data = gnm_in_data + 1
                if gnm_in_data <= 10 then
                    print(string.format("  .data+0x%06X -> gnm+0x%04X", off, vl - gn_tl))
                end
            end
        end
    end
    print(string.format("  gnm ptrs in .data: %d", gnm_in_data))
end

-- ============================================================
-- [C] GnmDriver .data: find doorbell-like pointers
-- ============================================================
print("")
print("[C] GnmDriver .data pointers")

local sc_649 = mk(649)
local dtb = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(3), uint64(dtb)) end)
local gnm_data_q = rq(N(dtb))
local gdn = N(gnm_data_q)
print(string.format("  gnm .data=%s", hexq(gnm_data_q)))

local ptr_list = {}
for off = 0, 0x1000 - 8, 8 do
    local v = rq(gdn + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if (vh ~= 0 or vl ~= 0) and
           (vh < 0xFFFF4000 or vh > 0xFFFF5000) and
           not (vh == gn_th and vl >= gn_tl and vl < gn_tl + gn_ts) then
            local ptr = vh * 0x100000000 + vl
            local test = rd(ptr)
            local readable = (test ~= nil)
            local val = 0
            if readable then
                val = test
                if val < 0 then val = val + 0x100000000 end
            end
            table.insert(ptr_list, {off = off, vh = vh, vl = vl, r = readable, val = val})
        end
    end
end

print(string.format("  non-NID non-text entries: %d", #ptr_list))
for _, p in ipairs(ptr_list) do
    local tag = p.r and string.format("val=0x%08X", p.val) or "FAULT"
    print(string.format("  +0x%03X 0x%08X%08X [%s]", p.off, p.vh, p.vl, tag))
end

-- ============================================================
-- [D] Small integers in GnmDriver .data
-- ============================================================
print("")
print("[D] Small ints in gnm .data")
local small_ints = {}
for off = 0, 0x800 - 4, 4 do
    local d = rd(gdn + off)
    if d then
        if d < 0 then d = d + 0x100000000 end
        if d > 0 and d < 0x100000 then
            table.insert(small_ints, {off = off, val = d})
        end
    end
end
for _, s in ipairs(small_ints) do
    print(string.format("  +0x%03X: %d (0x%X)", s.off, s.val, s.val))
end

print("")
print("=== 530l DONE ===")
