-- CRASH_CLASS: LOW
-- PROBE 530m: Fast GOT finder — minimal memory reads
--
-- 530k/530l: output corruption from reading too many qwords.
-- This probe reads ONLY sampled qwords to find the GOT region fast.

print("=== PROBE 530m ===")

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

local sc_593 = mk(593)

local function get_mod(h)
    local ib = memory.alloc(0x200)
    wd(N(ib), 0x160)
    pcall(function() sc_593(uint64(h), ib) end)
    local tl = rd(N(ib) + 0x108) or 0
    local th = rd(N(ib) + 0x10C) or 0
    if tl < 0 then tl = tl + 0x100000000 end
    if th < 0 then th = th + 0x100000000 end
    local ts = rd(N(ib) + 0x110) or 0
    if ts < 0 then ts = ts + 0x100000000 end
    return th, tl, ts
end

local eb_th, eb_tl, eb_ts = get_mod(0)
local gn_th, gn_tl, gn_ts = get_mod(56)
local eb_end = eb_th * 0x100000000 + eb_tl + eb_ts

print(string.format("eb_end=0x%X%08X gnm=0x%X%08X+0x%X", eb_th, eb_tl + eb_ts, gn_th, gn_tl, gn_ts))

-- [A] Quick page probe — which pages after .text are readable?
print("")
print("[A] Page probe")
local page_status = {}
for p = 0, 127 do
    local addr = eb_end + p * 0x4000
    local v = rq(addr)
    if v then
        page_status[p] = true
    end
end

local readable = {}
for p = 0, 127 do
    if page_status[p] then table.insert(readable, p) end
end
print(string.format("readable pages: %d of 128", #readable))
if #readable > 0 then
    -- Print ranges
    local ranges = {}
    local rstart = readable[1]
    local rend = readable[1]
    for i = 2, #readable do
        if readable[i] == rend + 1 then
            rend = readable[i]
        else
            table.insert(ranges, {rstart, rend})
            rstart = readable[i]
            rend = readable[i]
        end
    end
    table.insert(ranges, {rstart, rend})
    for _, r in ipairs(ranges) do
        print(string.format("  pages %d-%d (0x%X - 0x%X)", r[1], r[2],
            eb_end + r[1] * 0x4000, eb_end + (r[2] + 1) * 0x4000))
    end
end

-- [B] For each readable page, sample first qword to classify
print("")
print("[B] Page classification")
for _, p in ipairs(readable) do
    if p > 95 then break end  -- limit output
    local addr = eb_end + p * 0x4000
    local v = rq(addr)
    local vh, vl = get_hi_lo(v)
    if vh < 0 then vh = vh + 0x100000000 end
    if vl < 0 then vl = vl + 0x100000000 end

    local tag = "data"
    if vh == 0 and vl == 0 then tag = "zero"
    elseif vh >= 0xFFFF0000 then tag = "NID?"
    elseif vh == gn_th then tag = "GNM_PTR!"
    elseif vh == eb_th then tag = "EBOOT_PTR"
    elseif vh >= 1 and vh <= 0x20 then tag = "UPTR"
    end

    -- Count gnm pointers in this page (sample every 64 bytes)
    local gnm_hits = 0
    for off = 0, 0x4000 - 8, 64 do
        local sv = rq(addr + off)
        if sv then
            local svh, svl = get_hi_lo(sv)
            if svh < 0 then svh = svh + 0x100000000 end
            if svl < 0 then svl = svl + 0x100000000 end
            if svh == gn_th and svl >= gn_tl and svl < gn_tl + gn_ts then
                gnm_hits = gnm_hits + 1
            end
        end
    end

    if gnm_hits > 0 or tag ~= "zero" then
        print(string.format("  p%d: [0]=%s gnm_sampled=%d", p, tag, gnm_hits))
    end
end

-- [C] If any page has gnm hits, scan it fully
print("")
print("[C] Full scan of GOT pages")
local total_gnm = 0
for _, p in ipairs(readable) do
    local addr = eb_end + p * 0x4000
    -- Quick check with sampling first
    local has_gnm = false
    for off = 0, 0x4000 - 8, 64 do
        local sv = rq(addr + off)
        if sv then
            local svh = get_hi_lo(sv)
            if svh < 0 then svh = svh + 0x100000000 end
            if svh == gn_th then has_gnm = true; break end
        end
    end

    if has_gnm then
        -- Full scan this page
        for off = 0, 0x4000 - 8, 8 do
            local sv = rq(addr + off)
            if sv then
                local svh, svl = get_hi_lo(sv)
                if svh < 0 then svh = svh + 0x100000000 end
                if svl < 0 then svl = svl + 0x100000000 end
                if svh == gn_th and svl >= gn_tl and svl < gn_tl + gn_ts then
                    total_gnm = total_gnm + 1
                    if total_gnm <= 20 then
                        print(string.format("  GOT p%d+0x%04X -> gnm+0x%04X", p, off, svl - gn_tl))
                    end
                end
            end
        end
    end
end
print(string.format("total gnm GOT entries: %d", total_gnm))

-- [D] GnmDriver .data doorbell
print("")
print("[D] gnm .data ptrs")
local sc_649 = mk(649)
local dtb = memory.alloc(8)
pcall(function() sc_649(uint64(56), uint64(3), uint64(dtb)) end)
local gdn = N(rq(N(dtb)))

for off = 0, 0x800 - 8, 8 do
    local v = rq(gdn + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vl < 0 then vl = vl + 0x100000000 end
        if (vh ~= 0 or vl ~= 0) and
           (vh < 0xFFFF4000 or vh > 0xFFFF5000) and
           not (vh == gn_th and vl >= gn_tl) then
            local ptr = vh * 0x100000000 + vl
            local t2 = rd(ptr)
            local rtag = "F"
            if t2 ~= nil then
                if t2 < 0 then t2 = t2 + 0x100000000 end
                rtag = string.format("0x%X", t2)
            end
            print(string.format("  +0x%03X: 0x%X%08X [%s]", off, vh, vl, rtag))
        end
    end
end

print("")
print("=== DONE ===")
