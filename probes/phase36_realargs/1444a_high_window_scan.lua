-- CRASH_CLASS: MODERATE
-- PROBE 1444a: what is in the read-only window at 64 GiB?
--
-- 1412a and 1441a located a second /dev/dmem0 window starting at offset
-- 0x1000000000 (64 GiB): offsets 64 GiB + 0 and 64 GiB + 0x1000000 map, 64 GiB +
-- 0x2000000 refuses, so the region is somewhere between 16 and 32 MiB wide.  It
-- accepts only prot 0/1 and mprotect cannot escalate it, so it is read-only by
-- construction - unlike the 4 GiB window, which is our own container's GPU
-- memory and is writable.
--
-- A read-only window that the caller is allowed to see is unusual.  Either it is
-- a reserved/empty aperture, or it holds system GPU memory the ACL only lets us
-- observe - which would be the first cross-container read this project has.
-- 1412a read one page and found 255 of 256 dwords zero with a 2 at +0x120; that
-- is not enough to characterise a window.
--
-- This probe samples the region at a 256 KiB stride, prints the offset BEFORE
-- each read, and reports the non-zero dword count plus the first eight dwords.
-- A hole would fault, so a death here is itself a measurement (the last printed
-- offset is where the mapping stops backing pages).
--
-- Prior art:
--   1410a/1411a/1412a/1441a  results/phase36_realargs/
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1444a: THE 64 GiB READ-ONLY WINDOW ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function rd(p)
    local ok, v = pcall(function() return to_num(memory.read_dword(p)) end)
    if ok then return v end
    return nil
end
local function str_addr(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    memory.write_byte(p + #s, 0)
    return p
end

local m5, m477, m73 = sc(5), sc(477), sc(73)
local fd = to_num(m5(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0)))
print(string.format("open(/dev/dmem0) -> %d", fd))

local BASE = 0x1000000000

local function probe(off)
    local ok, r = pcall(function()
        return m477(uint64(0), uint64(0x1000), uint64(1), uint64(1),
            uint64(fd), uint64(off))
    end)
    local va = nil
    if ok then
        local v = to_num(r)
        if v >= 0x10000 and v <= 0x8000000000 then va = v end
    end
    if not va then
        print(string.format("  %#014x FAILED (%s)", off, es()))
        return nil
    end
    local nz, words = 0, {}
    for i = 0, 255 do
        local d = rd(va + i * 4)
        if d and d ~= 0 then
            nz = nz + 1
            if #words < 8 then
                words[#words + 1] = string.format("+%03X=%08X", i * 4, d)
            end
        end
    end
    local line = string.format("  %#014x nz=%3d", off, nz)
    if nz > 0 then line = line .. "  " .. table.concat(words, " ") end
    print(line)
    pcall(function() m73(uint64(va), uint64(0x1000)) end)
    return nz
end

print("[A] 0 .. 32 MiB at a 256 KiB stride")
local mapped, total_nz = 0, 0
for k = 0, 127 do
    local nz = probe(BASE + k * 0x40000)
    if nz then
        mapped = mapped + 1
        total_nz = total_nz + nz
    end
end
print(string.format("  mapped=%d of 128 samples, total non-zero dwords=%d", mapped, total_nz))
print("")

print("[B] page-by-page over the first 256 KiB")
for k = 0, 63 do probe(BASE + k * 0x1000) end
print("")

print("[C] full dword dump of the two pages 1412a/1441a named")
for _, off in ipairs({BASE, BASE + 0x1000000}) do
    local ok, r = pcall(function()
        return m477(uint64(0), uint64(0x1000), uint64(1), uint64(1), uint64(fd), uint64(off))
    end)
    local va = nil
    if ok then
        local v = to_num(r)
        if v >= 0x10000 and v <= 0x8000000000 then va = v end
    end
    if va then
        print(string.format("  page %#014x:", off))
        for row = 0, 15 do
            local t = {}
            for i = 0, 15 do
                t[i + 1] = string.format("%08X", rd(va + (row * 16 + i) * 4) or 0)
            end
            print(string.format("   +%03X  %s", row * 64, table.concat(t, " ")))
        end
        pcall(function() m73(uint64(va), uint64(0x1000)) end)
    else
        print(string.format("  page %#014x FAILED (%s)", off, es()))
    end
end
print("")

print("=== PROBE 1444a COMPLETE ===")
