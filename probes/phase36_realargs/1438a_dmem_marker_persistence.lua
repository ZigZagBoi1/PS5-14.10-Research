-- CRASH_CLASS: LOW
-- PROBE 1438a: did the 1397j markers survive the process that wrote them?
--
-- 1397j (results/phase36_realargs/1397j_dmem_page0_write_20261109_143351.txt)
-- stored 0xAAAA5555 / 0x11112222 at window offset 0xBF0 and 0xBBBB6666 at
-- 0x16F00, and read both back 500 ms later and through a second mapping.
-- The loader process that made those stores is long dead -- pid 350 -> 357 ->
-- 364 -> 371 -> 378 -> 383 -> 402 -> ... -- so this probe only maps the window
-- and reads, with no write of its own.
--
--   markers still there  -> the window is backed by memory that outlives the
--                           process: a persistent, system-visible GPU write
--   markers zeroed       -> the container is rebuilt per process and 1397j's
--                           stores were private to the process that made them
--
-- Prior art:
--   1397j results/phase36_realargs/1397j_dmem_page0_write_20261109_143351.txt
--   1397i results/phase36_realargs/1397i_dmem_block_checksum_20261109_143254.txt
--   1397g results/phase36_realargs/1397g_dmem_f000_dump_20261109_143115.txt
--   docs/DMEM_WINDOW_14_10.md

print("=== PROBE 1438a: DMEM MARKER PERSISTENCE ===")
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
local function rd(p) return to_num(memory.read_dword(p)) end
local function rq(p) return to_num(memory.read_qword(p)) end
local function str_addr(s)
    local p = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(p + i - 1, string.byte(s, i)) end
    memory.write_byte(p + #s, 0)
    return p
end

local fd = to_num(sc(5)(uint64(str_addr("/dev/dmem0")), uint64(0x4002), uint64(0)))
print(string.format("open(/dev/dmem0) -> %d (%s)", fd, es()))

local function map(off, len)
    local ok, r = pcall(function()
        return sc(477)(uint64(0), uint64(len), uint64(3), uint64(1),
            uint64(fd), uint64(off))
    end)
    if not ok then return nil end
    local v = to_num(r)
    if v < 0x10000 or v > 0x8000000000 then return nil end
    return v
end

local va = map(0, 0x20000)
print(string.format("mmap(off 0, len 0x20000) -> %s", va and string.format("%#x", va) or "FAILED"))
if not va then
    print("cannot map the window; nothing to test")
    print("")
    print("=== PROBE 1438a COMPLETE ===")
    return
end

local function show(label, off)
    local p = va + off
    print(string.format("  %-22s off %#08x : %08X %08X", label, off, rd(p), rd(p + 4)))
end

print("[A] the 1397j write sites")
show("page0 +0xBF0", 0xBF0)
show("page0x16 +0xF00", 0x16F00)
print("")

print("[B] context: the static header that was identical in 1397g")
show("ONION header 0xF000", 0xF000)
show("ONION header 0xF010", 0xF010)
local va2 = map(0, 0x20000)
print(string.format("  second mapping            : %s", va2 and string.format("%#x", va2) or "FAILED"))
if va2 then
    print(string.format("  page0x16 +0xF00 via map2  : %08X", rd(va2 + 0x16F00)))
    print(string.format("  identical mapping         : %s",
        (rq(va + 0xBF0) == rq(va2 + 0xBF0)) and "yes" or "no"))
end
print("")

print("[C] a page that was never written by any probe")
show("page0x12 +0x100", 0x12100)
show("page0x15 +0x800", 0x15800)

print("")
print("=== PROBE 1438a COMPLETE ===")
