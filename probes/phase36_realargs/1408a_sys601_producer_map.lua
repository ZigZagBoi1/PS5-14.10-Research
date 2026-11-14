-- CRASH_CLASS: HIGH
-- PROBE 1408a: 601 - producer map. For every surviving command, hand arg1 = a canary page
--              and arg2 = a canary page, and count what the command writes back into each.
--
-- prior art:
--   results/phase36_realargs/1403a_sys601_write_dest_map_20261109_152155.txt
--     shape A (arg1=0, arg2=OUT) for 22 commands: no command wrote to OUT; errno map
--     0x0A/0x0F/0x18=EPERM, 0x02/0x05/0x06/0x16/0x17=ENOSYS, 0x10/0x15=EINVAL,
--     0x07/0x09/0x0B/0x0D/0x13/0x14/0x19=0, 0x01/0x0E/0x1A=EFAULT, 0x12=ENOENT.
--     Its shape-B block is INVALID: it zeroed the first 0x20 bytes of the watched page and
--     then counted those 8 dwords as "changed", so its in_ch=8 means nothing and its
--     out_ch was never measured (it watched OUT only in shape A).
--   results/phase35_dead_end_reruns/1383a_*: 601(0x00, buf) writes 00000100 00000000 into
--     BUF, i.e. 0x00 writes to arg1, not to arg2.
--   results/phase36_realargs/1406a_sys601_cmd12_qword8_20261109_152629.txt
--     0x12 needs struct+0x08 non-zero (a canary page satisfies that) and then answers
--     ENOENT for every key, so a canary-filled arg1 gets 0x12 past its null gate.
--
-- Why: the 13.60 consumer of proc+0x578 does a 0x480-byte copyout to a caller buffer. If any
-- 14.10 command produces data at arg1 or arg2, that command is a copyout site and the
-- 0x480 region is where to look. A canary fill also means "every field non-zero", which is
-- the shape that gets past null gates without guessing field values.
--
-- Skipped, lethal or parking: 0x03 0x04 0x08 0x0C 0x11 0x1B 0x1C.
-- Watched window: 0x480 bytes (the 13.60 consumer's copyout length) from each pointer.

print("=== PROBE 1408a: 601 PRODUCER MAP ===")

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
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function safe_wd(a, v) local ok = pcall(function() memory.write_dword(a, v) end) return ok end
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return -1 end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

local sc601 = make_syscall(601)
local sc477 = make_syscall(477)
local sc20 = make_syscall(20)
print(string.format("[0] pid=%d", to_num(sc20(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function mmap(px)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local IN = mmap(0x8000)
local OUT = mmap(0x8000)
print(string.format("  in=0x%X out=0x%X", IN, OUT))
if IN == 0 or OUT == 0 then print("[!] mmap failed"); return end

local CAN = 0x5A5A5A5A
local WATCH = 0x480
local function fill(a, n, v) for o = 0, n - 4, 4 do safe_wd(a + o, v) end end
local function changed(a, n, v)
    local c = 0
    for o = 0, n - 4, 4 do if safe_rd(a + o) ~= v then c = c + 1 end end
    return c
end

local function probe(cmd, pat)
    fill(IN, 0x8000, pat)
    fill(OUT, 0x8000, CAN)
    local rv
    local ok = pcall(function() rv = sc601(uint64(cmd), uint64(IN), uint64(OUT), uint64(0), uint64(0), uint64(0)) end)
    if not ok then
        print(string.format("  0x%02X pat=0x%08X      EXC", cmd, pat))
        return
    end
    local e = es()
    local ci = changed(IN, WATCH, pat)
    local co = changed(OUT, WATCH, CAN)
    local flag = ""
    if co > 0 then flag = "  <<< WROTE ARG2" end
    if ci > 0 then flag = flag .. "  <-- wrote arg1" end
    print(string.format("  0x%02X pat=0x%08X rv=%-10s errno=%-26s arg1_ch=%-4d arg2_ch=%-4d%s",
        cmd, pat, sgn(rv), e, ci, co, flag))
end

local cmds = {0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F,
              0x10, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A}

print("")
print("[A] canary pattern in arg1 (every field non-zero) and canary in arg2")
for _, c in ipairs(cmds) do probe(c, CAN) end

print("")
print("[B] zero pattern in arg1, canary arg2 (the shape 0x00 answered rv=0 to in 1403a)")
for _, c in ipairs(cmds) do probe(c, 0) end

print("")
print("[C] arg1 = 0, arg2 = canary page (shape A again, but watching 0x480 bytes)")
for _, c in ipairs(cmds) do
    fill(OUT, 0x8000, CAN)
    local rv
    local ok = pcall(function() rv = sc601(uint64(c), uint64(0), uint64(OUT), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        local co = changed(OUT, WATCH, CAN)
        if co > 0 then
            print(string.format("  0x%02X rv=%-10s errno=%-26s arg2_ch=%d  <<< WROTE ARG2", c, sgn(rv), es(), co))
        end
    end
end
print("  (only commands that wrote are listed)")

print("")
print("=== 1408a DONE ===")
