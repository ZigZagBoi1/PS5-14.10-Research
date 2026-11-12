-- CRASH_CLASS: HIGH
-- PROBE 1403a: 601 - write-destination map. Which commands write to arg1, which to arg2,
--              and which share the 0x12/0x01 EINVAL class.
--
-- prior art:
--   results/phase36_realargs/1401a_sys601_cmd12_errno_20261109_151911.txt
--     12(0, x) = EFAULT(14); 12(struct, x) = EINVAL(22) for a mapped 0x10000-byte struct,
--     so the 0x20-byte copyin reads arg1 and a later content-independent gate answers EINVAL.
--   results/phase36_realargs/1402a_sys601_cmd12_field_gate_20261109_152003.txt
--     every single-qword struct value {1..0xFFFFFFFF} is still EINVAL, and arg2 in
--     {0,1,8,0x100,0x4000,page} is still EINVAL -> the gate does not read the struct.
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--     0x00 rv=0 writes 0x100/0; 0x07/0x09/0x0B/0x0D/0x13/0x14/0x19 rv=0 no write;
--     0x0E writes two zero dwords; 0x1A writes one; 0x01/0x02/0x05/0x06/0x0A/0x15..0x18 = -1;
--     died at 0x1B.
--   results/phase35_dead_end_reruns/1383a_*: 0x02/0x05/0x06 = ENOSYS(78), 0x0A = EPERM(1),
--     0x01 = EINVAL on our bytes / EFAULT on null, 0x0C parks forever.
--   results/kernel_handlers/analysis/sys_601_deep.md, docs/MDBG_601_COMMAND_MAP_14_10.md
--
-- Why: the 13.60 consumer at 0xffffffff8b661b2c copies 0x480 bytes from [proc+0x578] to a
-- caller buffer, then frees that pointer. [proc+0x578] is written by a 601 command from
-- caller-supplied data. If the consumer command can be identified by behaviour, the arming
-- command becomes the only remaining obstacle to a 0x480-byte arbitrary kernel read.
--
-- Shapes per command (all buffers canary-filled so any write is visible):
--   A: (cmd, 0, OUT)      - does the command write to arg2?
--   B: (cmd, IN0, OUT)    - arg1 = all-zero 0x20-byte struct at the start of a page
--   C: (cmd, 0, 0)        - errno class only
-- Skipped: 0x03 0x04 0x08 0x0C (lethal/park), 0x1B (lethal in every shape tried), 0x11
-- (kills on an all-zero page, 1400a). 0x1C..0x27 run LAST so a death costs nothing above.

print("=== PROBE 1403a: 601 WRITE-DESTINATION MAP ===")

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

local OUTLEN = 0x2000
local INLEN  = 0x2000
local IN = mmap(INLEN)
local OUT = mmap(OUTLEN)
print(string.format("  in=0x%X out=0x%X", IN, OUT))
if IN == 0 or OUT == 0 then print("[!] mmap failed"); return end

local CANARY = 0x5A5A5A5A
local function fill(a, n, v) for o = 0, n - 4, 4 do safe_wd(a + o, v) end end
local function changed(a, n, v)
    local c = 0
    for o = 0, n - 4, 4 do
        if safe_rd(a + o) ~= v then c = c + 1 end
    end
    return c
end

local function call(cmd, a1, a2)
    local rv
    local ok = pcall(function() rv = sc601(uint64(cmd), uint64(a1), uint64(a2), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return "EXC", "-" end
    return sgn(rv), es()
end

local function shape(tag, cmd, a1, a2, watch, wlen)
    fill(OUT, OUTLEN, CANARY)
    fill(IN, INLEN, CANARY)
    -- shape B/C use a zeroed 0x20-byte struct at IN
    if a1 == IN then for o = 0, 0x20 - 8, 8 do safe_wd(IN + o, 0) safe_wd(IN + o + 4, 0) end end
    local rv, er = call(cmd, a1, a2)
    local co, ci = -1, -1
    if watch == "out" then co = changed(OUT, wlen or 0x100, CANARY) end
    if watch == "in" then ci = changed(IN, 0x20, CANARY) end
    print(string.format("  0x%02X %-16s rv=%-10s errno=%-16s out_ch=%d in_ch=%d", cmd, tag, rv, er, co, ci))
end

local function cmds(list, note)
    print("")
    print(note)
    for _, c in ipairs(list) do
        shape("A(0,OUT)", c, 0, OUT, "out", 0x100)
        shape("C(0,0)", c, 0, 0, "none")
    end
end

-- part 1: the commands already known to answer without dying
local safe = {0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0D, 0x0E, 0x0F,
              0x10, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A}
cmds(safe, "[A] known-answering commands, shape A (arg1=0, arg2=OUT)")

-- part 2: same commands with a zero 0x20-byte struct in arg1 (the 0x12 shape)
print("")
print("[B] same commands, arg1 = zero 0x20 struct, arg2 = OUT")
for _, c in ipairs(safe) do
    shape("B(IN,OUT)", c, IN, OUT, "in")
end

-- part 3: the commands nobody has measured; last, because they may be lethal
local risky = {0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27}
cmds(risky, "[C] unmeasured high commands, shape A (arg1=0, arg2=OUT)")

print("")
print("=== 1403a DONE ===")
