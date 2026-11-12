-- CRASH_CLASS: HIGH
-- PROBE 1404a: 601 cmd 0x12 - is arg1 an index (get-by-slot) rather than a pointer?
--
-- prior art:
--   results/phase36_realargs/1401a_sys601_cmd12_errno_20261109_151911.txt
--     12(0, NULL)=EFAULT, 12(0, mapped)=EFAULT, 12(struct, NULL)=EINVAL,
--     12(struct, mapped)=EINVAL, and struct+0x10000-0x08 = EFAULT.
--   results/phase36_realargs/1403a_sys601_write_dest_map_20261109_152155.txt
--     12(0, OUT) = -1 errno=2 ENOENT, 12(0, 0) = -1 errno=14 EFAULT,
--     12(IN=page, OUT) = -1 errno=22 EINVAL.  ENOENT contradicts the 1401a EFAULT row,
--     so the two runs disagree about arg2=mapped and the difference is the buffer contents
--     (1401a used a zeroed page, 1403a a 0x5A5A5A5A canary page).
--   results/kernel_handlers/analysis/sys_601_deep.md (13.60 case 0x12 copies 0x20 from arg2)
--   docs/MDBG_601_COMMAND_MAP_14_10.md
--
-- Model under test: 0x12 takes an index in arg1 and a destination in arg2;
--   index out of range -> EINVAL, destination unusable -> EFAULT, slot empty -> ENOENT.
-- If that holds, the index sweep finds the table size and any populated slot.
--
-- The destination page is FILLED WITH A CANARY and never zeroed, so changed_dwords is a
-- real measure of what the handler writes.

print("=== PROBE 1404a: 601 CMD 0x12 INDEX ===")

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

local OUT = mmap(0x4000)
local OUT2 = mmap(0x4000)
print(string.format("  out=0x%X out2=0x%X", OUT, OUT2))
if OUT == 0 or OUT2 == 0 then print("[!] mmap failed"); return end

local CAN = 0x5A5A5A5A
local function fill(a, n, v) for o = 0, n - 4, 4 do safe_wd(a + o, v) end end
local function changed(a, n, v)
    local c = 0
    for o = 0, n - 4, 4 do if safe_rd(a + o) ~= v then c = c + 1 end end
    return c
end

-- one call: fills the destination with `pat`, calls, reports rv/errno/changes
local function c12p(tag, idx, dst, pat)
    local target = dst or OUT
    fill(target, 0x4000, pat)
    local rv
    local ok = pcall(function() rv = sc601(uint64(0x12), uint64(idx), uint64(target), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print(string.format("  %-22s EXC", tag)) return end
    print(string.format("  %-22s rv=%-10s errno=%-26s ch=%d  out0=0x%08X",
        tag, sgn(rv), es(), changed(target, 0x100, pat), safe_rd(target)))
end
local function c12(tag, idx, dst) c12p(tag, idx, dst, CAN) end

print("")
print("[A] determinism: repeat the same shape, interleaved with commands that set errno")
c12("12(0,out)", 0)
c12("12(0,out) again", 0)
local rv
pcall(function() rv = sc601(uint64(0x0A), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
print(string.format("  0x0A(0,0)          rv=%s errno=%s", sgn(rv), es()))
c12("12(0,out) after", 0)
c12("12(0,out2)", 0, OUT2)
c12("12(0,out2) again", 0, OUT2)

print("")
print("[A2] does the destination CONTENT change the answer? (1401a used a zeroed page")
print("     and got EFAULT, 1403a used a canary page and got ENOENT)")
c12p("12(0,out-zeroed)", 0, OUT, 0x00000000)
c12("12(0,out-canary)", 0, OUT)
c12p("12(0,out-zeroed)#2", 0, OUT, 0x00000000)
c12p("12(0,out2-zeroed)", 0, OUT2, 0x00000000)
c12p("12(0,out-0x01s)", 0, OUT, 0x01010101)
c12p("12(0,out-0xFFs)", 0, OUT, 0xFFFFFFFF)

print("")
print("[B] index sweep 0..0x40, destination = out")
local hits = 0
for i = 0, 0x40 do
    local before = safe_rd(OUT)
    fill(OUT, 0x4000, CAN)
    local ok = pcall(function() rv = sc601(uint64(0x12), uint64(i), uint64(OUT), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        local e = es()
        local ch = changed(OUT, 0x100, CAN)
        if e ~= "No such file or directory" then
            print(string.format("  idx=0x%02X rv=%-10s errno=%-26s ch=%d out0=0x%08X", i, sgn(rv), e, ch, safe_rd(OUT)))
            hits = hits + 1
        end
    else
        print(string.format("  idx=0x%02X EXC", i))
    end
end
print(string.format("  (non-ENOENT rows above: %d)", hits))

print("")
print("[C] large indices (printed before each call in case one is lethal)")
local big = {0x41, 0x80, 0x100, 0x400, 0x1000, 0x10000, 0x100000, 0xFFFFFFFF}
for _, i in ipairs(big) do
    print(string.format("  idx=0x%X ...", i))
    fill(OUT, 0x4000, CAN)
    local ok = pcall(function() rv = sc601(uint64(0x12), uint64(i), uint64(OUT), uint64(0), uint64(0), uint64(0)) end)
    if ok then
        print(string.format("rv=%s errno=%s ch=%d", sgn(rv), es(), changed(OUT, 0x100, CAN)))
    else
        print("EXC")
    end
end

print("")
print("=== 1404a DONE ===")
