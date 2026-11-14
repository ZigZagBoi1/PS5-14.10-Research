-- CRASH_CLASS: HIGH
-- PROBE 1406a: 601 cmd 0x12 - the qword at struct+0x08 is consumed as a scalar or as a
--              user pointer. Sweep it.
--
-- prior art:
--   results/phase36_realargs/1405a_sys601_cmd12_field_20261109_152556.txt
--     arg2 points at a struct; setting dword +0x08 or +0x0C non-zero flips the answer from
--     EFAULT(14) to ENOENT(2). Every other dword (+0x00,+0x04,+0x10..+0x100) leaves it at
--     EFAULT. Values written at +0x00 have no effect, so the consumed field is the qword at
--     +0x08 tested for non-zero, not a pointer at +0x00.
--   results/phase36_realargs/1404a_sys601_cmd12_index_20261109_152525.txt
--     index (arg1) 0 = ENOENT with a non-zero page, 0x01..0xFFFFFFFF = EINVAL(22), and
--     nothing is ever written to the destination (ch=0 in every shape).
--   results/kernel_handlers/analysis/sys_601_deep.md (13.60 case 0x12 is a copyin+store to
--     proc+0x578, which does not match this behaviour, so 14.10's 0x12 is different code)
--
-- Two models still fit:
--   (A) scalar: +0x08 is an id/key, 0 = refuse(EFAULT), non-zero = look up -> ENOENT.
--   (B) pointer: +0x08 is a user address, 0 = the copyin of NULL fails(EFAULT), non-zero =
--       copyin runs and a mapped user page should get PAST the fault.
-- A mapped user address distinguishes them: under (B) the answer changes from ENOENT,
-- under (A) it stays ENOENT for any non-zero scalar.

print("=== PROBE 1406a: 601 CMD 0x12 QWORD+8 ===")

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
local function safe_wq(a, v) local ok = pcall(function() memory.write_qword(a, v) end) return ok end
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

local IN = mmap(0x4000)
local DST = mmap(0x4000)
print(string.format("  in=0x%X dst=0x%X", IN, DST))
if IN == 0 or DST == 0 then print("[!] mmap failed"); return end

local function zero() for o = 0, 0x4000 - 8, 8 do safe_wq(IN + o, uint64(0)) end end

local function call(tag, idx, f8)
    zero()
    if f8 ~= nil then safe_wq(IN + 8, uint64(f8)) end
    local rv
    local ok = pcall(function() rv = sc601(uint64(0x12), uint64(idx), uint64(IN), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print(string.format("  %-26s EXC", tag)) return "EXC", "-" end
    local e = es()
    print(string.format("  %-26s rv=%-10s errno=%-26s out0=0x%08X", tag, sgn(rv), e, safe_rd(DST)))
    return sgn(rv), e
end

print("")
print("[A] is the qword a user pointer? (mapped pages first)")
call("f8 = 0 (control)", 0, 0)
call("f8 = dst page", 0, DST)
call("f8 = dst+0x1000", 0, DST + 0x1000)
call("f8 = in page", 0, IN)
call("f8 = dst+0x10", 0, DST + 0x10)

print("")
print("[B] scalar magnitudes")
local vals = {1, 2, 3, 0x10, 0x16, 0x100, 0x1000, 0x10000, 0x100000, 0x7FFFFFFF,
              0xFFFFFFFF, 0x100000000, 0xFFFF00000000}
for _, v in ipairs(vals) do
    call(string.format("f8 = 0x%X", v), 0, v)
end

print("")
print("[C] index 0 vs the +8 field together (does a second index value unlock anything?)")
call("idx=1 f8=dst", 1, DST)
call("idx=0x16 f8=dst", 0x16, DST)
call("idx=0x100 f8=dst", 0x100, DST)

print("")
print("[D] kernel addresses (last: an unmapped one would prove a raw deref)")
call("f8 = stub page (k)", 0, 0xFFFFFFFFC0000000)
call("f8 = image base (k)", 0, 0xFFFFFFFFC1000000)
print("  about to try an unmapped kernel VA - a kill here means a raw deref of +8")
call("f8 = 0xFFFFFFFFD0000000", 0, 0xFFFFFFFFD0000000)

print("")
print("=== 1406a DONE ===")
