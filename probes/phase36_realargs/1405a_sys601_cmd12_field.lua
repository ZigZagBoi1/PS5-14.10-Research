-- CRASH_CLASS: HIGH
-- PROBE 1405a: 601 cmd 0x12 - which field of arg2 flips EFAULT->ENOENT, and what the
--              pointer in that field is used for.
--
-- prior art:
--   results/phase36_realargs/1404a_sys601_cmd12_index_20261109_152525.txt
--     12(0, page-zeroed) = -1 EFAULT(14); 12(0, page-0x5A5A5A5A) = -1 ENOENT(2);
--     same for 0x01010101 and 0xFFFFFFFF fills; deterministic across repeats and
--     interleaved with 0x0A (which proves errno is fresh, not stale);
--     index 0x00 = ENOENT, index 0x01..0x40 and 0x41..0xFFFFFFFF = EINVAL(22);
--     no dword in the first 0x100 of the destination is ever modified (ch=0).
--   results/phase36_realargs/1403a_sys601_write_dest_map_20261109_152155.txt
--     the same ENOENT appears there; 1401a saw EFAULT only because its page was zeroed.
--   results/kernel_handlers/analysis/sys_601_deep.md (13.60 case 0x12 is a copyin+store,
--     which does not match this behaviour - 14.10's 0x12 is different code)
--
-- Model: arg1 is a small enum (only 0 passes), arg2 points at a struct whose first
-- non-zero field is consumed. A zero field answers EFAULT; a non-zero field enters a
-- lookup that misses and answers ENOENT.
--
-- Two things to learn:
--   [1] the exact offset of the field that flips the answer (tells us it is a pointer or
--       a key, and how wide);
--   [2] what the handler does with that value. If it carries it into a copyin, a kernel VA
--       answers EFAULT; if it dereferences it in kernel mode, a mapped kernel VA is read
--       and an unmapped one kills the process - and that difference is the oracle.

print("=== PROBE 1405a: 601 CMD 0x12 FIELD ===")

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

local IN = mmap(0x4000)     -- the struct handed to arg2
local DST = mmap(0x4000)    -- a second user page, to see whether it is used as a target
print(string.format("  in=0x%X dst=0x%X", IN, DST))
if IN == 0 or DST == 0 then print("[!] mmap failed"); return end

local KERNEL = 0xFFFFFFFFC1000000   -- this boot's kernel image base (STATE.md)
local KERNEL2 = 0xFFFFFFFFC2000000  -- inside the image
local KSTUB = 0xFFFFFFFFC0000000    -- the 2 MB stub page, mapped
local UNMAPPED_K = 0xFFFFFFFFD0000000 -- outside the image on this boot

local function zero() for o = 0, 0x4000 - 8, 8 do safe_wq(IN + o, uint64(0)) end end

local function call(tag, idx, a2)
    local rv
    local ok = pcall(function() rv = sc601(uint64(0x12), uint64(idx), uint64(a2), uint64(0), uint64(0), uint64(0)) end)
    if not ok then print(string.format("  %-24s EXC", tag)) return "EXC", "-" end
    local e = es()
    print(string.format("  %-24s rv=%-10s errno=%s", tag, sgn(rv), e))
    return sgn(rv), e
end

print("")
print("[1] which dword of the struct flips EFAULT -> ENOENT (all else zero)")
local offs = {0, 4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20, 0x24, 0x40, 0x80, 0x100}
for _, o in ipairs(offs) do
    zero()
    safe_wd(IN + o, 1)
    call(string.format("+0x%03X = 1", o), 0, IN)
end
zero()
call("all zero (control)", 0, IN)

print("")
print("[2] the field's value is a pointer: does a kernel VA reach a copyin or a raw deref?")
zero()
safe_wq(IN + 0, uint64(DST))
call("q0 = dst page", 0, IN)
zero()
safe_wq(IN + 0, uint64(KSTUB))
call("q0 = stub page (k)", 0, IN)
zero()
safe_wq(IN + 0, uint64(KERNEL))
call("q0 = kernel image base", 0, IN)
zero()
safe_wq(IN + 0, uint64(KERNEL2))
call("q0 = kernel image +16M", 0, IN)

print("")
print("[3] a small integer in q0 (if it is a handle/key, a low value may hit)")
for _, v in ipairs({1, 2, 3, 0x16, 0x20, 0x100}) do
    zero()
    safe_wq(IN + 0, uint64(v))
    call(string.format("q0 = 0x%X", v), 0, IN)
end

print("")
print("[4] last: an unmapped kernel VA. If this kills the process, the handler")
print("    dereferences q0 in kernel mode rather than copying in from it.")
zero()
safe_wq(IN + 0, uint64(UNMAPPED_K))
print(string.format("  q0 = 0x%X (unmapped) ...", UNMAPPED_K))
call("q0 = unmapped kernel VA", 0, IN)

print("")
print("=== 1405a DONE ===")
