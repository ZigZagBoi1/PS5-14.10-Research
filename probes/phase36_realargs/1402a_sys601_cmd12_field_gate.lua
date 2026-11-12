-- CRASH_CLASS: MODERATE
-- PROBE 1402a: 601 cmd 0x12 - find the field gate that answers EINVAL after the copyin
--
-- prior art:
--   results/phase36_realargs/1401a_sys601_cmd12_errno_20261109_151911.txt
--     12(0, NULL) = -1/EFAULT(14); 12(0, struct) = -1/EFAULT(14);
--     12(struct, NULL) = -1/EINVAL(22); 12(struct, struct) = -1/EINVAL(22).
--     So the 0x20-byte copyin source is arg1 (not arg2 as in the 13.60 body), the
--     copyin's own bounds are exact (struct+0x10000-0x08 is still EFAULT), and the
--     refusal happens after a successful copy.
--   results/kernel_handlers/asm/sys_601_deep.asm (13.60 case 0x12 at 0xffffffff8b660de6
--     copies from arg2; 14.10 differs, which is why this is measured, not assumed)
--   docs/MDBG_601_COMMAND_MAP_14_10.md
--
-- Hypothesis: 14.10 validates one or more fields of the copied 0x20-byte struct and
-- answers EINVAL when they are all zero. This sweeps one field at a time.
--
-- SAFETY: qword0 of the struct stays 0 for every call except the last block, so if a
-- shape is accepted the kernel stores proc+0x578 = 0 and the known consumer at
-- 0xffffffff8b661b2c skips its 0x480 copyout and its free (test r12,r12 / je).
-- The final block deliberately sets qword0 to a mapped user page ONLY if an earlier
-- shape returned 0, and it prints before it runs.

print("=== PROBE 1402a: 601 CMD 0x12 FIELD GATE ===")

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

local function mmap(px, prot)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(prot or 3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local S = mmap(0x10000)
local pg = mmap(0x10000)
print(string.format("  struct=0x%X out=0x%X", S, pg))
if S == 0 or pg == 0 then print("[!] mmap failed"); return end

local function zero() for i = 0, 7 do safe_wq(S + i * 8, uint64(0)) end end
local function fillpg(v) for i = 0, 0xFFC, 4 do safe_wd(pg + i, v) end end

local function call(a1, a2)
    local rv
    local ok = pcall(function() rv = sc601(uint64(0x12), uint64(a1), uint64(a2), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return "EXC", "-" end
    return sgn(rv), es()
end

local vals = {1, 2, 3, 8, 0x10, 0x20, 0x100, 0x400, 0x1000, 0x4000, 0x10000, 0xFFFFFFFF}
local vname = {}
for i, v in ipairs(vals) do vname[i] = string.format("0x%X", v) end

print("")
print("[A] one qword at a time (qword0 stays 0), arg2 = 0")
zero()
local r0, e0 = call(S, 0)
print(string.format("  base (all zero)          rv=%s errno=%s", r0, e0))
for qi = 1, 3 do
    for i, v in ipairs(vals) do
        zero()
        safe_wq(S + qi * 8, uint64(v))
        local rv, er = call(S, 0)
        if not (rv == "-1" and er == "Invalid argument") then
            print(string.format("  q%d = %-10s   rv=%s errno=%s", qi, vname[i], rv, er))
        end
        zero()
    end
end
print("  (shapes that printed nothing were EINVAL like the base)")

print("")
print("[B] qword1 = a mapped user page (possible copyout destination)")
zero()
safe_wq(S + 8, uint64(pg))
fillpg(0xA5A5A5A5)
local rb, eb = call(S, 0)
local ch = 0
for i = 0, 0xFFC, 4 do if safe_rd(pg + i) ~= 0xA5A5A5A5 then ch = ch + 1 end end
print(string.format("  q1 = out page            rv=%s errno=%s changed_dwords=%d", rb, eb, ch))

print("")
print("[C] arg2 variants with an all-zero struct")
zero()
for _, a2 in ipairs({0, 1, 8, 0x100, 0x4000, pg}) do
    local rv, er = call(S, a2)
    print(string.format("  arg2=0x%-8X           rv=%s errno=%s", a2, rv, er))
end

print("")
print("[D] two-field pairs: q1 = out page plus one q2/q3 value")
for qi = 2, 3 do
    for i, v in ipairs(vals) do
        zero()
        safe_wq(S + 8, uint64(pg))
        safe_wq(S + qi * 8, uint64(v))
        local rv, er = call(S, 0)
        if not (rv == "-1" and er == "Invalid argument") then
            print(string.format("  q1=out q%d=%-8s rv=%s errno=%s", qi, vname[i], rv, er))
        end
    end
end
print("  (pairs that printed nothing were EINVAL)")

print("")
print("=== 1402a DONE ===")
