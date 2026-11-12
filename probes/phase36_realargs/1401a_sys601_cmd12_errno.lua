-- CRASH_CLASS: MODERATE
-- PROBE 1401a (v2): 601 cmd 0x12 - print the errno for every plausible argument shape
--
-- prior art:
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--     601(0x12, 0, mapped struct) = -1 twice; the errno was never printed, so it is
--     unknown whether the 20-byte copyin failed or the [proc+0x528] & 0x400 gate refused.
--   results/kernel_handlers/asm/sys_601_deep.asm (case 0x12 at VA 0xffffffff8b660de6):
--     copyin(arg2 -> rbp-0xf0, 0x20), on error return that code; lock proc+0x148,
--     test [proc+0x528] & 0x400, if set jump to 0x8b661573 (unlock, return td), else
--     store qword0 -> proc+0x578, qword1 -> proc+0x580.
--   results/kernel_handlers/asm/sys_601_deep.asm (consumer at VA 0xffffffff8b661b2c):
--     0x480-byte copyout sourced from [proc+0x578] to the caller buffer, then free().
--   docs/MDBG_601_COMMAND_MAP_14_10.md
--
-- Why the struct is eight zero qwords: if 0x12 ever succeeds it writes proc+0x578 = 0,
-- and the consumer's `test r12,r12 / je` then skips both the 0x480 copyout and the
-- free, so a success cannot start a copyout-then-free chain by accident.
--
-- Discriminators:
--   errno 14 on the null shape proves the 0x20 copyin is the first action.
--   errno 14 on the mapped shape means the 14.10 copyin rejects a legal user pointer.
--   any other errno on the mapped shape means the copyin ran and the 0x400 gate refused.

print("=== PROBE 1401a: 601 CMD 0x12 ERRNO ===")

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

local struct = mmap(0x10000)
local pg = mmap(0x10000)
print(string.format("  struct=0x%X pg=0x%X", struct, pg))
if struct == 0 or pg == 0 then print("[!] mmap failed"); return end

local function call(tag, cmd, a2, a3)
    local rv
    local ok = pcall(function() rv = sc601(uint64(cmd), uint64(a2), uint64(a3), uint64(0), uint64(0), uint64(0)) end)
    if not ok then
        print(string.format("  %-24s EXC", tag))
        return
    end
    print(string.format("  %-24s rv=%s  errno=%s", tag, sgn(rv), es()))
end

print("")
print("[A] shapes")
call("12(0, NULL)", 0x12, 0, 0)
call("12(0, struct)", 0x12, 0, struct)
call("12(struct, NULL)", 0x12, struct, 0)
call("12(struct, struct)", 0x12, struct, struct)

print("")
print("[B] copyin boundary: struct near the end of the mapped region")
call("12(0, end-0x10)", 0x12, 0, struct + 0x10000 - 0x10)
call("12(0, end-0x20)", 0x12, 0, struct + 0x10000 - 0x20)
call("12(0, end-0x08)", 0x12, 0, struct + 0x10000 - 0x08)

print("")
print("[C] control: 601(0x00) still answers, then a second 0x12")
local rv0
local ok0 = pcall(function() rv0 = sc601(uint64(0), uint64(pg), uint64(0x100), uint64(0), uint64(0), uint64(0)) end)
print(string.format("  00 rv=%s errno=%s out[0]=0x%08X", ok0 and sgn(rv0) or "EXC", es(), safe_rd(pg)))
call("12(0, struct) after", 0x12, 0, struct)

print("")
print("=== 1401a DONE ===")
