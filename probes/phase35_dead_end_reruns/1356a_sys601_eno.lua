-- CRASH_CLASS: HIGH (cmd 0x1B kills; it runs last)
-- PROBE 1356a: sys 601 - close the command table with errno
--
-- Context: 1355a (results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt)
-- called 601 cmd 0x12 with arg2 pointing at a mapped zeroed 0x20-byte block and
-- got -1 twice, then died at 0x1B. The dossier price for 0x12 is large
-- (copyin 0x20 from arg2, then [proc+0x578]/[proc+0x580] = our two qwords; the
-- consumer at sys_601_deep.asm:ca1b32 reads them back, copyout'ing 0x480 kernel
-- bytes to our pointer and then kfree()ing it), so the 14.10 refusal is worth
-- one decisive test: errno separates "handler ran and rejected" from "slot is a
-- stub".
--
-- [A] cmd 0x12 three ways, errno after each:
--     (0x12, 0, mapped_struct)   - the shape that should reach the copyin
--     (0x12, 0, 0x1000)          - unmapped source: EFAULT proves copyin ran
--     (0x12, 0, 0)               - null source: EFAULT if copyin ran
--     errno 78 (ENOSYS) in all three closes the command as stubbed on 14.10.
-- [B] cmd 0x0C with arg1=0: the 0x0C branch (sys_601_deep.asm:ca0b58-ca0b79)
--     reads two bytes the kernel picks itself, then errors 0x23 when they equal
--     0xCD/0x41 and returns 0 otherwise - i.e. the "backdoor marker" check
--     *refuses* a marked process. One call tells us which side we are on and
--     whether the step is reachable at all (it needs arg1 == 0).
-- [C] the surviving table with the other argument slot: 601(cmd, 0, buf) for
--     every cmd 0x00-0x27 except the ones already known, errno printed, changed
--     dwords counted. This complements 1355a's (cmd, buf, 0x100) sweep. cmd 0x1B
--     runs LAST because it kills the process.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--   results/kernel_handlers/asm/sys_601_deep.asm:300-350 (0x0C), :478-520 (0x12), :900-960 (consumer)
--   results/kernel_handlers/analysis/sys_601_deep.md:10-31
--   probes/phase17_new_vectors/1192a_601_dispatcher_command.lua:33 (the old skip list)

print("=== PROBE 1356a: SYS 601 TABLE, WITH ERRNO ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function hx(v)
    if v == nil then return "nil" end
    return string.format("0x%08X", v % 0x100000000)
end
local function sgn(val)
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
-- errno as a number plus the platform string; stale on success.
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end

local sc601 = make_syscall(601)
local sc477 = make_syscall(477)
local getpid = make_syscall(20)
print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function mmap(px, prot)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(prot or 3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local buf = mmap(0x4000)
print(string.format("  buf=0x%X", buf))
if buf == 0 then print("[!] mmap failed"); return end

local function fill(v)
    for i = 0, 0xFFF do safe_wd(buf + i * 4, v) end
end
local function changed()
    local n = 0
    for i = 0, 0xFFF do
        if safe_rd(buf + i * 4) ~= 0xA5A5A5A5 then n = n + 1 end
    end
    return n
end
local function call(cmd, a1, a2)
    local ok, ret = pcall(function() return sc601(uint64(cmd), uint64(a1), uint64(a2)) end)
    local r = ok and sgn(ret) or "PCALL-FAIL"
    return r, es()
end

print("")
print("[A] cmd 0x12 with errno")
fill(0)
print(string.format("  0x12 (arg1=0, arg2=buf)     : %s  errno=%s", call(0x12, 0, buf)))
print(string.format("  0x12 (arg1=0, arg2=0x1000)  : %s  errno=%s", call(0x12, 0, 0x1000)))
print(string.format("  0x12 (arg1=0, arg2=0)       : %s  errno=%s", call(0x12, 0, 0)))
print(string.format("  0x12 (arg1=buf, arg2=buf)   : %s  errno=%s", call(0x12, buf, buf)))

print("")
print("[B] cmd 0x0C, the marker check (arg1 must be 0)")
print(string.format("  0x0C (arg1=0, arg2=buf)     : %s  errno=%s", call(0x0C, 0, buf)))
print(string.format("  0x0C (arg1=0, arg2=0)       : %s  errno=%s", call(0x0C, 0, 0)))

print("")
print("[C] surviving table, (cmd, 0, buf): first dword + changed count + errno")
local cmds = {0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0e,
              0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
              0x1a, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
              0x26, 0x27}
for _, cmd in ipairs(cmds) do
    fill(0xA5A5A5A5)
    print(string.format("  calling 0x%02X ...", cmd))
    local r, e = call(cmd, 0, buf)
    local n = changed()
    print(string.format("  0x%02X %s ch=%d d0=%s errno=%s", cmd, r, n, hx(safe_rd(buf)), e))
end

print("")
print("[D] last: cmd 0x1B, which killed 1355a in the other argument slot")
fill(0)
print(string.format("  calling 0x1B ..."))
print(string.format("  0x1B (arg1=0, arg2=buf): %s  errno=%s", call(0x1B, 0, buf)))
print(string.format("  calling 0x1B again with the 1355a shape ..."))
print(string.format("  0x1B (arg1=buf, arg2=0x100): %s  errno=%s", call(0x1B, buf, 0x100)))

print("")
print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1356a COMPLETE ===")
