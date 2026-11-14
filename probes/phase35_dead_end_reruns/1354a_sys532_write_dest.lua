-- CRASH_CLASS: MODERATE (phase E touches an unmapped user address on purpose)
-- PROBE 1354a: 532 cmd 0x2F zeroes 0x30 bytes at arg3 - is that destination checked?
--
-- Context: 1353a (results/phase35_dead_end_reruns/1353a_sys532_low_step2_20261109_105622.txt)
-- showed, with arg3 pointing at a page filled with 0x11223344:
--
--   0x1E  rv=0, status = 3, input page untouched
--   0x2F  rv=0, status = 0, 12 dwords of the input page turned to zero
--
-- Twelve dwords is 0x30 bytes, and cmd 0x20 is the one the doc calls "fixed
-- 0x30 size" (results/kernel_handlers/analysis/sys_532_deep.md:275). So 0x2F is
-- a fixed-size 0x30-byte zero fill whose destination is arg3. Whether that
-- destination is range-checked decides if it is a primitive or a nothing:
-- the 13.60 copyout helper 0x2591d0 validates the destination
-- (results/kernel_handlers/asm/sys_646.asm:8569-8619), the bzero helper
-- 0x258ff0 does not.
--
-- [A] 0x2F with arg3 at a mapped page +0x800, sentinel-filled: confirm the
--     0x30-byte write lands at arg3 and count exactly how many bytes it zeroes
--     at sizes 0x30 / 0x40 / 0x100.
-- [B] 0x1E with six input patterns: identify the value it returns (3 on a
--     0x11223344 fill, 0 on zeros).
-- [C] 0x20 after a 0x1E + 0x2F, in case 0x800D0219 is an uninitialised state.
-- [D] 0x2F with arg3 = 0 (null) - control.
-- [E] 0x2F with arg3 = 0x1000 (unmapped user) and arg3 = a kernel VA: a
--     validated copyout answers EFAULT, an unchecked store does not. Printed
--     before each call so a death is attributable.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1353a_sys532_low_step2_20261109_105622.txt
--   results/phase35_dead_end_reruns/1352a_sys532_unpriv_commands_20261109_105538.txt
--   results/kernel_handlers/asm/sys_646.asm (copyout predicate 0x2591f0-0x25921b)
--   results/kernel_handlers/analysis/sys_532_deep.md:255-292

print("=== PROBE 1354a: 532 CMD 0x2F WRITE DESTINATION ===")

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
    if type(v) == "number" and v < 0 then return tostring(v) end
    return string.format("0x%08X", v % 0x100000000)
end
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

local sc532 = make_syscall(532)
local sc477 = make_syscall(477)
local getpid = make_syscall(20)
print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function mmap(px)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local out = mmap(0x4000)
local inp = mmap(0x4000)
print(string.format("  out=0x%X in=0x%X", out, inp))
if out == 0 or inp == 0 then print("[!] mmap failed"); return end

local function fill_out()
    for i = 0, 0xFF do safe_wd(out + i * 4, 0xDEADBEEF) end
end
local function call(cmd, arg3, size)
    local ok, ret = pcall(function()
        return sc532(uint64(cmd), uint64(0), uint64(out), uint64(arg3), uint64(size), uint64(0))
    end)
    return ok and sgn(ret) or "PCALL-FAIL"
end

print("")
print("[A] 0x2F into a sentinel region at in+0x800")
for _, size in ipairs({0x30, 0x40, 0x100}) do
    local dst = inp + 0x800
    for i = 0, 0x1FF do safe_wd(dst + i * 4, 0xA5A5A5A5) end
    fill_out()
    local r = call(0x2F, dst, size)
    local n = 0
    for i = 0, 0x1FF do
        if safe_rd(dst + i * 4) ~= 0xA5A5A5A5 then n = n + 1 end
    end
    print(string.format("  size=0x%03X %s st=%s changed_dwords=%d dst[0]=%s dst[12]=%s dst[13]=%s",
        size, tostring(r), hx(safe_rd(out)), n, hx(safe_rd(dst)), hx(safe_rd(dst + 0x30)), hx(safe_rd(dst + 0x34))))
end

print("")
print("[B] 0x1E return value against input patterns (size 0x30)")
local patterns = {
    {name = "all0", v = 0},
    {name = "all_1122", v = 0x11223344},
    {name = "first1", v = 0},
    {name = "alt1", v = 0},
}
for _, p in ipairs(patterns) do
    for i = 0, 0x3F do safe_wd(inp + i * 4, p.v) end
    if p.name == "first1" then safe_wd(inp, 1) end
    if p.name == "alt1" then
        for i = 0, 0x3F, 2 do safe_wd(inp + i * 4, 1) end
    end
    fill_out()
    local r = call(0x1E, inp, 0x30)
    print(string.format("  %s %s st=%s", p.name, tostring(r), hx(safe_rd(out))))
end

print("")
print("[C] 0x20 after 0x1E and 0x2F")
for i = 0, 0x3F do safe_wd(inp + i * 4, 0) end
call(0x1E, inp, 0x30)
call(0x2F, inp, 0x30)
fill_out()
print(string.format("  0x20 after init: %s st=%s", tostring(call(0x20, inp, 0x30)), hx(safe_rd(out))))

print("")
print("[D] 0x2F with a null arg3")
fill_out()
print(string.format("  arg3=0: %s st=%s", tostring(call(0x2F, 0, 0x30)), hx(safe_rd(out))))

print("")
print("[E] 0x2F destination validation")
fill_out()
print(string.format("  arg3=0x1000 (unmapped): %s st=%s", tostring(call(0x2F, 0x1000, 0x30)), hx(safe_rd(out))))
fill_out()
print(string.format("  arg3=kernel 0xFFFFFFFFC1000000: %s st=%s", tostring(call(0x2F, 0xFFFFFFFFC1000000, 0x30)), hx(safe_rd(out))))

print("")
print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1354a COMPLETE ===")
