-- CRASH_CLASS: HIGH
-- PROBE 532i: MapDirectMemory from main thread via fcall
--
-- fcall_with_rax forwards 6 register args. MapDirectMemory takes 7.
-- The 7th arg (name) is on the stack, which we don't control.
-- Stack garbage might be NULL (0) — which is what we want.
--
-- DEM9N101 step163-190 said it crashes. But maybe with the right
-- preparation (zeroing nearby stack memory?) it could work.
--
-- ALTERNATIVE APPROACH: Instead of MapDirectMemory (wrapper at +0x15020),
-- find the actual syscall number by checking known Sony syscalls.
-- From CLAUDE.md: raw syscalls 546-554 return -1.
-- 546 = sceKernelAllocateDirectMemory (the raw one)
-- 547 = ?
-- 548 = sceKernelMapDirectMemory (likely!)
--
-- But wait — CLAUDE.md says "Raw syscalls 546-554 return -1 but the
-- GOT wrappers bypass that." So the wrappers must be doing something
-- special (authid check bypass? different syscall number?).
--
-- Let's try syscall 548 from the child thread instead.
-- Also try: 547, 549, 550 with MapDirectMemory-like args.

print("=== PROBE 532i: MAPDM MAINTHREAD ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)

-- Get libkernel base
local info = memory.alloc(0x200)
zero(info, 0x200); wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0x2001), info) end)
local lk_lo = rd(info + 0x108) or 0
local lk_hi = rd(info + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lk_hi or 0, lk_lo or 0))
print("lk=" .. q(lk))

local alloc_fn = lk + uint64(0x17EF0)
local map_fn = lk + uint64(0x15020)

-- [A] AllocateDirectMemory
print("[A] Alloc phys")
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
pcall(function()
    native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
local phys = rq(phys_out)
print("  phys=" .. q(phys))
if not phys or to_num(phys) == 0 then print("FAIL") return end

-- [B] Try raw syscalls 546-554 with MapDirectMemory-like args
-- MapDirectMemory(out_ptr, len, prot, flags, phys_offset, alignment)
-- In syscall ABI: rdi=out_ptr, rsi=len, rdx=prot, r10=flags, r8=phys, r9=align
-- Note: we use make_syscall which uses fn_addr (the syscall;ret gadget)
-- So args map: arg1=rdi, arg2=rsi, arg3=rdx, arg4=r10(?), arg5=r8, arg6=r9

print("")
print("[B] Raw syscall tests (546-554)")
local out_ptr = memory.alloc(8)

for sn = 546, 554 do
    wq(out_ptr, uint64(0))
    local sc = make_syscall(sn)
    local ok_c, rv = pcall(function()
        return sc(uint64(out_ptr), uint64(0x4000), uint64(3),
            uint64(0), phys, uint64(0x4000))
    end)
    local rvn = -999
    if ok_c then rvn = to_num(rv) end
    local va = rq(out_ptr)
    print(string.format("  sys %d: rv=%d out=%s", sn, rvn, q(va)))
end

-- [C] Try MapDirectMemory via fcall (6 args, 7th is stack garbage)
-- This MIGHT crash. But if name is ignored for flags=0, could work.
print("")
print("[C] MapDirectMemory fcall (6 args, name=garbage)")
wq(out_ptr, uint64(0))

-- Zero a bunch of stack area first (try to make garbage be 0)
-- Actually we can't control the stack. Let's just try it.
local ok_c, rv_c = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(out_ptr), uint64(0x4000), uint64(3),
        uint64(0), phys, uint64(0x4000))
end)
local rvn_c = -999
if ok_c then rvn_c = to_num(rv_c) end
local va_c = rq(out_ptr)
print("  rv=" .. rvn_c .. " out=" .. q(va_c))

if ok_c and va_c and to_num(va_c) ~= 0 then
    print("  *** MAPDM FROM MAIN THREAD SUCCEEDED ***")
    local test = rd(to_num(va_c))
    if test then
        print(string.format("  first_dword=0x%X", test < 0 and test + 0x100000000 or test))
    end
end

print("")
print("=== 532i DONE ===")
