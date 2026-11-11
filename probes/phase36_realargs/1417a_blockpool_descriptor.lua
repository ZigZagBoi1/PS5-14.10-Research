-- CRASH_CLASS: HIGH
-- PROBE 1417a: what a blockpool descriptor does, and whether 654/655 act on a live mapping
--
-- prior art:
--   results/phase36_realargs/1416a_blockpool_open_20261109_154348.txt
--     653(0) -> rv=26, 653(0x100000) -> rv=27, 653(0x400000) -> rv=711, 653(0x500000) ->
--     -1 EMFILE; fstat then reports fd 26 and fd 27 valid. 653 returns the descriptor
--     number, so blockpool_open is usable for a game process; 654/655 still answer EINVAL.
--   13.60 body of 653 at 0xffffffff8b367d10: kmalloc 0x410b0 with type 0x8102, mtx_init,
--     copies proc+0x5c4 / proc+0x5d0, then 0x8b0ec7a0(td,&fp,&fd,flags|2,0) installs a
--     descriptor, refcount at object+0x58.
--   13.60 body of 654 at 0xffffffff8b369560: rbx = [proc+0x200]; uap[0] must be below
--     [rbx+0x20] and [rbx+0x28] with ([rbx+0x28]-uap[0]) >= uap[1], both 64 KiB aligned;
--     then 0x8ac86c40(rbx, uap[0], &obj) looks uap[0] up, requires [obj+0x60]&2 == 0,
--     [obj+0x50] != 0 and byte [vmobject+0x9d] == 0xb, and finally calls 0x8b3697a0 to
--     install the mapping.  655 has the same prologue and gate and is the unmap.
--   results/phase36_realargs/1397d_dmem_extent_regs_20261109_142819.txt
--     /dev/dmem0 maps RW at 64 KiB offsets over a 4 GiB range and read-only above.
--   results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt
--     open(5) needs a real string buffer; passing a Lua string to uint64() raises.
--
-- Reading: if [proc+0x200] is the per-process map of *mapped* ranges, then 654 keyed on a
-- user VA should find any mapping we already own, including a read-only dmem mapping, and
-- re-install it with the protection selected by uap[2].  A 654 that returns 0 on a
-- read-only dmem mapping followed by a store that lands is a protection bypass.
--
-- Method: (A) exercise the descriptor 653 returned; (B) make a read-only dmem mapping and a
-- read-write one, call 654/655 keyed on their addresses, then store into the read-only one
-- last so nothing after it can be lost.

print("=== PROBE 1417a: BLOCKPOOL DESCRIPTOR + 654 ON LIVE MAPPINGS ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end

local pid = sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", pid))

local sc477 = mk(477)
local function mmap_pages(n, prot, flags, fd, off)
    local va = N(sc477(uint64(0), uint64(0x1000 * n), uint64(prot or 3), uint64(flags or 0x1002),
        uint64(fd or 0xFFFFFFFF), uint64(off or 0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end
local function str_addr(s)
    local va = mmap_pages(1)
    if not va then return nil end
    for i = 1, #s do pcall(function() memory.write_byte(va + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(va + #s, 0) end)
    return va
end

local ST = mmap_pages(2)
local BUF = mmap_pages(2)
local INP = mmap_pages(2)
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(ST + off, 0) end) end
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(BUF + off, 0x41414141) end) end
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(INP + off, 0) end) end
print(string.format("[0] ST=0x%X BUF=0x%X INP=0x%X", ST, BUF, INP))

local function call6(sc, a, b, c, d, e)
    local ok, rv = pcall(function() return sc(uint64(a or 0), uint64(b or 0), uint64(c or 0), uint64(d or 0), uint64(e or 0), uint64(0)) end)
    if not ok then return "EXC" end
    return sg(rv)
end

-- ---------------------------------------------------------------- A: the descriptor
print("[A] open two pools")
local sc653 = mk(653)
local f0 = call6(sc653, 0x100000)
print(string.format("  653(0x100000) -> %s", tostring(f0)))
local f1 = call6(sc653, 0)
print(string.format("  653(0) -> %s", tostring(f1)))
if type(f0) ~= "number" or f0 < 0 then print("[A] no descriptor: " .. es()) f0 = nil end

if f0 then
    print("[A2] fstat / ioctl / read / write / lseek on the pool descriptor")
    local r = call6(mk(189), f0, ST)
    print(string.format("  fstat(%d) -> rv=%s errno=%s mode=%s size=%s", f0, tostring(r), es(), hex4(rd(ST + 4)), hex4(rd(ST + 8))))
    local r2 = call6(mk(54), f0, 0x4004667F, INP)
    print(string.format("  ioctl FIODTYPE -> rv=%s errno=%s out=%s", tostring(r2), es(), hex4(rd(INP))))
    local r3 = call6(mk(54), f0, 0x8004667E, INP)
    print(string.format("  ioctl FIONBIO -> rv=%s errno=%s", tostring(r3), es()))
    local r4 = call6(mk(475), f0, BUF, 16, 0)
    print(string.format("  pread 16 -> rv=%s errno=%s buf0=%s", tostring(r4), es(), hex4(rd(BUF))))
    local r5 = call6(mk(476), f0, BUF, 16, 0)
    print(string.format("  pwrite 16 -> rv=%s errno=%s", tostring(r5), es()))
    local r6 = call6(mk(478), f0, 0, 2)
    print(string.format("  lseek end -> rv=%s errno=%s", tostring(r6), es()))
    print("[A3] mmap the pool descriptor")
    local p1 = mmap_pages(1, 3, 1, f0, 0)
    print(string.format("  477(fd=%d,len 0x1000,prot 3,SHARED) -> %s errno=%s", f0, tostring(p1), es()))
    if p1 then print(string.format("  read at pool mapping: %s", hex4(rd(p1)))) end
    local p2 = mmap_pages(1, 1, 1, f0, 0)
    print(string.format("  477(fd=%d,len 0x1000,prot 1,SHARED) -> %s errno=%s", f0, tostring(p2), es()))
    print(string.format("  628 mmap_dmem(fd=%d) -> %s errno=%s", f0, tostring(call6(mk(628), 0, 0x4000, f0)), es()))
end

-- ---------------------------------------------------------------- B: 654 on live mappings
print("[B] make a read-only dmem mapping and a read-write one")
local RO_G = nil
local P = str_addr("/dev/dmem0")
print(string.format("  path buffer 0x%X", P or 0))
local dfd = call6(mk(5), P, 0x4002)
print(string.format("  open(/dev/dmem0) -> %s errno=%s", tostring(dfd), es()))
if type(dfd) == "number" and dfd >= 0 then
    local RW = mmap_pages(1, 3, 1, dfd, 0x1000)
    print(string.format("  RW dmem page at 0x%X (prot 3, off 0x1000)", RW or 0))
    if RW then pcall(function() memory.write_dword(RW, 0x11223344) end) end
    local RO = mmap_pages(1, 1, 1, dfd, 0x2000)
    RO_G = RO
    print(string.format("  RO dmem page at 0x%X (prot 1, off 0x2000) first=%s", RO or 0, RO and hex4(rd(RO)) or "-"))

    local function try654(tag, va, typ)
        if not va then return end
        local rv = call6(mk(654), va, 0x1000, typ, 0, 0)
        print(string.format("  654(%s=0x%X,0x1000,%d,0,0) -> rv=%s errno=%s", tag, va, typ, tostring(rv), es()))
    end
    if RW then
        try654("RW", RW, 0)
        try654("RW", RW, 3)
        try654("RW", RW, 10)
    end
    if RO then
        try654("RO", RO, 0)
        try654("RO", RO, 3)
        try654("RO", RO, 10)
    end
    local anon = mmap_pages(1)
    print(string.format("  anon page at 0x%X", anon or 0))
    try654("ANON", anon, 0)
    try654("ANON", anon, 3)

    print("[B2] 655 unmap keyed on the read-write dmem page")
    if RW then
        print(string.format("  655(0x%X,0x1000) -> rv=%s errno=%s", RW, tostring(call6(mk(655), RW, 0x1000)), es()))
        print(string.format("  after unmap, read at 0x%X = %s", RW, hex4(rd(RW))))
    end
end

print("[C] last action: store into the read-only dmem page")
if RO_G then
    print(string.format("  about to write 0xDEADBEEF at 0x%X (prot 1 unless a 654 re-mapped it)", RO_G))
    local ok = pcall(function() memory.write_dword(RO_G, 0xDEADBEEF) end)
    print(string.format("  write_dword returned ok=%s, readback=%s", tostring(ok), hex4(rd(RO_G))))
else
    print("  no read-only page was created")
end
print("=== PROBE 1417a COMPLETE ===")
