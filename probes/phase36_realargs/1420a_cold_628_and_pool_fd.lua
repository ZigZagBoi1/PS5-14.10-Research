-- CRASH_CLASS: MODERATE
-- PROBE 1420a: cold-process 628 (is EBUSY a device-busy precondition?) and 653 descriptor use
--
-- prior art:
--   results/phase36_realargs/1419a_sys628_container_sweep_20261109_155132.txt
--     628(0x100000000,0x4000,idx,0,0,0) for idx 0..0x14 ALL returned -1 EBUSY(16);
--     with flags 0x40 / prot 0x40 every idx returned EINVAL.  That run was late in a
--     process that had mapped dmem many times and had exhausted its descriptor table.
--   13.60 body 0xffffffff8b47d540: uap[0] 16 KiB aligned < 2^50, uap[1] 16 KiB aligned
--     >= 0x4000, uap[2] container idx checked only by 0x8ad833e0 (= cmp edi,0x15; setb al),
--     uap[3] flags with (flags & 0xfffffc0c) == 0, uap[4] prot with (prot & 0x9fdf2f) == 0,
--     uap[5] < 0x4000.  flags bit 6 requires byte [proc+0xc81] != 0, which is 0 for a game
--     process.  The EBUSY site is 0x8b47eeef (mov r13d,0x10) right after
--     call 0x8ae86580 with a per-container lock table at rip+0x3137f24.
--   results/phase36_realargs/1416a_blockpool_open_20261109_154348.txt
--     653(0) -> fd 26, 653(0x100000) -> fd 27 on a process whose table later filled.
--   13.60 586 dmem_container: 586(n), n != -1, does priv_check(td,0x2ad) then
--     proc+0x5c4 = n for n <= 4 and record+0x38 != 0; 586(-1) returns 0 with no check.
--
-- Reading: if EBUSY is a device state rather than a per-container answer, a fresh process
-- should answer differently on the first call.  This probe therefore runs 628 as early as
-- possible, before any dmem mapping exists, and records the first few answers verbatim.
--
-- Method: (A) one 653 pool descriptor and what it supports; (B) cold 628 over idx 0..4 and
-- four physical addresses with flags 0; (C) 586 with -1 and with 1; (D) 628 again.

print("=== PROBE 1420a: COLD 628 + 653 DESCRIPTOR ===")

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

local ST = mmap_raw(0, 0x2000, 3, 0x1002, nil, 0)
local BUF = mmap_raw(0, 0x2000, 3, 0x1002, nil, 0)
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(ST + off, 0) end) end
for off = 0, 0x1FF0, 4 do pcall(function() memory.write_dword(BUF + off, 0x41414141) end) end

-- ---------------------------------------------------------------- A: the pool descriptor
print("[A] 653 pool descriptor on a cold table")
local f0 = call6(mk(653), 0x100000)
print(string.format("  653(0x100000) -> %s errno=%s", tostring(f0), es()))
if type(f0) == "number" and f0 >= 0 then
    local r = call6(mk(189), f0, ST)
    print(string.format("  fstat(%d) -> rv=%s d0=%s d1=%s d2=%s d3=%s", f0, tostring(r),
        hex4(rd(ST)), hex4(rd(ST + 4)), hex4(rd(ST + 8)), hex4(rd(ST + 12))))
    print(string.format("  ioctl FIODTYPE -> rv=%s out=%s", tostring(call6(mk(54), f0, 0x4004667F, BUF)), hex4(rd(BUF))))
    print(string.format("  pread 16 -> rv=%s errno=%s buf0=%s", tostring(call6(mk(475), f0, BUF, 16, 0)), es(), hex4(rd(BUF))))
    print(string.format("  pwrite 16 -> rv=%s errno=%s", tostring(call6(mk(476), f0, BUF, 16, 0)), es()))
    print(string.format("  lseek(0,END) -> rv=%s errno=%s", tostring(call6(mk(478), f0, 0, 2)), es()))
    local pv = mmap_raw(0, 0x1000, 3, 1, f0, 0)
    print(string.format("  477(fd=%d, prot 3, SHARED) -> %s errno=%s", f0, tostring(pv), es()))
    if pv then print(string.format("  first dwords: %s %s %s %s", hex4(rd(pv)), hex4(rd(pv + 4)), hex4(rd(pv + 8)), hex4(rd(pv + 12)))) end
    local pv1 = mmap_raw(0, 0x1000, 1, 1, f0, 0)
    print(string.format("  477(fd=%d, prot 1, SHARED) -> %s", f0, tostring(pv1)))
else
    print(string.format("  no descriptor, errno=%s", es()))
end

-- ---------------------------------------------------------------- B: cold 628
print("[B] cold 628, flags 0 prot 0")
local sc628 = mk(628)
local results = {}
for idx = 0, 4 do
    for _, phys in ipairs({0, 0x4000, 0x1000000, 0x100000000}) do
        local rv = call6(sc628, phys, 0x4000, idx, 0, 0, 0)
        local e = es()
        print(string.format("  628(phys=0x%X,0x4000,idx=0x%X,0,0) -> %s errno=%s", phys, idx, tostring(rv), e))
        results[#results + 1] = { idx = idx, phys = phys, rv = rv, e = e }
    end
end

-- ---------------------------------------------------------------- C: 586
print("[C] 586 dmem_container")
print(string.format("  586(-1) -> %s errno=%s", tostring(call6(mk(586), 0xFFFFFFFF, 0, 0, 0, 0)), es()))
print(string.format("  586(0)  -> %s errno=%s", tostring(call6(mk(586), 0, 0, 0, 0, 0)), es()))
print(string.format("  586(1)  -> %s errno=%s", tostring(call6(mk(586), 1, 0, 0, 0, 0)), es()))

-- ---------------------------------------------------------------- D: 628 again after 586
print("[D] 628 again")
for idx = 0, 4 do
    local rv = call6(sc628, 0x100000000, 0x4000, idx, 0, 0, 0)
    print(string.format("  628 after 586, idx=0x%X -> %s errno=%s", idx, tostring(rv), es()))
end

print("=== PROBE 1420a COMPLETE ===")
