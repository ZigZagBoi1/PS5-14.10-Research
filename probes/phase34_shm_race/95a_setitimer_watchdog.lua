-- CRASH_CLASS: LOW
-- PROBE 95a: setitimer SIGALRM watchdog for auto-recovery
--
-- Problem: blocking syscalls (sendfile on unix socket, etc) hang the loader
-- process permanently, requiring game close+relaunch.
-- Solution: setitimer(83) ITIMER_REAL sends SIGALRM(14) after N seconds.
-- With a bare ret gadget as signal handler, blocking syscalls return EINTR
-- and pcall catches the error, letting execution continue.

print("=== PROBE 95a: SETITIMER WATCHDOG ===")
print("")

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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Get eboot base for gadget addresses
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local eb_lo = rd(N(info) + 0x108) or 0
local eb_hi = rd(N(info) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
print(string.format("eboot_text=0x%X%08X", eb_hi, eb_lo))

-- bare ret gadget at eboot+0x42
local ret_gadget = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x42))
print("ret_gadget=" .. tostring(ret_gadget))

-- === TEST A: Install SIGALRM handler ===
print("")
print("--- A: sigaction(14, ret_gadget) ---")

-- struct sigaction: sa_handler at +0, sa_mask at +8, sa_flags at +0x48(?)
-- FreeBSD sigaction: sa_handler(8), sa_flags(4), sa_mask(16) = 28 bytes
-- Actually on FreeBSD: { void (*sa_handler)(int); int sa_flags; sigset_t sa_mask; }
-- sigset_t is 4 u32 = 16 bytes. Total = 8 + 4 + 16 = 28 bytes
local sa_new = memory.alloc(64)
wq(N(sa_new), ret_gadget)       -- sa_handler = bare ret
wd(N(sa_new) + 8, 0)            -- sa_flags = 0 (no SA_RESTART!)
wd(N(sa_new) + 12, 0)           -- sa_mask = empty
wd(N(sa_new) + 16, 0)
wd(N(sa_new) + 20, 0)
wd(N(sa_new) + 24, 0)

local sa_old = memory.alloc(64)
local ok_s, rv_s = pcall(function()
    return mk(416)(uint64(14), sa_new, sa_old)
end)
local sig_ret = ok_s and N(rv_s) or -999
if sig_ret >= 0x80000000 then sig_ret = sig_ret - 0x100000000 end
print("sigaction(14) ret=" .. sig_ret)

-- === TEST B: setitimer with 3 second timeout ===
print("")
print("--- B: setitimer(ITIMER_REAL, 3s) ---")

-- struct itimerval { struct timeval it_interval; struct timeval it_value; }
-- struct timeval { time_t tv_sec; suseconds_t tv_usec; } = 8+8 = 16 bytes each
-- itimerval = 32 bytes total
-- it_interval at +0 (repeat), it_value at +16 (initial)
local itv = memory.alloc(64)
-- it_interval = 0 (no repeat)
wq(N(itv), uint64(0))        -- interval.tv_sec = 0
wq(N(itv) + 8, uint64(0))    -- interval.tv_usec = 0
-- it_value = 3 seconds
wq(N(itv) + 16, uint64(3))   -- value.tv_sec = 3
wq(N(itv) + 24, uint64(0))   -- value.tv_usec = 0

local ok_t, rv_t = pcall(function()
    return mk(83)(uint64(0), itv, uint64(0))  -- ITIMER_REAL=0
end)
local timer_ret = ok_t and N(rv_t) or -999
if timer_ret >= 0x80000000 then timer_ret = timer_ret - 0x100000000 end
print("setitimer ret=" .. timer_ret)

-- === TEST C: Verify SIGALRM interrupts a blocking call ===
print("")
print("--- C: blocking read with 3s alarm ---")

-- Create a unix socketpair, read from it (will block since nothing written)
local sv = memory.alloc(16); wd(N(sv), 0); wd(N(sv)+4, 0)
pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv) end)
local sr = rd(N(sv)) or -1; local sw = rd(N(sv)+4) or -1
print("socketpair=" .. sr .. "," .. sw)

if sr >= 0 then
    -- Set the 3s alarm
    local itv2 = memory.alloc(64)
    wq(N(itv2), uint64(0))
    wq(N(itv2) + 8, uint64(0))
    wq(N(itv2) + 16, uint64(3))
    wq(N(itv2) + 24, uint64(0))
    pcall(function() mk(83)(uint64(0), itv2, uint64(0)) end)

    local t1 = os.clock()

    -- This read WILL block because nobody writes to sw
    -- SIGALRM after 3s should interrupt it with EINTR
    local rbuf = memory.alloc(64)
    local ok_r, rv_r = pcall(function()
        return mk(3)(uint64(sr), uint64(N(rbuf)), uint64(64))
    end)
    local t2 = os.clock()
    local r_ret = ok_r and N(rv_r) or -999
    if r_ret >= 0x80000000 then r_ret = r_ret - 0x100000000 end

    local elapsed = t2 - t1
    print(string.format("read ret=%d elapsed=%.1fs ok=%s", r_ret, elapsed, tostring(ok_r)))

    if elapsed >= 2 and elapsed <= 5 then
        print("SIGALRM INTERRUPTED BLOCKING READ!")
    elseif elapsed < 1 then
        print("read returned immediately (not blocking?)")
    else
        print("unexpected timing")
    end

    pcall(function() mk(6)(uint64(sr)) end)
    pcall(function() mk(6)(uint64(sw)) end)
end

-- === TEST D: Verify sendfile would be interrupted too ===
print("")
print("--- D: sendfile on unix socket with alarm ---")

do
    -- shm
    local ok_s2, rv_s2 = pcall(function()
        return mk(482)(uint64(1), uint64(2), uint64(0x1FF))
    end)
    local shm_fd = ok_s2 and N(rv_s2) or -1
    if shm_fd >= 0x80000000 then shm_fd = shm_fd - 0x100000000 end

    if shm_fd >= 0 then
        pcall(function() mk(480)(uint64(shm_fd), uint64(0x100000)) end)  -- 1MB

        local sv2 = memory.alloc(16); wd(N(sv2), 0); wd(N(sv2)+4, 0)
        pcall(function() mk(135)(uint64(1), uint64(1), uint64(0), sv2) end)
        local sr2 = rd(N(sv2)) or -1; local sw2 = rd(N(sv2)+4) or -1

        if sw2 >= 0 then
            -- 3s alarm
            local itv3 = memory.alloc(64)
            wq(N(itv3), uint64(0))
            wq(N(itv3) + 8, uint64(0))
            wq(N(itv3) + 16, uint64(3))
            wq(N(itv3) + 24, uint64(0))
            pcall(function() mk(83)(uint64(0), itv3, uint64(0)) end)

            local t1 = os.clock()
            local sbytes = memory.alloc(8); wq(N(sbytes), uint64(0))
            local ok_sf, rv_sf = pcall(function()
                return mk(393)(uint64(shm_fd), uint64(sw2), uint64(0), uint64(0x100000), uint64(0), uint64(N(sbytes)))
            end)
            local t2 = os.clock()
            local sf_ret = ok_sf and N(rv_sf) or -999
            if sf_ret >= 0x80000000 then sf_ret = sf_ret - 0x100000000 end
            local sent = rd(N(sbytes)) or 0
            if sent < 0 then sent = sent + 0x100000000 end

            print(string.format("sendfile ret=%d sent=%d elapsed=%.1fs", sf_ret, sent, t2-t1))

            if t2 - t1 >= 2 and t2 - t1 <= 5 then
                print("SIGALRM INTERRUPTED SENDFILE!")
            end

            pcall(function() mk(6)(uint64(sr2)) end)
            pcall(function() mk(6)(uint64(sw2)) end)
        end
        pcall(function() mk(6)(uint64(shm_fd)) end)
    end
end

-- === TEST E: Cancel timer (disarm) ===
print("")
print("--- E: cancel timer ---")
local itv_cancel = memory.alloc(64)
for j = 0, 60, 4 do wd(N(itv_cancel)+j, 0) end
local ok_c, rv_c = pcall(function()
    return mk(83)(uint64(0), itv_cancel, uint64(0))
end)
local c_ret = ok_c and N(rv_c) or -999
if c_ret >= 0x80000000 then c_ret = c_ret - 0x100000000 end
print("cancel ret=" .. c_ret)

print("")
print("alive=" .. tostring(N(native.fcall_with_rax(stub, 20)) == pid_val))
print("=== 95a COMPLETE ===")
