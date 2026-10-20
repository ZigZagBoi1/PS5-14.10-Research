-- CRASH_CLASS: LOW
-- Isolated kevent filter copyout survey.
print("=== PROBE 109h: KEVENT FILTERS ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
end

local SYS_close       = 6
local SYS_getpid      = 20
local SYS_getpeername  = 31
local SYS_getsockname  = 32
local SYS_socket      = 97
local SYS_getsockopt  = 118
local SYS_setsockopt  = 105
local SYS_socketpair  = 135
local SYS_fstat       = 189
local SYS_fstat12     = 551
local SYS_kqueue      = 362
local SYS_kevent      = 363

local AF_LOCAL     = 1
local AF_INET      = 2
local SOCK_STREAM  = 1
local SOCK_DGRAM   = 2
local SOL_SOCKET   = 0xFFFF
local SOL_LOCAL    = 0
local IPPROTO_TCP  = 6

local pid = to_num(make_syscall(SYS_getpid)())
print("pid: " .. pid)
print("")

local function close_fd(fd)
    if fd == nil then return end
    pcall(function() make_syscall(SYS_close)(uint64(fd)) end)
end

local function create_socketpair()
    local sv = memory.alloc(8)
    safe_wd(sv, 0); safe_wd(sv + 4, 0)
    local ok, ret = pcall(function()
        return make_syscall(SYS_socketpair)(uint64(AF_LOCAL), uint64(SOCK_STREAM),
            uint64(0), uint64(sv))
    end)
    if not ok or to_num(ret) ~= 0 then return nil, nil end
    return safe_rd(sv), safe_rd(sv + 4)
end

local function scan_buf_for_kptrs(tag, buf, size)
    local kptr_count = 0
    local interesting = 0
    for i = 0, size - 8, 8 do
        local qv = safe_rq(buf + i)
        if qv ~= nil then
            local h, l = get_hi_lo(qv)
            if is_kptr(qv) then
                print(tag .. " +" .. string.format("%02X", i) .. ": " ..
                      fmt_addr(qv) .. " *** KERNEL POINTER ***")
                kptr_count = kptr_count + 1
            elseif h ~= 0 and h ~= 0xFFFFFFFF and l ~= 0 then
                interesting = interesting + 1
            end
        end
    end
    return kptr_count, interesting
end

-- SECTION D: kevent event data deep scan
-- ============================================================
print("--- SECTION D: KEVENT EVENT DATA ---")
print("")

repeat
    local ok_kq, kq = pcall(function() return to_num(make_syscall(SYS_kqueue)()) end)
    if not ok_kq or kq < 0 then print("[D] kqueue FAILED"); break end
    print("[D] kqueue fd=" .. kq)

    -- struct kevent = 32 bytes (0x20)
    -- +0x00: ident (8)   +0x08: filter (2) +0x0A: flags (2)
    -- +0x0C: fflags (4)  +0x10: data (8)   +0x18: udata (8)

    local EVFILT_READ  = -1
    local EVFILT_WRITE = -2
    local EVFILT_PROC  = -5
    local EVFILT_TIMER = -7
    local EVFILT_USER  = -11

    local EV_ADD      = 0x0001
    local EV_ENABLE   = 0x0004
    local EV_ONESHOT  = 0x0010
    local EV_CLEAR    = 0x0020

    local NOTE_EXIT   = 0x80000000
    local NOTE_FORK   = 0x40000000
    local NOTE_EXEC   = 0x20000000
    local NOTE_TRACK  = 0x00000001
    local NOTE_TRIGGER = 0x01000000
    local NOTE_MSECONDS = 0x00000000

    local function write_kevent(buf, ident, filter, flags, fflags, data, udata)
        safe_wq(buf, uint64(ident))
        -- filter is signed short at +8, flags is unsigned short at +10
        local filter_flags = 0
        if filter < 0 then
            filter_flags = (0x10000 + filter) + flags * 0x10000
        else
            filter_flags = filter + flags * 0x10000
        end
        safe_wd(buf + 8, filter_flags)
        safe_wd(buf + 0x0C, fflags)
        safe_wq(buf + 0x10, uint64(data))
        safe_wq(buf + 0x18, uint64(udata))
    end

    local function dump_kevent(tag, buf, count)
        local kptrs = 0
        for ev = 0, count - 1 do
            local base = buf + ev * 0x20
            local ident_q = safe_rq(base)
            local filter_flags = safe_rd(base + 8)
            local fflags = safe_rd(base + 0x0C)
            local data_q = safe_rq(base + 0x10)
            local udata_q = safe_rq(base + 0x18)

            local filter = 0
            local flags = 0
            if filter_flags ~= nil then
                filter = filter_flags % 0x10000
                if filter >= 0x8000 then filter = filter - 0x10000 end
                flags = math.floor(filter_flags / 0x10000)
            end

            print(tag .. " ev" .. ev .. ": ident=" .. fmt_addr(ident_q) ..
                  " filter=" .. tostring(filter) .. " flags=0x" .. string.format("%X", flags) ..
                  " fflags=0x" .. string.format("%X", fflags or 0))
            print(tag .. "   data=" .. fmt_addr(data_q) .. " udata=" .. fmt_addr(udata_q))

            if is_kptr(data_q) then
                print(tag .. "   *** DATA IS KERNEL POINTER ***")
                kptrs = kptrs + 1
            end
            if is_kptr(udata_q) then
                print(tag .. "   *** UDATA IS KERNEL POINTER ***")
                kptrs = kptrs + 1
            end
            if is_kptr(ident_q) then
                print(tag .. "   *** IDENT IS KERNEL POINTER ***")
                kptrs = kptrs + 1
            end
        end
        return kptrs
    end

    local total_kptrs = 0

    -- D1: EVFILT_USER — register, trigger, poll
    print("[D] D1: EVFILT_USER register + trigger + poll")
    local change = memory.alloc(0x40)
    write_kevent(change, 42, EVFILT_USER, EV_ADD + EV_CLEAR, 0, 0, 0xAAAA)
    local events = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    local ts = memory.alloc(16)
    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))

    local ok_r, rv_r = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(0), uint64(ts)))
    end)
    print("[D] register EVFILT_USER: ret=" .. tostring(rv_r))

    -- Trigger it
    write_kevent(change, 42, EVFILT_USER, 0, NOTE_TRIGGER, 0, 0)
    pcall(function()
        make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(0), uint64(0), uint64(0))
    end)

    -- Poll
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end
    local ok_p, rv_p = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(0), uint64(0),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] poll EVFILT_USER: ret=" .. tostring(rv_p) .. " (events returned)")
    if ok_p and to_num(rv_p) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_p))
    end
    print("")

    -- D2: EVFILT_TIMER — short timer poll
    print("[D] D2: EVFILT_TIMER register + poll")
    write_kevent(change, 99, EVFILT_TIMER, EV_ADD + EV_ONESHOT, NOTE_MSECONDS, 1, 0xBBBB)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    -- Register + immediate poll with 10ms timeout
    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(10000000)) -- 10ms in nanoseconds
    local ok_t, rv_t = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] EVFILT_TIMER register+poll: ret=" .. tostring(rv_t))
    if ok_t and to_num(rv_t) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_t))
    end
    print("")

    -- D3: EVFILT_PROC on self
    print("[D] D3: EVFILT_PROC on self (pid=" .. pid .. ")")
    write_kevent(change, pid, EVFILT_PROC, EV_ADD + EV_CLEAR,
        NOTE_EXIT + NOTE_FORK + NOTE_EXEC, 0, 0xCCCC)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))

    local ok_proc, rv_proc = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] EVFILT_PROC register+poll: ret=" .. tostring(rv_proc))
    if ok_proc and to_num(rv_proc) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_proc))
    elseif ok_proc then
        print("[D] no events (expected — no fork/exec happened)")
    end
    print("")

    -- D4: EVFILT_PROC on pid=1 (init)
    print("[D] D4: EVFILT_PROC on pid=1 (init)")
    write_kevent(change, 1, EVFILT_PROC, EV_ADD + EV_CLEAR,
        NOTE_EXIT + NOTE_FORK + NOTE_EXEC + NOTE_TRACK, 0, 0xDDDD)
    for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

    safe_wq(ts, uint64(0))
    safe_wq(ts + 8, uint64(0))

    local ok_init, rv_init = pcall(function()
        return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
            uint64(events), uint64(4), uint64(ts)))
    end)
    print("[D] EVFILT_PROC pid=1 register+poll: ret=" .. tostring(rv_init))
    if ok_init and to_num(rv_init) > 0 then
        total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_init))
    end
    print("")

    -- D5: EVFILT_READ on socketpair (data available)
    print("[D] D5: EVFILT_READ on socketpair with data")
    local sp_a, sp_b = create_socketpair()
    if sp_a ~= nil then
        -- Write data to sp_b so sp_a has bytes to read
        local wbuf = memory.alloc(8)
        safe_wd(wbuf, 0x41424344)
        pcall(function()
            make_syscall(4)(uint64(sp_b), uint64(wbuf), uint64(4)) -- write(4)
        end)

        write_kevent(change, sp_a, EVFILT_READ, EV_ADD, 0, 0, 0xEEEE)
        for i = 0, 0xFF, 4 do safe_wd(events + i, 0xDEADBEEF) end

        safe_wq(ts, uint64(0))
        safe_wq(ts + 8, uint64(0))

        local ok_rd, rv_rd = pcall(function()
            return to_num(make_syscall(SYS_kevent)(uint64(kq), uint64(change), uint64(1),
                uint64(events), uint64(4), uint64(ts)))
        end)
        print("[D] EVFILT_READ register+poll: ret=" .. tostring(rv_rd))
        if ok_rd and to_num(rv_rd) > 0 then
            total_kptrs = total_kptrs + dump_kevent("[D]", events, to_num(rv_rd))
        end

        close_fd(sp_a); close_fd(sp_b)
    end

    print("")
    print("[D] total kernel pointers across all events: " .. total_kptrs)

    close_fd(kq)
until true

print("")
print("=== PROBE 109h COMPLETE ===")
