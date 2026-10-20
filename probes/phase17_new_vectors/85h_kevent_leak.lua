-- CRASH_CLASS: LOW
-- PROBE 85h: Use kevent to check for kernel pointer leaks
-- Register events on various fds, read back kevent structures
-- kevent struct: ident(8) + filter(2) + flags(2) + fflags(4) + data(8) + udata(8) = 32 bytes

print("=== PROBE 85h ===")

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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- Create kqueue
local kq = to_num(make_syscall(362)())
print("kq=" .. kq)

-- Create pipe for events
local pipebuf = memory.alloc(8)
memory.write_dword(pipebuf, 0)
memory.write_dword(pipebuf + 4, 0)
syscall.pipe(uint64(pipebuf))
local pipe_rd = to_num(memory.read_dword(pipebuf))
local pipe_wr = to_num(memory.read_dword(pipebuf + 4))
print("pipes=" .. pipe_rd .. "," .. pipe_wr)

-- Write some data to make pipe readable
local wbuf = memory.alloc(16)
memory.write_qword(wbuf, uint64(0x4141414142424242))
syscall.write(uint64(pipe_wr), uint64(wbuf), uint64(8))

-- Build kevent changelist
-- struct kevent { uintptr_t ident; short filter; u_short flags; u_int fflags; intptr_t data; void *udata; }
-- EV_ADD=1, EVFILT_READ=-1
local changelist = memory.alloc(64)
-- Event 1: monitor pipe_rd for EVFILT_READ
memory.write_qword(changelist, uint64(pipe_rd))        -- ident
memory.write_word(changelist + 8, 0xFFFF)               -- filter = EVFILT_READ = -1 (as short)
memory.write_word(changelist + 10, 1)                    -- flags = EV_ADD
memory.write_dword(changelist + 12, 0)                   -- fflags
memory.write_qword(changelist + 16, uint64(0))           -- data
memory.write_qword(changelist + 24, uint64(0xDEADBEEF)) -- udata (marker)

-- Event 2: monitor kq itself
memory.write_qword(changelist + 32, uint64(kq))
memory.write_word(changelist + 40, 0xFFFF)
memory.write_word(changelist + 42, 1)
memory.write_dword(changelist + 44, 0)
memory.write_qword(changelist + 48, uint64(0))
memory.write_qword(changelist + 56, uint64(0xCAFEBABE))

-- kevent(kq, changelist, nchanges, eventlist, nevents, timeout)
-- kevent = 560 on FreeBSD (but PS5 may differ)
-- Actually kevent is syscall 363
local eventlist = memory.alloc(128)
for i = 0, 124, 4 do memory.write_dword(eventlist + i, 0) end

-- timeout = {0, 0} (immediate)
local timeout = memory.alloc(16)
memory.write_qword(timeout, uint64(0))
memory.write_qword(timeout + 8, uint64(0))

print("--- KEVENT ---")
local ok, ret = pcall(function()
    return make_syscall(363)(uint64(kq), uint64(changelist), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout))
end)
print("kevent ok=" .. tostring(ok) .. " ret=" .. tostring(ret))

if ok then
    local nevents = to_num(ret)
    print("nevents=" .. nevents)
    -- Dump returned events
    for ev = 0, math.min(nevents - 1, 3) do
        local base = eventlist + ev * 32
        print(string.format("event%d:", ev))
        for off = 0, 24, 8 do
            local q = memory.read_qword(base + off)
            local h, l = get_hi_lo(q)
            print(string.format("  +0x%02X=%s", off, tostring(q)))
            if h >= 0xFFFF8000 then
                print("  *** KERNEL PTR ***")
            end
        end
    end
end

-- Also try kevent with EVFILT_PROC (-5) to monitor our own process
print("")
print("--- PROC EVENT ---")
memory.write_qword(changelist, uint64(pid))
memory.write_word(changelist + 8, 0xFFFB)  -- EVFILT_PROC = -5
memory.write_word(changelist + 10, 1)       -- EV_ADD
memory.write_dword(changelist + 12, 0x80000000) -- NOTE_TRACK
memory.write_qword(changelist + 16, uint64(0))
memory.write_qword(changelist + 24, uint64(0))

for i = 0, 60, 4 do memory.write_dword(eventlist + i, 0) end

local ok2, ret2 = pcall(function()
    return make_syscall(363)(uint64(kq), uint64(changelist), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout))
end)
print("proc_kevent ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))
if ok2 then
    local nevents = to_num(ret2)
    for ev = 0, math.min(nevents - 1, 3) do
        local base = eventlist + ev * 32
        for off = 0, 24, 8 do
            local q = memory.read_qword(base + off)
            local h, l = get_hi_lo(q)
            print(string.format("  +0x%02X=%s", off, tostring(q)))
            if h >= 0xFFFF8000 then print("  *** KERNEL PTR ***") end
        end
    end
end

-- Cleanup
syscall.close(uint64(kq))
syscall.close(uint64(pipe_rd))
syscall.close(uint64(pipe_wr))

print("=== PROBE 85h COMPLETE ===")
