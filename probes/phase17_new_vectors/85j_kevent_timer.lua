-- CRASH_CLASS: LOW
-- PROBE 85j: kevent with EVFILT_TIMER and socket fd
-- EVFILT_TIMER doesn't need a real fd, fires immediately with timeout=0

print("=== PROBE 85j ===")

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

local kq = to_num(make_syscall(362)())
print("kq=" .. kq)

-- Create a UDP socket to monitor
local sock = to_num(syscall.socket(uint64(28), uint64(2), uint64(17)))
print("sock=" .. sock)

local eventlist = memory.alloc(256)
local timeout = memory.alloc(16)
memory.write_qword(timeout, uint64(0))
memory.write_qword(timeout + 8, uint64(0))

-- Test 1: EVFILT_TIMER (-7) with ident=1, data=0 (fire immediately)
print("--- TIMER ---")
local cl = memory.alloc(32)
memory.write_qword(cl, uint64(1))           -- ident=1
-- filter=EVFILT_TIMER=-7 (0xFFF9), flags=EV_ADD|EV_ONESHOT=0x0011
memory.write_dword(cl + 8, 0x0011FFF9)
memory.write_dword(cl + 12, 0)              -- fflags
memory.write_qword(cl + 16, uint64(0))      -- data=0ms
memory.write_qword(cl + 24, uint64(0xAAAA)) -- udata

for i = 0, 124, 4 do memory.write_dword(eventlist + i, 0) end

local ok, ret = pcall(function()
    return make_syscall(363)(uint64(kq), uint64(cl), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout))
end)
print("ok=" .. tostring(ok) .. " ret=" .. tostring(ret))
if ok then
    local n = to_num(ret)
    print("n=" .. n)
    for ev = 0, math.min(n - 1, 3) do
        local base = eventlist + ev * 32
        for off = 0, 28, 4 do
            local d = to_num(memory.read_dword(base + off))
            print(string.format("ev%d+0x%02X=0x%08X", ev, off, d))
        end
        -- Check qwords for kernel ptrs
        for off = 0, 24, 8 do
            local q = memory.read_qword(base + off)
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then print("  *** KPTR at +" .. string.format("0x%02X", off) .. " ***") end
        end
    end
end

-- Test 2: EVFILT_READ (-1) on socket fd
print("")
print("--- SOCK READ ---")
memory.write_qword(cl, uint64(sock))
memory.write_dword(cl + 8, 0x0011FFFF)  -- EVFILT_READ + EV_ADD|EV_ONESHOT
memory.write_dword(cl + 12, 0)
memory.write_qword(cl + 16, uint64(0))
memory.write_qword(cl + 24, uint64(0xBBBB))

for i = 0, 124, 4 do memory.write_dword(eventlist + i, 0) end

local ok2, ret2 = pcall(function()
    return make_syscall(363)(uint64(kq), uint64(cl), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout))
end)
print("ok=" .. tostring(ok2) .. " ret=" .. tostring(ret2))
if ok2 then
    local n = to_num(ret2)
    print("n=" .. n)
    for ev = 0, math.min(n - 1, 3) do
        local base = eventlist + ev * 32
        for off = 0, 28, 4 do
            local d = to_num(memory.read_dword(base + off))
            print(string.format("ev%d+0x%02X=0x%08X", ev, off, d))
        end
        for off = 0, 24, 8 do
            local q = memory.read_qword(base + off)
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then print("  *** KPTR at +" .. string.format("0x%02X", off) .. " ***") end
        end
    end
end

-- Test 3: EVFILT_PROC (-5) on our PID
print("")
print("--- PROC ---")
memory.write_qword(cl, uint64(pid))
-- EVFILT_PROC=-5 (0xFFFB), EV_ADD=1
memory.write_dword(cl + 8, 0x0001FFFB)
memory.write_dword(cl + 12, 0x7FFFFFFF)  -- all note flags
memory.write_qword(cl + 16, uint64(0))
memory.write_qword(cl + 24, uint64(0xCCCC))

for i = 0, 124, 4 do memory.write_dword(eventlist + i, 0) end

local ok3, ret3 = pcall(function()
    return make_syscall(363)(uint64(kq), uint64(cl), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout))
end)
print("ok=" .. tostring(ok3) .. " ret=" .. tostring(ret3))
if ok3 then
    local n = to_num(ret3)
    print("n=" .. n)
    for ev = 0, math.min(n - 1, 3) do
        local base = eventlist + ev * 32
        for off = 0, 28, 4 do
            local d = to_num(memory.read_dword(base + off))
            print(string.format("ev%d+0x%02X=0x%08X", ev, off, d))
        end
        for off = 0, 24, 8 do
            local q = memory.read_qword(base + off)
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then print("  *** KPTR at +" .. string.format("0x%02X", off) .. " ***") end
        end
    end
end

-- Test 4: Try EVFILT_USER (-11)
print("")
print("--- USER ---")
memory.write_qword(cl, uint64(42))
-- EVFILT_USER=-11 (0xFFF5), EV_ADD=1
memory.write_dword(cl + 8, 0x0001FFF5)
memory.write_dword(cl + 12, 0)
memory.write_qword(cl + 16, uint64(0))
memory.write_qword(cl + 24, uint64(0xDDDD))

for i = 0, 124, 4 do memory.write_dword(eventlist + i, 0) end

local ok4, ret4 = pcall(function()
    return make_syscall(363)(uint64(kq), uint64(cl), uint64(1),
        uint64(eventlist), uint64(4), uint64(timeout))
end)
print("ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))
if ok4 then
    local n = to_num(ret4)
    print("n=" .. n)
end

syscall.close(uint64(kq))
syscall.close(uint64(sock))
print("=== PROBE 85j COMPLETE ===")
