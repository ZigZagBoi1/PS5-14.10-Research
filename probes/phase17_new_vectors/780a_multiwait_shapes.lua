-- CRASH_CLASS: LOW
-- PROBE 780a: aio_multi_wait argument shapes on genuinely in-flight requests
--
-- Context: 778b parked two requests in state 2 and multi_wait returned -1 with
-- no status writeback; 779a's three requests never started because two
-- in-flight requests from the previous run were still occupying the workers
-- (an in-flight request cannot be deleted: the delete state gate wants 3 or 4).
--
-- This probe runs shapes in a fresh process, cancels and deletes after every
-- shape so nothing is leaked, and prints the worker-visible state before and
-- after each wait. Shape order matters: the last shape is the one most likely
-- to leak.

print("=== PROBE 780a: MULTI_WAIT SHAPES ===")

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
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end

local sink   = to_num(memory.alloc(0x2000))
local req    = to_num(memory.alloc(0x1000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout  = to_num(memory.alloc(0x40))
local tmo    = to_num(memory.alloc(0x40))
local feed   = to_num(memory.alloc(0x100))
local fds    = to_num(memory.alloc(64))
for i = 0, 0x3FF do wd(req + i * 4, 0) end
for i = 0, 0x3F do memory.write_byte(feed + i, 0x41 + (i % 26)) end

local SOCKETPAIR, WRITE, IOCTL = 135, 4, 54
local AIO_DEL, AIO_WAIT, AIO_POLL, AIO_CANCEL, AIO_SUBMIT = 662, 663, 664, 666, 669

local function pair()
    wd(fds, 0); wd(fds + 4, 0)
    local r = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
    return r, rd(fds), rd(fds + 4)
end
local function submit(slot, fd)
    wq(req + slot * 0x40 + 0x00, Z)
    wq(req + slot * 0x40 + 0x08, U(16))
    wq(req + slot * 0x40 + 0x10, U(sink + slot * 0x40))
    wq(req + slot * 0x40 + 0x18, U(sink + 0x1000 + slot * 8))
    wd(req + slot * 0x40 + 0x20, fd)
    wd(req + slot * 0x40 + 0x24, 0)
    local r = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req + slot * 0x40), U(1), U(3), U(idout), Z))
    return r, rd(idout)
end
local function poll_n(n)
    wd(states, 0xDEADBEEF)
    local r = sgn(make_syscall(AIO_POLL)(U(ids), U(n), U(states), Z, Z, Z))
    local out = {}
    for i = 0, n - 1 do out[i] = rd(states + i * 4) end
    return r, out
end
local function show(tag, r, s, n)
    local parts = {}
    for i = 0, n - 1 do parts[#parts + 1] = hx(s[i]) end
    print(string.format("[%s] ret=%d states=%s", tag, r, table.concat(parts, " ")))
end
local function cleanup(n)
    local c = sgn(make_syscall(AIO_CANCEL)(U(ids), U(n), U(states), Z, Z, Z))
    local d = sgn(make_syscall(AIO_DEL)(U(ids), U(n), U(states), Z, Z, Z))
    local parts = {}
    for i = 0, n - 1 do parts[#parts + 1] = hx(rd(states + i * 4)) end
    print(string.format("[cleanup] cancel=%d delete=%d status=%s", c, d, table.concat(parts, " ")))
end

-- shape 1: two in-flight requests, wait with mode 0
local function shape(tag, mode, us, do_feed, n)
    local pr, rfd, wfd = pair()
    print(string.format("[%s] socketpair=%d rfd=%d", tag, pr, rfd))
    for i = 0, n - 1 do
        local r, id = submit(i, rfd)
        wd(ids + i * 4, id)
        print(string.format("[%s] submit%d ret=%d id=%s", tag, i, r, hx(id)))
    end
    local _, s0 = poll_n(n)
    show(tag .. "-pre", 0, s0, n)
    if do_feed then
        local w = sgn(make_syscall(WRITE)(U(wfd), U(feed), U(n * 16), Z, Z, Z))
        print(string.format("[%s] feed ret=%d", tag, w))
        local _, s1 = poll_n(n)
        show(tag .. "-fed", 0, s1, n)
    end
    wd(tmo, us)
    wd(states, 0xDEADBEEF)
    local w = sgn(make_syscall(AIO_WAIT)(U(ids), U(n), U(states), U(mode), U(tmo), Z))
    local parts = {}
    for i = 0, n - 1 do parts[#parts + 1] = hx(rd(states + i * 4)) end
    print(string.format("[%s] wait(mode=%d us=%d) ret=%d states=%s", tag, mode, us, w, table.concat(parts, " ")))
    local _, s2 = poll_n(n)
    show(tag .. "-post", 0, s2, n)
    cleanup(n)
end

shape("A", 0, 10000, false, 2)
shape("B", 2, 10000, false, 2)
shape("C", 0, 10000, true, 2)

print("=== PROBE 780a DONE ===")
