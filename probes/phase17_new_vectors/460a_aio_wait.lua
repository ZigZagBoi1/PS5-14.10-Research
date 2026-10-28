-- CRASH_CLASS: MODERATE
-- PROBE 460a: call aio_multi_wait (663) with a real request for the first time
--
-- 663 is the one AIO entry that has only ever been called with six zeros; it
-- answered -1, which says nothing.  Its 13.60 contract is five slots
-- (id_array, count 1..128, state_array, mode < 3, optional 4-byte timeout).
-- The public Relapse chain's kernel stage names a use-after-free race in this
-- exact routine, so the first question is whether it works at all.
--
-- This probe submits one request through 669 and then waits on it, with a
-- ready target (/dev/zero) and a pending one (a socketpair nobody writes to).

print("=== PROBE 460a: AIO MULTI WAIT ===")
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
local function sgn(v)
    if type(v) ~= "table" or not v.h then
        local n = tonumber(v) or 0
        if n < 0 then return -1 end
        return n
    end
    local h = tonumber(v.h) or 0
    local l = tonumber(v.l) or 0
    if h == -1 or h == 0xFFFFFFFF then
        if l == -1 or (l % 4294967296) == 0xFFFFFFFF then return -1 end
    end
    if h ~= 0 then return nil end
    return l
end
local function fmt(v) if v == nil then return "BIG" end return tostring(v) end
local function rd(addr) return to_num(memory.read_dword(uint64(addr))) end
local function wr(addr, v) memory.write_dword(uint64(addr), uint64(v)) end
local function wrq(addr, v) memory.write_qword(uint64(addr), uint64(v)) end

local sc_open  = make_syscall(5)
local sc_close = make_syscall(6)
local sc_mmap  = make_syscall(477)
local SOCKPAIR = make_syscall(135)
local AIO_SUBMIT = make_syscall(669)
local AIO_DELETE = make_syscall(662)
local AIO_WAIT   = make_syscall(663)
local AIO_POLL   = make_syscall(664)

local function put_path(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do memory.write_byte(b + i - 1, s:byte(i)) end
    memory.write_byte(b + #s, 0)
    return b
end
local function open_node(path, flags)
    return sgn(sc_open(uint64(to_num(put_path(path))), uint64(flags), uint64(0), uint64(0), uint64(0), uint64(0)))
end

local PAGE = 0x3000
local page = to_num(sc_mmap(uint64(0), uint64(PAGE), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
if page <= 0 or page >= 0x800000000000 then print("mmap failed"); return end
local REQ = page            -- 0x28 descriptor
local IDS = page + 0x100    -- id array
local STATES = page + 0x200 -- state array
local TMO = page + 0x300    -- 4-byte timeout
local DATA = page + 0x400   -- 0x40 data buffer
local RESULT = page + 0x500 -- result word
for i = 0, PAGE - 1, 8 do memory.write_qword(uint64(page + i), uint64(0)) end

local function descriptor(fd, nbytes, data, result)
    for i = 0, 0x27, 8 do wrq(REQ + i, 0) end
    wrq(REQ + 0x00, 0)          -- offset
    wrq(REQ + 0x08, nbytes)     -- byte count
    wrq(REQ + 0x10, data)       -- data pointer
    wrq(REQ + 0x18, result)     -- result pointer
    wr(REQ + 0x20, fd)          -- fd
end

local function submit(fd, nbytes)
    descriptor(fd, nbytes, DATA, RESULT)
    wrq(IDS, 0)
    local rv = sgn(AIO_SUBMIT(uint64(1), uint64(REQ), uint64(1), uint64(1), uint64(IDS), uint64(0)))
    return rv, rd(IDS)
end

local function wait(ids, count, mode, tmo)
    wrq(STATES, 0)
    local arg5 = uint64(0)
    if tmo then wr(TMO, tmo); arg5 = uint64(TMO) end
    local rv = sgn(AIO_WAIT(uint64(ids), uint64(count), uint64(STATES), uint64(mode), arg5, uint64(0)))
    return rv, rd(STATES), rd(TMO)
end

print("[A] ready target: /dev/zero")
local zero = open_node("/dev/zero", 2)
print(string.format("    fd=%s", tostring(zero)))
if zero and zero > 0 then
    local rv, id = submit(zero, 16)
    print(string.format("    669 rv=%s id=0x%X result=0x%X", fmt(rv), id, rd(RESULT)))
    local w, st, tmo = wait(IDS, 1, 0, 100)
    print(string.format("    663 mode=0 rv=%s states=0x%X tmo=%d", fmt(w), st, tmo))
    local w2, st2 = wait(IDS, 1, 1, 100)
    print(string.format("    663 mode=1 rv=%s states=0x%X", fmt(w2), st2))
    local w3, st3 = wait(IDS, 1, 2, 100)
    print(string.format("    663 mode=2 rv=%s states=0x%X", fmt(w3), st3))
    local d = sgn(AIO_DELETE(uint64(IDS), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0)))
    print(string.format("    662 delete rv=%s", fmt(d)))
    local w4, st4 = wait(IDS, 1, 0, 100)
    print(string.format("    663 after delete rv=%s states=0x%X", fmt(w4), st4))
end
print("")

print("[B] pending target: socketpair read")
local fds = page + 0x600
wrq(fds, 0)
local pr = sgn(SOCKPAIR(uint64(1), uint64(1), uint64(0), uint64(fds), uint64(0), uint64(0)))
local a, b = rd(fds), rd(fds + 4)
print(string.format("    socketpair rv=%s read=%d write=%d", fmt(pr), a, b))
if pr == 0 and a and a > 0 and a < 0x100000 then
    local rv, id = submit(a, 16)
    print(string.format("    669 rv=%s id=0x%X result=0x%X", fmt(rv), id, rd(RESULT)))
    local t0 = 0
    local w, st, tmo = wait(IDS, 1, 0, 100)
    print(string.format("    663 mode=0 rv=%s states=0x%X tmo=%d result=0x%X", fmt(w), st, tmo, rd(RESULT)))
    local p, ps = nil, nil
    local prv = sgn(AIO_POLL(uint64(IDS), uint64(1), uint64(page + 0x700), uint64(0), uint64(0), uint64(0)))
    print(string.format("    664 poll rv=%s state=0x%X", fmt(prv), rd(page + 0x700)))
    -- make the request ready from the other end and wait again
    local msg = memory.alloc(16)
    for i = 0, 15 do memory.write_byte(msg + i, 0x41) end
    local sent = sgn(syscall.write(uint64(b), uint64(to_num(msg)), uint64(16)))
    print(string.format("    write peer=%s", fmt(sent)))
    local w2, st2 = wait(IDS, 1, 0, 200)
    print(string.format("    663 after data rv=%s states=0x%X result=0x%X data=%08X", fmt(w2), st2, rd(RESULT), rd(DATA)))
end
print("")

print("[C] argument controls")
local w5, st5 = wait(IDS, 0, 0, 10)
print(string.format("    count=0   rv=%s", fmt(w5)))
local w6 = sgn(AIO_WAIT(uint64(IDS), uint64(129), uint64(STATES), uint64(0), uint64(0), uint64(0)))
print(string.format("    count=129 rv=%s", fmt(w6)))
local w7 = sgn(AIO_WAIT(uint64(IDS), uint64(1), uint64(STATES), uint64(3), uint64(0), uint64(0)))
print(string.format("    mode=3    rv=%s", fmt(w7)))
local w8 = sgn(AIO_WAIT(uint64(0), uint64(1), uint64(STATES), uint64(0), uint64(0), uint64(0)))
print(string.format("    null ids  rv=%s", fmt(w8)))
local bogus = page + 0x800
wrq(bogus, 0xDEAD)
local w9, st9 = wait(bogus, 1, 0, 10)
print(string.format("    bogus id  rv=%s states=0x%X", fmt(w9), st9))

print("")
print("=== 460a DONE ===")
