-- CRASH_CLASS: LOW
-- PROBE 470a: what does the dce command change in the world?
--
-- Context: 275a swept the full 32-bit ioctl encoding space on /dev/dce and
-- exactly one driver command returned 0: 0x80088209 (_IOW(0x82, 9), eight
-- bytes in). 276a proved it belongs to dce and no other node, and 277a
-- showed it copyins eight bytes, demands exactly len=8 and IOC_IN, and
-- accepts any content. Nobody asked what it *changes*: the command takes an
-- input but has no output, so if it does anything real it must move state
-- somewhere else — a file flag, a dce setting, a counter, or a second
-- command's answer.
--
-- This probe reads everything readable around it before and after, across a
-- content ladder and a 100 000-call hammer run, so an effect shows up as a
-- moved value or a flapped return.

print("=== PROBE 470a: the dce command's footprint ===")
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
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h % 0x100000000 == 0xFFFFFFFF and l % 0x100000000 == 0xFFFFFFFF then return -1 end
    if h == 0 and l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function wd(addr, v) return pcall(function() memory.write_dword(addr, v) end) end
local function wq(addr, v) return pcall(function() memory.write_qword(addr, v) end) end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -1
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local sc_fcntl = make_syscall(92)
local sc_fstat = make_syscall(189)
local sc_poll = make_syscall(209)

local DEC_CMD = 0x80088209
local FIODTYPE = 0x4004667A   -- the other dce 0-returner, reads a dword out
local F_GETFL = 3

local fd = sgn(sc_open(uint64(put_str("/dev/dce")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/dce")), uint64(0), uint64(0))) end
print(string.format("[0] open(/dev/dce)=%d", fd))
if fd < 0 then
    print("=== PROBE 470a ABORTED ===")
    return
end

local arg = memory.alloc(16)
local probe = memory.alloc(16)
local statbuf = memory.alloc(0x100)
local pollfd = memory.alloc(8)

-- One snapshot of every readable surface around the fd.
local function snapshot()
    local s = {}
    wq(arg, uint64(0))
    local r = sc_ioctl(uint64(fd), uint64(FIODTYPE), uint64(arg))
    s.dtype_ret = sgn(r)
    s.dtype_val = rd(arg)
    local g = sc_fcntl(uint64(fd), uint64(F_GETFL), uint64(0))
    s.getfl = sgn(g)
    for i = 0, 0xFF, 4 do wd(statbuf + i, 0) end
    s.fstat = sgn(sc_fstat(uint64(fd), uint64(statbuf)))
    s.st_mode = rd(statbuf + 8)
    s.st_nlink = rd(statbuf + 12)
    s.st_size_lo = rd(statbuf + 48)
    s.st_size_hi = rd(statbuf + 52)
    wd(pollfd, fd)
    wd(pollfd + 4, 0x0001)  -- POLLIN request; upper half takes revents
    s.poll = sgn(sc_poll(uint64(pollfd), uint64(1), uint64(0)))
    s.revents = math.floor(rd(pollfd + 4) / 0x10000)
    return s
end

local function show(tag, s)
    print(string.format("  %-14s dtype(ret=%d,val=0x%08X) getfl=%d fstat=%d mode=0x%08X nlink=%d size=%08X%08X poll=%d revents=0x%X",
        tag, s.dtype_ret, s.dtype_val, s.getfl, s.fstat, s.st_mode, s.st_nlink, s.st_size_hi, s.st_size_lo, s.poll, s.revents))
end

local function dce_call(q0, q1)
    wq(arg, uint64(q0))
    wd(arg + 8, 0)
    wd(arg + 12, 0)
    -- q1 chooses the second dword when it matters below
    if q1 ~= 0 then wd(arg + 8, q1 % 0x100000000) end
    return sgn(sc_ioctl(uint64(fd), uint64(DEC_CMD), uint64(arg)))
end

print("")
print("[A] baseline snapshot")
local base = snapshot()
show("baseline", base)

print("")
print("[B] content ladder: call, then snapshot")
local ladder = {
    { "q0=0", 0, 0 },
    { "q0=1", 1, 0 },
    { "q0=2", 2, 0 },
    { "q0=0x1000", 0x1000, 0 },
    { "q0=-1", 0xFFFFFFFF, 0 },
    { "q0=self", 0, 0 },  -- filled below
    { "q0=0x7fffffff", 0x7FFFFFFF, 0 },
}
for _, step in ipairs(ladder) do
    local name, q0, q1 = step[1], step[2], step[3]
    if name == "q0=self" then q0 = to_num(arg) end
    local r = dce_call(q0, q1)
    local s = snapshot()
    local moved = (s.dtype_val ~= base.dtype_val) or (s.getfl ~= base.getfl)
        or (s.st_mode ~= base.st_mode) or (s.st_size_lo ~= base.st_size_lo)
        or (s.poll ~= base.poll) or (s.revents ~= base.revents)
    show(name .. " ret=" .. r, s)
    if moved then print("    *** MOVED vs baseline ***") end
end

print("")
print("[C] 25000 hammer at q0=0x41, watching for a flapped return")
local flips = 0
for i = 1, 25000 do
    wq(arg, uint64(0x41))
    wd(arg + 8, 0)
    wd(arg + 12, 0)
    if sgn(sc_ioctl(uint64(fd), uint64(DEC_CMD), uint64(arg))) ~= 0 then
        flips = flips + 1
        if flips <= 5 then print("    iter " .. i .. " returned non-zero") end
    end
end
print("  flips: " .. flips .. " / 25000")
show("post-hammer", snapshot())

print("")
print("[D] 25000 hammer at q0=-1, then snapshot again")
flips = 0
for i = 1, 25000 do
    wq(arg, uint64(0xFFFFFFFF))
    wd(arg + 8, 0)
    wd(arg + 12, 0)
    if sgn(sc_ioctl(uint64(fd), uint64(DEC_CMD), uint64(arg))) ~= 0 then
        flips = flips + 1
        if flips <= 5 then print("    iter " .. i .. " returned non-zero") end
    end
end
print("  flips: " .. flips .. " / 25000")
show("post-hammer2", snapshot())

print("")
print("[E] a second fd: does one fd's call move the other's snapshot?")
local fd2 = sgn(sc_open(uint64(put_str("/dev/dce")), uint64(2), uint64(0)))
print(string.format("  fd2=%d", fd2))
if fd2 >= 0 then
    wq(arg, uint64(0))
    sc_ioctl(uint64(fd2), uint64(FIODTYPE), uint64(arg))
    local before = rd(arg)
    dce_call(0x1234, 0)
    wq(arg, uint64(0))
    sc_ioctl(uint64(fd2), uint64(FIODTYPE), uint64(arg))
    local after = rd(arg)
    print(string.format("  fd2 dtype: 0x%08X -> 0x%08X %s", before, after,
        before ~= after and "*** MOVED ***" or "(same)"))
    pcall(function() sc_close(uint64(fd2)) end)
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 470a COMPLETE ===")
