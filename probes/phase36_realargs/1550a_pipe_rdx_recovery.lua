-- CRASH_CLASS: LOW
-- PROBE 1550a: does pipe(42) actually work, with fd1 hidden in rdx?
--
-- prior art:
--   docs/DEAD_ENDS.md:33  "pipe(42) via make_syscall — returns fds 0,0 (dead)"
--   .local/build/SAVEDATA/misc.lua:391 create_pipe():
--       -- HACK: current syscall wrapper that we use in ps5 (gettimeofday) doesn't
--       --       handle pipe() return values correctly (rax/rdx). use rop to manually
--       --       get the return values
--       chain:push_syscall(syscall.pipe)
--       chain:push_store_rax_into_memory(fildes)
--       chain:push_store_rdx_into_memory(fildes + 4)
--     i.e. on PS5 the pair comes back as fd0=rax, fd1=rdx, and the fildes[]
--     array is never written. A plain Lua syscall call returns only rax, so a
--     probe that reads fildes[] sees (0,0) — which is exactly the dead-end row.
--   probes/phase36_realargs/1537b_sys548_op4_and_op0_semantics.lua (helper style)
--   results/phase36_realargs/1537b_sys548_op4_and_op0_semantics_20261110_151410.txt
--
-- Hypothesis: pipe(42) succeeds and allocates a real pair, and the DEAD_ENDS
-- row is a probe artefact. WHICH register carries fd1 is a separate question
-- and this probe answers it only if fildes[] turns out to be unwritten: a plain
-- FreeBSD compat10.pipe returns 0 and fills fildes[], so the [D] verdict
-- compares fildes[] against the diff-recovered pair instead of assuming.
--
-- Method (zero deaths expected, nothing is written to an unknown fd):
--   [A] fstat every fd in 0..40, before.
--   [B] pipe(42) once.
--   [C] fstat every fd in 0..40, after. Exactly two fds that were closed and
--       are now open = the pair, identified without guessing.
--   [D] round-trip 4 bytes fd0->fd1 and fd1->fd0 on the pair.
--   [E] close both.
-- fstat(189) is measured working (353c) and is read-only.

print("=== PROBE 1550a: pipe(42) fd recovery ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end

local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function rd(a)
    local ok, val = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(val) end
    return nil
end

local sc_fstat = mk(189)
local stbuf = memory.alloc(0x100)

-- returns true if fstat(fd) reports an open descriptor
local function open_fd(fd)
    pcall(function()
        for i = 0, 0xFC, 4 do memory.write_dword(uint64(stbuf + i), 0) end
    end)
    local ok, rv = pcall(function()
        return sc_fstat(uint64(fd), uint64(stbuf), uint64(0),
                        uint64(0), uint64(0), uint64(0))
    end)
    if not ok then return false end
    return to_num(rv) == 0
end

-- A fresh process already holds fds 0..23 (1024a), and a probe that opens the
-- /dev nodes holds more than 58, so the pipe pair can land above 40.
local FDMAX = 128

local fd = rd(signal.fd_addr) or 0
local pid = to_num(mk(20)())
print(string.format("[0] pid=%u sink_fd=%u", pid, fd))
if pid == 0 then
    print("=== ABORT: no pid ===")
    return
end

-- ---- [A] before ----
local before = {}
local line = {}
for i = 0, FDMAX do
    before[i] = open_fd(i)
    line[#line + 1] = before[i] and tostring(i) or "."
end
print("[A] open before: " .. table.concat(line, ""))

-- ---- [B] pipe ----
local fildes = memory.alloc(0x10)
pcall(function()
    for i = 0, 0xC, 4 do memory.write_dword(uint64(fildes + i), 0xDEADBEEF) end
end)
local sc_pipe = mk(42)
print("[B] calling 42(fildes) ...")
local okb, rvb = pcall(function()
    return sc_pipe(uint64(fildes), uint64(0), uint64(0),
                   uint64(0), uint64(0), uint64(0))
end)
local rv = okb and to_num(rvb) or -999
print(string.format("[B] rv=%d  fildes[0]=0x%X fildes[1]=0x%X",
    rv, rd(fildes) or 0, rd(fildes + 4) or 0))

if rv < 0 then
    print("[B] pipe refused at the syscall — the dead end stands as written.")
    print("=== DONE (refused) ===")
    return
end

-- ---- [C] after ----
local newfds = {}
line = {}
for i = 0, FDMAX do
    local now = open_fd(i)
    if now and not before[i] then newfds[#newfds + 1] = i end
    line[#line + 1] = now and tostring(i) or "."
end
print("[C] open after : " .. table.concat(line, ""))
print(string.format("[C] new fds: n=%d  [%s]",
    #newfds, table.concat(newfds, ",")))

if #newfds < 2 then
    print("[C] fewer than two new descriptors — pipe did not allocate a pair.")
    if rv >= 0 then
        print(string.format("[C] rv=%d is a success code, not a descriptor", rv))
    end
    -- do not leak what the scan did find: both pipe ends stay open for the
    -- life of the process and shift the fd table for every later probe.
    local sc_close0 = mk(6)
    for _, f in ipairs(newfds) do
        pcall(function() sc_close0(uint64(f), uint64(0), uint64(0),
                                  uint64(0), uint64(0), uint64(0)) end)
    end
    print("=== DONE (no pair) ===")
    return
end

local fd0 = newfds[1]
local fd1 = newfds[2]
print(string.format("[C] pair = fd0=%d fd1=%d  (rax claimed %d)", fd0, fd1, rv))

-- ---- [D] round-trip ----
local buf = memory.alloc(0x10)
local rbuf = memory.alloc(0x10)
local function wd(a, v) memory.write_dword(uint64(a), v) end
local sc_write = mk(4)
local sc_read = mk(3)

local function roundtrip(wfd, rfd, tag)
    pcall(function()
        wd(buf, 0x41424344)
        for i = 0, 0xC, 4 do wd(rbuf + i, 0) end
    end)
    print(string.format("[D] %s write(%d) ...", tag, wfd))
    local okw, rvw = pcall(function()
        return sc_write(uint64(wfd), uint64(buf), uint64(4),
                        uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("[D] %s write rv=%d", tag, okw and to_num(rvw) or -999))
    print(string.format("[D] %s read(%d) ...", tag, rfd))
    local okr, rvr = pcall(function()
        return sc_read(uint64(rfd), uint64(rbuf), uint64(4),
                       uint64(0), uint64(0), uint64(0))
    end)
    local got = rd(rbuf) or 0
    print(string.format("[D] %s read rv=%d  got=0x%X %s", tag,
        okr and to_num(rvr) or -999, got,
        got == 0x41424344 and "<<< ROUND TRIP OK" or ""))
    return got == 0x41424344
end

local fwd = roundtrip(fd1, fd0, "fwd")
local rev = roundtrip(fd0, fd1, "rev")
print(string.format("[D] VERDICT fwd=%s rev=%s", tostring(fwd), tostring(rev)))

if fwd or rev then
    -- A plain FreeBSD pipe returns 0 and fills fildes[]. Only the fildes[]
    -- contents can separate that from the rax/rdx claim, so print them.
    local f0, f1 = rd(fildes), rd(fildes + 4)
    print(string.format("[D] diff pair fd0=%d fd1=%d  rv=%d  fildes=[%s,%s]",
        fd0, fd1, rv, tostring(f0), tostring(f1)))
    if f0 == fd0 and f1 == fd1 then
        print("[D] pipe(42) returns 0 and FILLS fildes[] — a plain FreeBSD pipe.")
        print("[D] The DEAD_ENDS row is a probe artefact, but the rax/rdx story is not needed.")
    elseif f0 ~= fd0 and f0 ~= f1 then
        print("[D] fildes[] does NOT hold the pair; returned rv=" .. rv)
        print("[D] pair recovered by fd-diff only: which register carries fd1 is UNRESOLVED.")
    else
        print("[D] fildes[] and the diff disagree — record both, conclude nothing.")
    end
else
    print("[D] two descriptors appeared but no bytes moved — investigate.")
end

-- ---- [E] teardown ----
local sc_close = mk(6)
for _, f in ipairs(newfds) do
    print(string.format("[E] close(%d) ...", f))
    local okc, rvc = pcall(function()
        return sc_close(uint64(f), uint64(0), uint64(0),
                        uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("[E] close rv=%d", okc and to_num(rvc) or -999))
end

print("=== PROBE 1550a COMPLETE ===")
