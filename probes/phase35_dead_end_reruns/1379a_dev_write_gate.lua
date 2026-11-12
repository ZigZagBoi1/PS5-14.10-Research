-- CRASH_CLASS: LOW -- open with write modes, write() ladders, and the cheap unrun calls.
-- PROBE 1379a: the O_WRONLY gate on /dev nodes, and write() on anything that opens
--
-- docs/DEVFS_GAP_ANALYSIS_14_10.md section 3, gap 5: "No probe has ever tried O_WRONLY on any
-- node." Every ioctl sweep in this repository opened O_RDONLY (or O_RDONLY|O_NONBLOCK), and a
-- driver that checks FWRITE returns EBADF before its d_ioctl runs, so a whole direction of
-- every driver table may have been invisible. 1038a's "rdonly" lines are exactly that: EBADF
-- on a read-only fd, not a measured refusal.
--
-- This probe answers three questions in one connection:
--   [A] which nodes accept O_WRONLY / O_RDWR at all (never measured),
--   [B] for those, what write(fd, page, len) returns at len 0, 1, 8, 0x10, 0x100, 0x1000 and
--       whether a second call agrees,
--   [C] the calls that were never made on a devfs fd: ftruncate, fsync, double close, and an
--       open of /dev/fd/22 to learn what the fd directory node answers.
--
-- Nothing here reads /dev/notification0 (writing is fine, reading wedges the Lua thread for
-- good - it is the one node a probe must never read). Every length is bounded at 0x1000.
--
-- -- prior art:
--   docs/DEVFS_GAP_ANALYSIS_14_10.md (gap 5, gap 6, section 8 traps)
--   results/phase17_new_vectors/1038a_device_read_write_20261103_181643.txt (read-only fds)
--   results/phase17_new_vectors/1067a_notification_write_len_20261104_093517.txt (the ladder)
--   results/phase17_new_vectors/1151a_devfs_open_modes_20261104_120816.txt (modes on refusing nodes)
--   docs/DEVICE_IOCTL_14_10.md (the gc/dce tables)

print("=== PROBE 1379a: O_WRONLY GATE AND write() ON /dev ===")

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
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function es()
    local ok, s = pcall(function() return get_error_string() end)
    if ok and type(s) == "string" then return s end
    return "?"
end
local mk = make_syscall
local S_OPEN, S_CLOSE, S_WRITE, S_FSYNC = mk(5), mk(6), mk(4), mk(95)
local S_FTRUNC, S_FSTAT = mk(480), mk(189)

local path = memory.alloc(0x100)
local pa = to_num(path)
local function setpath(p)
    pcall(function() memory.write_buffer(path, p .. string.rep("\0", 0x80 - #p)) end)
end

local PAGE = memory.alloc(0x4000)
local PAGE_A = to_num(PAGE)
pcall(function() memory.write_buffer(PAGE, string.rep(string.char(0xAA), 0x1000)) end)

local function openm(p, flags)
    setpath(p)
    local ok, rv = pcall(function() return S_OPEN(uint64(pa), uint64(flags), uint64(0)) end)
    if not ok then return "EXC" end
    return to_num(rv)
end
local function closefd(fd)
    local ok = pcall(function() return S_CLOSE(uint64(fd)) end)
    return ok
end

-- O_WRONLY = 1, O_RDWR = 2, O_RDONLY = 0, O_NONBLOCK = 0x4000 on this platform
local NODES = {"usb", "usbctl", "ugen0.2", "ajm", "ajmi", "rng", "sce_zlib", "dmem0",
               "dmem1", "dmem2", "uvd_enc", "dipsw", "hmd_cmd", "hmd2_cmd", "bt",
               "notification0", "gic", "gc", "dce", "camera", "hid", "deci_stdout"}
local LENS = {0, 1, 8, 0x10, 0x100, 0x1000}

print("[A] open modes per node: W=O_WRONLY R=O_RDWR N=O_WRONLY|O_NONBLOCK")
local writable = {}
for i = 1, #NODES do
    local n = NODES[i]
    local w = openm("/dev/" .. n, 1)
    local we = (w == -1) and es() or ""
    local r = openm("/dev/" .. n, 2)
    local re2 = (r == -1) and es() or ""
    local nb = openm("/dev/" .. n, 0x4001)
    local nbe = (nb == -1) and es() or ""
    print(string.format("  %-14s W=%s%s R=%s%s N=%s%s", n, tostring(w), we ~= "" and ("(" .. we .. ")") or "",
        tostring(r), re2 ~= "" and ("(" .. re2 .. ")") or "",
        tostring(nb), nbe ~= "" and ("(" .. nbe .. ")") or ""))
    local fd = -1
    if w ~= -1 and w ~= "EXC" then fd = w
    elseif r ~= -1 and r ~= "EXC" then fd = r
    elseif nb ~= -1 and nb ~= "EXC" then fd = nb end
    if fd ~= -1 then writable[#writable + 1] = {n, fd} end
    -- close the ones we did not keep
    for _, v in ipairs({w, r, nb}) do
        if v ~= -1 and v ~= "EXC" and v ~= fd then closefd(v) end
    end
end

print("[B] write() ladders on the fds that opened writable")
if #writable == 0 then
    print("  none")
end
for i = 1, #writable do
    local n, fd = writable[i][1], writable[i][2]
    print("w" .. n)
    local prev = nil
    for j = 1, #LENS do
        local len = LENS[j]
        local ok, rv = pcall(function() return S_WRITE(uint64(fd), uint64(PAGE_A), uint64(len)) end)
        local r = ok and to_num(rv) or "EXC"
        local same = (prev == r) and " same" or ""
        prev = r
        print(string.format("  %-14s fd=%d len=0x%X rv=%s%s%s", n, fd, len, tostring(r), same,
            (r == -1 and ok) and (" errno=" .. es()) or ""))
    end
    closefd(fd)
end

print("[C] the calls never made on a devfs fd")
local fd = openm("/dev/gc", 0)
if fd ~= -1 then
    print(string.format("  gc fd=%d", fd))
    local ok1, r1 = pcall(function() return S_FTRUNC(uint64(fd), uint64(0)) end)
    print(string.format("  ftruncate(gc,0) rv=%s%s", tostring(ok1 and to_num(r1) or "EXC"),
        (ok1 and to_num(r1) == -1) and (" errno=" .. es()) or ""))
    local ok2, r2 = pcall(function() return S_FTRUNC(uint64(fd), uint64(0x1000)) end)
    print(string.format("  ftruncate(gc,0x1000) rv=%s%s", tostring(ok2 and to_num(r2) or "EXC"),
        (ok2 and to_num(r2) == -1) and (" errno=" .. es()) or ""))
    local ok3, r3 = pcall(function() return S_FSYNC(uint64(fd)) end)
    print(string.format("  fsync(gc) rv=%s%s", tostring(ok3 and to_num(r3) or "EXC"),
        (ok3 and to_num(r3) == -1) and (" errno=" .. es()) or ""))
    local ok4, r4 = pcall(function() return S_CLOSE(uint64(fd)) end)
    local ok5, r5 = pcall(function() return S_CLOSE(uint64(fd)) end)
    print(string.format("  close twice: %s then %s%s", tostring(ok4 and to_num(r4) or "EXC"),
        tostring(ok5 and to_num(r5) or "EXC"),
        (ok5 and to_num(r5) == -1) and (" errno=" .. es()) or ""))
else
    print("  gc did not open read-only")
end
local fdx = openm("/dev/fd/22", 0)
print(string.format("  /dev/fd/22 open=%s%s", tostring(fdx), (fdx == -1) and (" errno=" .. es()) or ""))
if fdx ~= -1 then
    local okr, rr = pcall(function() return mk(3)(uint64(fdx), uint64(PAGE_A), uint64(0x40)) end)
    print(string.format("  read(/dev/fd/22) rv=%s", tostring(okr and to_num(rr) or "EXC")))
    closefd(fdx)
end

print("=== PROBE 1379a COMPLETE ===")
