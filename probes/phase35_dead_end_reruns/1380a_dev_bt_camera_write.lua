-- CRASH_CLASS: MODERATE -- write() into the bluetooth and camera drivers.
-- PROBE 1380a: /dev/bt and /dev/camera accept write() on an O_WRONLY fd
--
-- 1379a (results/phase35_dead_end_reruns/1379a_dev_write_gate_20261109_132830.txt) found that
-- every openable /dev node accepts O_WRONLY - the "rdonly" lines in the corpus were EBADF on
-- read-only fds, never a driver refusal - and that two nodes answer a write() with something
-- other than ENOTTY:
--
--   /dev/bt     len 0  -> -1 EINVAL, len 1 -> -1 EINVAL, len 8 -> rv=8, len 0x10 -> -1 EINVAL
--   /dev/camera len 0  -> -1 0x802E0010, len 1 -> rv=1, len 8 -> -1 0x802E0010
--
-- A length-exact acceptance is the signature of a message parser: /dev/bt took exactly eight
-- bytes, which is the shape of a request header (HCI command header plus one byte, or a
-- Sony 8-byte control block). Every earlier ioctl sweep used a read-only fd, so the whole
-- write-side of these drivers has never been measured.
--
-- This probe maps the acceptance set by length, checks whether the payload changes the answer
-- (which would prove the bytes are parsed), reads back afterwards to see whether the driver
-- queues a response, and re-calls four known /dev/gc commands on a writable fd to see whether
-- the FWRITE check was gating them.
--
-- Nothing reads /dev/notification0. Every length is bounded at 0x100.
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1379a_dev_write_gate_20261109_132830.txt (the O_WRONLY gate)
--   results/phase17_new_vectors/1038a_device_read_write_20261103_182309.txt (read-only fds)
--   results/phase17_new_vectors/288a_node_ioctl_groups_20261022_104212.txt (usb command tables)
--   docs/DEVFS_GAP_ANALYSIS_14_10.md (gap 5)

print("=== PROBE 1380a: write() INTO /dev/bt AND /dev/camera ===")

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
local S_OPEN, S_CLOSE, S_READ, S_WRITE, S_IOCTL = mk(5), mk(6), mk(3), mk(4), mk(54)

local path = memory.alloc(0x100)
local pa = to_num(path)
local function openm(p, flags)
    pcall(function() memory.write_buffer(path, p .. string.rep("\0", 0x80 - #p)) end)
    local ok, rv = pcall(function() return S_OPEN(uint64(pa), uint64(flags), uint64(0)) end)
    if not ok then return -1 end
    return to_num(rv)
end

local PB = memory.alloc(0x2000)
local PB_A = to_num(PB)

local function fill(n, byte)
    pcall(function() memory.write_buffer(PB, string.rep(string.char(byte), 0x100)) end)
    if n > 0x100 then pcall(function() memory.write_buffer(PB, string.rep(string.char(byte), n)) end) end
end

local function wr(fd, len)
    local ok, rv = pcall(function() return S_WRITE(uint64(fd), uint64(PB_A), uint64(len)) end)
    if not ok then return "EXC" end
    return to_num(rv)
end
local function rd(fd, len)
    local ok, rv = pcall(function() return S_READ(uint64(fd), uint64(PB_A), uint64(len)) end)
    if not ok then return "EXC" end
    return to_num(rv)
end
local function scan(n)
    local changed, first = 0, ""
    local ok, s = pcall(function() return memory.read_buffer(PB, n) end)
    if not (ok and type(s) == "string") then return 0, "" end
    for i = 1, #s, 4 do
        if #s - i >= 3 then
            local a, b, c, d = string.byte(s, i, i + 3)
            if not (a == 0xAA and b == 0xAA and c == 0xAA and d == 0xAA) then
                changed = changed + 1
                if #first < 48 then first = first .. string.format(" %02X%02X%02X%02X", d, c, b, a) end
            end
        end
    end
    return changed, first
end

local function ladder(name, startlen, endlen)
    local fd = openm(name, 1)
    if fd == -1 then
        print(string.format("  %s O_WRONLY failed: %s", name, es()))
        return nil, -1
    end
    print(string.format("  %s fd=%d", name, fd))
    local oklen = {}
    for len = startlen, endlen do
        fill(len, 0xAA)
        local rv = wr(fd, len)
        if rv ~= -1 and rv ~= "EXC" then
            oklen[#oklen + 1] = len
            print(string.format("    len=0x%X rv=%s ACCEPTED", len, tostring(rv)))
        end
    end
    print(string.format("    accepted lengths: %d", #oklen))
    return fd, oklen
end

print("[A] /dev/bt length ladder, payload 0xAA")
local btfd, btok = ladder("/dev/bt", 0, 0x40)
if btfd then
    if btok and #btok > 0 then
        local L = btok[1]
        print(string.format("  [B] payload sensitivity at len=0x%X", L))
        for _, pat in ipairs({{0x00, "zeros"}, {0xFF, "0xFF"}, {0x41, "0x41"}}) do
            fill(L, pat[1])
            local rv = wr(btfd, L)
            print(string.format("    %-6s rv=%s%s", pat[2], tostring(rv), (rv == -1) and (" errno=" .. es()) or ""))
        end
        fill(L, 0xAA)
        pcall(function() memory.write_dword(PB, 1) end)
        print(string.format("    dword0=1 rv=%s", tostring(wr(btfd, L))))
        pcall(function() memory.write_dword(PB, 0x100) end)
        print(string.format("    dword0=0x100 rv=%s", tostring(wr(btfd, L))))
        print("  [C] read back after the writes")
        fill(0x40, 0xAA)
        print(string.format("    read(0x40) rv=%s changed=%d%s", tostring(rd(btfd, 0x40)),
            select(1, scan(0x40)), select(2, scan(0x40))))
    end
    pcall(function() S_CLOSE(uint64(btfd)) end)
end

print("[D] /dev/camera length ladder")
local camfd, camok = ladder("/dev/camera", 0, 0x10)
if camfd then
    if camok and #camok > 0 then
        local L = camok[1]
        for _, pat in ipairs({{0x00, "zeros"}, {0xFF, "0xFF"}, {0x41, "0x41"}}) do
            fill(L, pat[1])
            print(string.format("    %-6s rv=%s", pat[2], tostring(wr(camfd, L))))
        end
        fill(0x40, 0xAA)
        print(string.format("  camera read(0x40) rv=%s changed=%d%s", tostring(rd(camfd, 0x40)),
            select(1, scan(0x40)), select(2, scan(0x40))))
    end
    pcall(function() S_CLOSE(uint64(camfd)) end)
end

print("[E] four /dev/gc commands on a writable fd (the FWRITE gate question)")
local gcw = openm("/dev/gc", 1)
local gcr = openm("/dev/gc", 0)
print(string.format("  gc writable fd=%s read fd=%s", tostring(gcw), tostring(gcr)))
local GCMC = {0xC008811B, 0xC0048113, 0x40048135, 0xC010810B}
for i = 1, #GCMC do
    local cmd = GCMC[i]
    pcall(function() memory.write_buffer(PB, string.rep(string.char(0xAA), 0x100)) end)
    local ok1, r1 = pcall(function() return S_IOCTL(uint64(gcw), uint64(cmd), uint64(PB_A)) end)
    local w_changed, w_first = scan(0x40)
    pcall(function() memory.write_buffer(PB, string.rep(string.char(0xAA), 0x100)) end)
    local ok2, r2 = pcall(function() return S_IOCTL(uint64(gcr), uint64(cmd), uint64(PB_A)) end)
    local r_changed, r_first = scan(0x40)
    print(string.format("  cmd=0x%X W:rv=%s wrote=%d%s  R:rv=%s wrote=%d%s", cmd,
        tostring(ok1 and to_num(r1) or "EXC"), w_changed, w_first ~= "" and ("[" .. w_first .. "]") or "",
        tostring(ok2 and to_num(r2) or "EXC"), r_changed, r_first ~= "" and ("[" .. r_first .. "]") or ""))
end
if gcw ~= -1 then pcall(function() S_CLOSE(uint64(gcw)) end) end
if gcr ~= -1 then pcall(function() S_CLOSE(uint64(gcr)) end) end

print("=== PROBE 1380a COMPLETE ===")
