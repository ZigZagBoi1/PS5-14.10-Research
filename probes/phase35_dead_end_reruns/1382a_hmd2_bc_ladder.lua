-- CRASH_CLASS: MODERATE -- length ladder on the one ioctl type byte that answers on hmd2_cmd.
-- PROBE 1382a: /dev/hmd2_cmd, type 0xBC, len 0..0x200, dir 0x80/0xC0/0x40
--
-- 1381a (results/phase35_dead_end_reruns/1381a_hmd2_cmd_sweep_20261109_133040.txt) swept
-- dir x len x type x num on /dev/hmd2_cmd: 1 376 256 calls, 1 376 229 of them the generic
-- 0x8A721003, and every one of the 26 survivors sits in **type 0xBC** with direction
-- 0x80000000 (IOW):
--
--   0x8004BC1D -> 0                      (the only success)
--   0x8004BC08, 0x8008BC01/04/09/10/15/17/18/22/33, 0x8018BC02 -> 0x8A720004
--   0x8008BC0C/0D/0E, 0x8010BC05/07/21, 0x8040BC1F/20        -> 0x8A721009
--   0x8008BC1E -> 0x8A721008
--   0x8004BC23, 0x8008BC24/2E                                -> 0x800D0203 (no such command)
--
-- A 0x8A72xxxx code is the driver's own status, and four different low words for the same
-- (type, num) at different lengths is the signature of a size check: the command number is
-- recognised but the declared length is wrong for it. The length field is part of the ioctl
-- number, so walking it is how the real struct size for each command is found - and the one
-- command that already returns 0 at length 4 may return data at its true length in the
-- IOWR direction.
--
-- This probe fixes the type byte at 0xBC, walks len 0..0x200 for the three useful directions,
-- and prints every answer that is not the generic 0x8A721003, with the changed-dword count of
-- a 0x400-byte 0xAA page (the driver may write up to its declared length).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1381a_hmd2_cmd_sweep_20261109_133040.txt
--   results/phase17_new_vectors/360a_encrypt_ioctl_matrix_20261022_175029.txt
--   results/phase17_new_vectors/283a_gc_struct_commands_20261022_*.txt (the pointer-follow test)
--   docs/DEVFS_GAP_ANALYSIS_14_10.md (rank 1)

print("=== PROBE 1382a: /dev/hmd2_cmd, TYPE 0xBC LENGTH LADDER ===")

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
local mk = make_syscall
local S_OPEN, S_CLOSE, S_IOCTL, S_PID = mk(5), mk(6), mk(54), mk(20)

print(string.format("[0] pid=%d", to_num(S_PID(U(0,0),U(0,0),U(0,0),U(0,0),U(0,0),U(0,0)))))

local path = memory.alloc(0x100)
local pa = to_num(path)
pcall(function() memory.write_buffer(path, "/dev/hmd2_cmd\0") end)
local fd = to_num(S_OPEN(uint64(pa), uint64(2), uint64(0)))
print(string.format("[1] open /dev/hmd2_cmd O_RDWR fd=%d", fd))

local PAGE = memory.alloc(0x1000)
local P = to_num(PAGE)
local SZ = 0x400
local PAINT = string.rep(string.char(0xAA), SZ)
local function repaint() pcall(function() memory.write_buffer(PAGE, PAINT) end) end
local function scan()
    local n, first = 0, ""
    local ok, s = pcall(function() return memory.read_buffer(PAGE, SZ) end)
    if not (ok and type(s) == "string") then return 0, "" end
    for i = 1, SZ - 3, 4 do
        local a, b, c, d = string.byte(s, i, i + 3)
        if not (a == 0xAA and b == 0xAA and c == 0xAA and d == 0xAA) then
            n = n + 1
            if #first < 70 then first = first .. string.format(" %02X%02X%02X%02X", d, c, b, a) end
        end
    end
    return n, first
end

local GENERIC = 0x8A721003
local TY = 0xBC
local dirs = {0x80000000, 0xC0000000, 0x40000000}
local total, generic, hits = 0, 0, 0
local seen = {}

for di = 1, #dirs do
    local dir = dirs[di]
    print(string.format("--- dir=0x%X type=0x%X", dir, TY))
    for len = 0, 0x200 do
        local base = dir + len * 0x10000 + TY * 0x100
        for num = 0, 0xFF do
            local cmd = base + num
            repaint()
            local ok, rv = pcall(function() return S_IOCTL(uint64(fd), uint64(cmd), uint64(P)) end)
            local r = ok and to_num(rv) or -99999
            total = total + 1
            local norm = r % 0x100000000
            if norm == GENERIC then
                generic = generic + 1
            else
                hits = hits + 1
                local ch, first = scan()
                print(string.format("  HIT dir=0x%X len=0x%X num=0x%02X rv=%d(0x%X) wrote=%d%s",
                    dir, len, num, r, norm, ch, first ~= "" and ("[" .. first .. "]") or ""))
                if norm == 0 and ch > 0 then seen[#seen + 1] = cmd end
            end
        end
    end
    print(string.format("  [running] total=%d generic=%d hits=%d", total, generic, hits))
end

print(string.format("[Z] total=%d generic=%d hits=%d writers=%d", total, generic, hits, #seen))
if #seen > 0 then
    print("[Y] the commands that both succeeded and wrote, with a zero page and a null pointer")
    for i = 1, #seen do
        local cmd = seen[i]
        pcall(function() memory.write_buffer(PAGE, string.rep("\0", SZ)) end)
        local ok1, r1 = pcall(function() return S_IOCTL(uint64(fd), uint64(cmd), uint64(P)) end)
        local ch1, f1 = scan()
        local ok2, r2 = pcall(function() return S_IOCTL(uint64(fd), uint64(cmd), uint64(0)) end)
        print(string.format("  cmd=0x%08X zeroed:rv=%s wrote=%d%s nullptr:rv=%s", cmd,
            tostring(ok1 and to_num(r1) or "EXC"), ch1, f1 ~= "" and ("[" .. f1 .. "]") or "",
            tostring(ok2 and to_num(r2) or "EXC")))
    end
end
pcall(function() S_CLOSE(uint64(fd)) end)
print("=== PROBE 1382a COMPLETE ===")
