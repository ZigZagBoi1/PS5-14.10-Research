-- CRASH_CLASS: MODERATE -- full-ish ioctl sweep of a command node that has a live dispatcher.
-- PROBE 1381a: /dev/hmd2_cmd, dir x len x type x num, printing only what is not the generic status
--
-- 360a (results/phase17_new_vectors/360a_encrypt_ioctl_matrix_20261022_175029.txt) found the
-- hmd2_* family answering 0x8A721003 to five fixed codes - a Sony status word, not an errno,
-- which means a real d_ioctl dispatcher runs and rejects those codes itself. docs/DEVFS_GAP_ANALYSIS_14_10.md
-- ranks the never-swept command nodes first for exactly that reason: hmd2_cmd and hmd_cmd are
-- literally named command nodes, were only ever called at group 0 or with 5-26 fixed codes,
-- and no probe has walked their type byte.
--
-- This probe walks dir x len x type(0..0xFF) x num(0..0xFF) on /dev/hmd2_cmd and prints a line
-- only for a command whose answer is neither -1 nor the generic 0x8A721003, with the
-- changed-dword count and the first eight dwords of a 0xAA page. It prints a running total per
-- block and a final histogram, so a truncated capture still shows how far it got.
--
-- The argument page is 0x100 bytes (the largest len swept) and is repainted before every call.
-- The write scan is byte-exact against the 0xAA fill; changed dwords are printed little-endian.
--
-- -- prior art:
--   results/phase17_new_vectors/360a_encrypt_ioctl_matrix_20261022_175029.txt (the 0x8A721003 beacon)
--   results/phase17_new_vectors/279a_node_ioc_sweep_20261022_100333.txt (the group-0 sweep)
--   results/phase17_new_vectors/286a_gc_sweep_remainder_20261022_*.txt (11.5M-call sweep method)
--   docs/DEVFS_GAP_ANALYSIS_14_10.md (rank 1, the unswept command nodes)

print("=== PROBE 1381a: /dev/hmd2_cmd FULL-SPACE IOCTL SWEEP ===")

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

local PAGE = memory.alloc(0x400)
local P = to_num(PAGE)
local SZ = 0x100
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
local dirs = {0xC0000000, 0x80000000, 0x40000000}
local lens = {4, 8, 0x10, 0x18, 0x20, 0x28, 0x40}
local hits, total, generic, errs = 0, 0, 0, 0

for di = 1, #dirs do
    local dir = dirs[di]
    for li = 1, #lens do
        local len = lens[li]
        print(string.format("--- dir=0x%X len=0x%X", dir, len))
        for ty = 0, 0xFF do
            local base = dir + len * 0x10000 + ty * 0x100
            for num = 0, 0xFF do
                local cmd = base + num
                repaint()
                local ok, rv = pcall(function() return S_IOCTL(uint64(fd), uint64(cmd), uint64(P)) end)
                local r = ok and to_num(rv) or -99999
                total = total + 1
                local norm = r % 0x100000000
                if r == -1 then
                    errs = errs + 1
                elseif norm == GENERIC then
                    generic = generic + 1
                else
                    hits = hits + 1
                    local ch, first = scan()
                    print(string.format("  HIT cmd=0x%08X rv=%d(0x%X) wrote=%d%s", cmd, r, norm, ch,
                        first ~= "" and ("[" .. first .. "]") or ""))
                end
            end
        end
        print(string.format("  [running] total=%d generic=%d errno=%d hits=%d", total, generic, errs, hits))
    end
end

print(string.format("[Z] total=%d generic=%d errno=%d hits=%d", total, generic, errs, hits))
pcall(function() S_CLOSE(uint64(fd)) end)
print("=== PROBE 1381a COMPLETE ===")
