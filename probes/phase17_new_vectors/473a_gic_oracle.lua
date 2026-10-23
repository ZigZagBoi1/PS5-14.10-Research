-- CRASH_CLASS: LOW
-- PROBE 473a: what does the gic command validate
--
-- Context: 472a showed the only driver command on /dev/gic, 0xC0104701
-- (_IOWR('G', 1, 0x10)), is content-sensitive in exactly one place: most
-- inputs get back a constant 0x816800FF in the last dword, but q0 set to our
-- own mapped page came back 0x00000000. The handler is an oracle for
-- something about q0. This probe walks the whole VM map (sys 674), feeds the
-- start address of every region as q0 with q1=0, and records which return 0
-- in the last word, which return the constant, and whether ret ever differs.
-- Unmapped gaps, the kernel VA range, and junk constants go through the same
-- call so the oracle's yes/no boundary shows up as a pattern.

print("=== PROBE 473a: the gic oracle's yes and no ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hi(v)
    if type(v) == "table" and v.h then return v.h % 0x100000000 end
    return 0
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
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end
    return -1
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)
local CMD = 0xC0104701

local fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(2), uint64(0)))
if fd < 0 then fd = sgn(sc_open(uint64(put_str("/dev/gic")), uint64(0), uint64(0))) end
print("[0] open(/dev/gic)=" .. fd)
if fd < 0 then
    print("=== PROBE 473a ABORTED ===")
    return
end

local page = memory.alloc(0x1000)
local function zero_page()
    for off = 0, 0xFFC, 4 do wd(page + off, 0) end
end
local function ask(q0)
    zero_page()
    local h, l = 0, 0
    if type(q0) == "table" and q0.h then h, l = q0.h % 0x100000000, q0.l % 0x100000000
    else l = to_num(q0) % 0x100000000 end
    wq(page, uint64(string.format("0x%X%08X", h, l)))
    wq(page + 8, uint64(0))
    local r = sgn(sc_ioctl(uint64(fd), uint64(CMD), uint64(page)))
    local tag = rd(page + 12)
    -- also read back the echo words to catch partial writes
    return r, tag, rd(page), rd(page + 4)
end

-- The full region list, sys 674 idiom from 375a
local sc674 = make_syscall(674)
local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
local countp = memory.alloc(16)
for i = 0, 12, 4 do wd(countp + i, 0) end
sgn(sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000)))
local count = rd(countp)
if count < 0 or count > MAX then count = 0 end
print(string.format("[0] regions: %d", count))
if count == 0 then
    print("=== PROBE 473a ABORTED ===")
    return
end

local n_zero, n_const, n_other, n_badret = 0, 0, 0, 0
local seen = {}
print("")
print("[A] every region start as q0 (only non-constant answers printed)")
for i = 0, count - 1 do
    local rec = buf + i * STRIDE
    local slo = rd(rec)
    local shi = hi(rd(rec))
    -- rd returns a tonumber; reconstruct via qword read when possible
    local ok, qv = pcall(function() return memory.read_qword(rec) end)
    local start = ok and qv or uint64(0)
    local r, tag, e0, e1 = ask(start)
    local key = string.format("ret=%d tag=0x%08X e0=0x%08X", r, tag % 0x100000000, e0 % 0x100000000)
    if r ~= 0 then
        n_badret = n_badret + 1
        print(string.format("  [%3d] %s start=%s", i, key, tostring(start)))
    elseif tag == 0 then
        n_zero = n_zero + 1
        if n_zero <= 30 then
            local prot = rd(rec + 0x18)
            local nm = {}
            for k = 0, 23 do
                local c = rb(rec + 0x20 + k)
                if c == 0 then break end
                if c >= 32 and c < 127 then nm[#nm + 1] = string.char(c) end
            end
            print(string.format("  [%3d] ZERO start=%s prot=0x%X %s", i, tostring(start), prot, table.concat(nm)))
        end
    elseif tag == 0x816800FF then
        n_const = n_const + 1
    else
        n_other = n_other + 1
        print(string.format("  [%3d] %s start=%s", i, key, tostring(start)))
    end
    seen[i % 64] = nil
end
print(string.format("[A] zero=%d const=0x816800FF x %d other-tag=%d bad-ret=%d",
    n_zero, n_const, n_other, n_badret))

print("")
print("[B] unmapped gaps, kernel VA, and junk constants")
local probes_b = {
    { "gap 0x4000", uint64(0x4000) },
    { "gap 0x100000", uint64(0x100000) },
    { "kern 0xFFFF8000_1000", uint64(string.format("0x%X%08X", 0xFFFF8000, 0x1000)) },
    { "kern 0xFFFFFFFF_80000000", uint64(string.format("0x%X%08X", 0xFFFFFFFF, 0x80000000)) },
    { "junk 1", uint64(1) },
    { "junk -1", uint64(0xFFFFFFFF) },
    { "junk 0xDEADBEEF", uint64(0xDEADBEEF) },
    { "eboot text?", uint64(0) },  -- replaced below with a real low mapping
}
-- last slot: reuse the loader's own page address like 472a's q0=self
probes_b[8][1] = "q0=self page"
probes_b[8][2] = uint64(page)
for _, p in ipairs(probes_b) do
    local r, tag = ask(p[2])
    print(string.format("    %-24s ret=%d tag=0x%08X", p[1], r, tag % 0x100000000))
end

pcall(function() sc_close(uint64(fd)) end)
print("")
print("=== PROBE 473a COMPLETE ===")
