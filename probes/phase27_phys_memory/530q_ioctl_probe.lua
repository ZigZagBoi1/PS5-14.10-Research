-- CRASH_CLASS: LOW
-- PROBE 530q: Deep probe of interesting gc ioctls
--
-- 530p found 12 working ioctls. Interesting ones:
-- nr=27: {0x80000000, 0xC} — flags + count
-- nr=45: {0, 1} — status
-- nr=50: {0,0,0,0,0x5C} — 0x5C = 92 (doorbell offset?)
-- nr=51: {0, 0x5C} — also 0x5C
--
-- Plan:
-- 1. Probe each with various input values
-- 2. Submit a command then re-check status ioctls
-- 3. Test if 0x5C is a doorbell offset we can use

print("=== PROBE 530q: IOCTL PROBE ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print(string.format("pid=%d", pid))

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

local devpath = memory.alloc(0x20)
local name = "/dev/gc"
for i = 1, #name do wd(N(devpath) + i - 1, string.byte(name, i)) end
wd(N(devpath) + #name, 0)
local gc_fd = N(native.fcall_with_rax(stub, 5, uint64(N(devpath)), uint64(2), uint64(0)))

local sc_ioctl = mk(54)

local function do_ioctl(cmd, input_dwords, sz, out_n)
    local buf = memory.alloc(math.max(sz, 256))
    for i = 0, sz - 1, 4 do wd(N(buf) + i, 0) end
    if input_dwords then
        for i, v in ipairs(input_dwords) do
            wd(N(buf) + (i-1)*4, v)
        end
    end
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(gc_fd), uint64(cmd), uint64(N(buf)))
    end)
    local ret = -999
    if ok and rv then ret = N(rv) end
    local out = {}
    for i = 0, (out_n or 8) - 1 do
        local d = rd(N(buf) + i * 4) or 0
        if d < 0 then d = d + 0x100000000 end
        table.insert(out, d)
    end
    return ret, out, N(buf)
end

-- ============================================================
-- [A] nr=27 (0xC008811B): {0x80000000, 0xC}
-- ============================================================
print("[A] nr=27 deep")

-- With various inputs
for _, v in ipairs({0, 1, 2, 0x80000000, 0xC}) do
    local rv, out = do_ioctl(0xC008811B, {v, 0}, 8, 4)
    print(string.format("  in[0]=0x%X: rv=%d out={0x%X,0x%X,0x%X,0x%X}",
        v, rv, out[1], out[2], out[3], out[4]))
end

-- Bigger size
local rv, out = do_ioctl(0xC020811B, nil, 32, 8)
if rv == 0 then
    local parts = {}
    for _, d in ipairs(out) do table.insert(parts, string.format("0x%X", d)) end
    print(string.format("  sz=32: rv=%d out={%s}", rv, table.concat(parts, ",")))
end

-- ============================================================
-- [B] nr=50 (0xC0188132): {0,0,0,0,0x5C}
-- ============================================================
print("")
print("[B] nr=50 deep")

-- Default
rv, out = do_ioctl(0xC0188132, nil, 24, 6)
print(string.format("  default: rv=%d out={0x%X,0x%X,0x%X,0x%X,0x%X,0x%X}",
    rv, out[1], out[2], out[3], out[4], out[5], out[6]))

-- With various pipe/queue IDs in first dword
for _, v in ipairs({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) do
    local rv2, out2 = do_ioctl(0xC0188132, {v}, 24, 6)
    if rv2 == 0 then
        local changed = false
        if out2[5] ~= 0x5C or out2[1] ~= v then changed = true end
        for i = 2, 4 do if out2[i] ~= 0 then changed = true end end
        if changed or v <= 3 then
            print(string.format("  pipe=%d: out={0x%X,0x%X,0x%X,0x%X,0x%X,0x%X}",
                v, out2[1], out2[2], out2[3], out2[4], out2[5], out2[6]))
        end
    else
        print(string.format("  pipe=%d: rv=%d", v, rv2))
    end
end

-- ============================================================
-- [C] nr=51 (0xC0088133): {0, 0x5C}
-- ============================================================
print("")
print("[C] nr=51 deep")

for _, v in ipairs({0, 1, 2, 3, 0x5C, 0xFF}) do
    local rv3, out3 = do_ioctl(0xC0088133, {v}, 8, 4)
    print(string.format("  in=%d: rv=%d out={0x%X,0x%X,0x%X,0x%X}",
        v, rv3, out3[1], out3[2], out3[3], out3[4]))
end

-- ============================================================
-- [D] nr=45 (0xC008812D): {0, 1}
-- ============================================================
print("")
print("[D] nr=45 deep")

for _, v in ipairs({0, 1, 2, 3}) do
    local rv4, out4 = do_ioctl(0xC008812D, {v}, 8, 4)
    print(string.format("  in=%d: rv=%d out={0x%X,0x%X,0x%X,0x%X}",
        v, rv4, out4[1], out4[2], out4[3], out4[4]))
end

-- ============================================================
-- [E] nr=1 (0xC0088101), nr=17 (0xC0088111) — probe with inputs
-- ============================================================
print("")
print("[E] nr=1 and nr=17")

for _, v in ipairs({0, 1, 0x100}) do
    rv, out = do_ioctl(0xC0088101, {v}, 8, 4)
    print(string.format("  nr=1 in=%d: rv=%d out={0x%X,0x%X}", v, rv, out[1], out[2]))
end

for _, v in ipairs({0, 1, 0x100}) do
    rv, out = do_ioctl(0xC0088111, {v}, 8, 4)
    print(string.format("  nr=17 in=%d: rv=%d out={0x%X,0x%X}", v, rv, out[1], out[2]))
end

-- ============================================================
-- [F] nr=30 (0xC030811E, sz=48) and nr=32 (0xC0108120)
-- ============================================================
print("")
print("[F] nr=30 and nr=32")

rv, out = do_ioctl(0xC030811E, nil, 48, 12)
local nz = 0
for _, d in ipairs(out) do if d ~= 0 then nz = nz + 1 end end
print(string.format("  nr=30 sz=48: rv=%d non-zero=%d", rv, nz))

rv, out = do_ioctl(0xC0108120, nil, 16, 4)
print(string.format("  nr=32 sz=16: rv=%d out={0x%X,0x%X,0x%X,0x%X}", rv, out[1], out[2], out[3], out[4]))

-- Try nr=32 with pipe IDs
for _, v in ipairs({0, 1, 2}) do
    local rv5, out5 = do_ioctl(0xC0108120, {v}, 16, 4)
    print(string.format("  nr=32 pipe=%d: rv=%d out={0x%X,0x%X,0x%X,0x%X}",
        v, rv5, out5[1], out5[2], out5[3], out5[4]))
end

-- ============================================================
-- [G] nr=57 (0xC0108139, sz=16)
-- ============================================================
print("")
print("[G] nr=57")
for _, v in ipairs({0, 1, 2}) do
    rv, out = do_ioctl(0xC0108139, {v}, 16, 4)
    print(string.format("  in=%d: rv=%d out={0x%X,0x%X,0x%X,0x%X}", v, rv, out[1], out[2], out[3], out[4]))
end

-- ============================================================
-- [H] Submit then check status
-- ============================================================
print("")
print("[H] Submit + status check")

-- Pre-submit status
rv, out = do_ioctl(0xC008812D, nil, 8, 2)
print(string.format("  pre-submit nr=45: {0x%X,0x%X}", out[1], out[2]))
rv, out = do_ioctl(0xC0088133, nil, 8, 2)
print(string.format("  pre-submit nr=51: {0x%X,0x%X}", out[1], out[2]))

-- Do a submit (NOP only)
local cmd_buf = memory.alloc(0x100)
wd(N(cmd_buf), 0xC0001000)  -- NOP, count=0
local desc = memory.alloc(0x10)
local cmd_lo = N(cmd_buf) % 0x100000000
local cmd_hi = math.floor(N(cmd_buf) / 0x100000000)
wd(N(desc), 0xC0023F00)
wd(N(desc) + 4, cmd_lo)
wd(N(desc) + 8, cmd_hi)
wd(N(desc) + 12, 1)

local sub = memory.alloc(0x10)
wd(N(sub), 0)
wd(N(sub) + 4, 1)
local desc_lo = N(desc) % 0x100000000
local desc_hi = math.floor(N(desc) / 0x100000000)
wd(N(sub) + 8, desc_lo)
wd(N(sub) + 12, desc_hi)

pcall(function() sc_ioctl(uint64(gc_fd), uint64(0xC0108102), uint64(N(sub))) end)

-- Post-submit status
rv, out = do_ioctl(0xC008812D, nil, 8, 2)
print(string.format("  post-submit nr=45: {0x%X,0x%X}", out[1], out[2]))
rv, out = do_ioctl(0xC0088133, nil, 8, 2)
print(string.format("  post-submit nr=51: {0x%X,0x%X}", out[1], out[2]))
rv, out = do_ioctl(0xC008811B, nil, 8, 2)
print(string.format("  post-submit nr=27: {0x%X,0x%X}", out[1], out[2]))

pcall(function() native.fcall_with_rax(stub, 6, uint64(gc_fd)) end)

print("")
print("=== 530q DONE ===")
