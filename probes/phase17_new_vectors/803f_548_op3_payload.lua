-- CRASH_CLASS: HIGH
-- PROBE 803f: what does 548 op 3 map?  (the payload field)
--
-- 548 record = {+0x00 addr, +0x08 payload, +0x10 len, +0x18 prot byte, +0x1c op dword}.
-- op 3 returns the mapped address and creates a fresh mapping at addr when payload is 0, so the
-- +0x08 qword is the only field that can select a source.  This probe varies it across the
-- physical values the dmem0 primitive hands out and across a user address, and for every
-- successful mapping dumps the first 64 bytes and the region's protection and name.
--
-- One value per connection-level pcall; the loader drops the process on a bad phys access, so a
-- dead run names the last attempt in the capture.

print("=== PROBE 803f: 548 OP 3 PAYLOAD ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
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
local function hexq(a)
    local v = rq(a)
    if type(v) == "table" and v.h then return string.format("%08X%08X", to_num(v.h), to_num(v.l)) end
    return string.format("%016X", to_num(v))
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
local function op3(addr, payload, len, prot)
    local b = recs
    wq(b, split(0, addr))
    wq(b + 8, split(0, payload))
    wq(b + 0x10, split(0, len))
    wd(b + 0x18, prot)
    wd(b + 0x1c, 3)
    local ok, rv = pcall(function()
        return sc548(uint64(0), uint64(0), uint64(recs), uint64(1), uint64(0))
    end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end

local TARGET = 0x740000000
local function clean(addr, len)
    pcall(function() return sc_munmap(uint64(addr), uint64(len)) end)
end

local cases = {
    {"payload 0",                 0},
    {"payload 0x1000",            0x1000},
    {"payload 0x40000000",        0x40000000},
    {"payload 0x100000000",       0x100000000},
    {"payload 0x110000000",       0x110000000},
    {"payload own heap",          0x310000000},
}

print("[A] op 3 with len=0x4000 prot=3")
for _, c in ipairs(cases) do
    clean(TARGET, 0x4000)
    local r = op3(TARGET, c[2], 0x4000, 3)
    local lo, hi, p, nm = region_of(TARGET)
    if lo then
        print(string.format("  %-28s ret=%-12s region=[%X,%X) prot=%X %s", c[1], tostring(r), lo, hi, p, nm))
        print(string.format("      q0=%s q1=%s q2=%s q3=%s", hexq(TARGET), hexq(TARGET + 8),
            hexq(TARGET + 16), hexq(TARGET + 24)))
    else
        print(string.format("  %-28s ret=%-12s region=GONE", c[1], tostring(r)))
    end
end

print("")
print("[B] op 3 with len variations on payload 0 (does len bound the mapping?)")
for _, len in ipairs({0x1000, 0x2000, 0x8000, 0x100000, 0}) do
    local a = 0x750000000
    clean(a, 0x200000)
    local r = op3(a, 0, len, 3)
    local lo, hi, p, nm = region_of(a)
    print(string.format("  len=%-10X ret=%-12s %s", len, tostring(r),
        lo and string.format("[%X,%X) prot=%X %s", lo, hi, p, nm) or "GONE"))
end

print("")
print("[C] alive pid=" .. to_num(getpid()))
