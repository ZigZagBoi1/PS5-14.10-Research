-- CRASH_CLASS: MODERATE
-- PROBE 589a: blockpool offset semantics
--
-- Rereading 654/655: arg1 is compared as a raw qword against [pool+0x20] and
-- [pool+0x28] -- "if [pool+0x20] <= arg1 -> EINVAL" then "end - arg1 >= size".
-- That reads as an absolute offset between a base and a limit, not an index.
-- This probe sweeps plausible bases with a 0x10000 size across map, batch and
-- unmap.

print("=== PROBE 589a: BLOCKPOOL OFFSETS ===")

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
local function u64(v) return uint64(tostring(v)) end
local function hi_lo(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, to_num(v)
end
local function hex64(v)
    local h, l = hi_lo(v)
    return string.format("%08X_%08X", to_num(h), to_num(l))
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end

local sc_open  = make_syscall(653)
local sc_map   = make_syscall(654)
local sc_unmap = make_syscall(655)
local sc_batch = make_syscall(657)

local ok0, r0 = pcall(function() return sc_open(u64(0x100000)) end)
print("[A] open(0x100000) ok=" .. tostring(ok0) .. " ret=" .. (ok0 and hex64(r0) or tostring(r0)))

local offs = {0x200000, 0x800000, 0x1000000, 0x10000000, 0x100000000, 0x400000000, 0x0, 0x10000}
for _, o in ipairs(offs) do
    local k1, m = pcall(function() return sc_map(o, 0x10000, 3, 0, 0) end)
    print(string.format("[B] map(0x%X,0x10000,3) ok=%s ret=%s", o, tostring(k1), k1 and hex64(m) or tostring(m)))
    local k2, u = pcall(function() return sc_unmap(o, 0x10000, 0) end)
    print(string.format("[C] unmap(0x%X,0x10000,0) ok=%s ret=%s", o, tostring(k2), k2 and hex64(u) or tostring(u)))
end

local hdr = memory.alloc(0x1000)
local out = memory.alloc(0x1000)
local function batch(op, off, size, flags, typ, cnt)
    for i = 0, 0x3FF do wb(hdr + i, 0); wb(out + i, 0) end
    wd(hdr + 0x00, op)
    wq(hdr + 0x08, off)
    wq(hdr + 0x10, size)
    wb(hdr + 0x18, flags)
    wb(hdr + 0x19, typ)
    return pcall(function() return sc_batch(u64(hdr), cnt, u64(out), 0) end)
end
for _, o in ipairs({0x200000, 0x1000000, 0x10000000, 0x100000000}) do
    local k, r = batch(1, o, 0x10000, 0x11, 3, 1)
    print(string.format("[D] batch(op=1,off=0x%X,size=0x10000) ok=%s ret=%s", o, tostring(k), k and hex64(r) or tostring(r)))
end
print("[E] alive")
