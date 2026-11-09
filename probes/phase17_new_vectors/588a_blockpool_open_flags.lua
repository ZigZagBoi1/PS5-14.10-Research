-- CRASH_CLASS: LOW
-- PROBE 588a: blockpool_open (653) flag values
--
-- 13.60 653 body 0xffffffff8b367d10: arg1 is a dword flags word tested with
-- "test r15d, 0xffafffff; jne EINVAL", so only bits 20 (0x100000) and 22
-- (0x400000) may be set. 653(0) returned 22 (EINVAL), so at least one bit is
-- probably required.  This probe tries each allowed combination and prints the
-- raw return, then runs a batch+map ladder if a handle appears.

print("=== PROBE 588a: BLOCKPOOL OPEN FLAGS ===")

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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end
local function dump(tag, a, n)
    local out = {}
    for i = 0, (n or 0x20) - 1 do out[#out + 1] = string.format("%02X", rd(a + i) % 256) end
    print(tag .. table.concat(out, " "))
end

local sc_open  = make_syscall(653)
local sc_map   = make_syscall(654)
local sc_unmap = make_syscall(655)
local sc_batch = make_syscall(657)

local last = 0
for _, f in ipairs({0x100000, 0x400000, 0x500000, 0, 0x200000, 0x800000}) do
    local ok, r = pcall(function() return sc_open(u64(f)) end)
    print(string.format("[A] open(0x%06X) ok=%s ret=%s", f, tostring(ok), ok and hex64(r) or tostring(r)))
    last = to_num(r)
end

local hdr = memory.alloc(0x1000)
local out = memory.alloc(0x1000)

local function batch(op, off, size, flags, typ, cnt)
    for i = 0, 0x3FF do wb(hdr + i, 0); wb(out + i, 0) end
    wd(hdr + 0x00, op)
    wd(hdr + 0x04, 0)
    wq(hdr + 0x08, off)
    wq(hdr + 0x10, size)
    wb(hdr + 0x18, flags)
    wb(hdr + 0x19, typ)
    return pcall(function() return sc_batch(u64(hdr), cnt, u64(out), 0) end)
end

for _, t in ipairs({0, 3, 10}) do
    for _, fl in ipairs({0x11, 0x22, 0x33, 0x00}) do
        local ok, r = batch(1, 0, 0x10000, fl, t, 1)
        print(string.format("[B] batch(op=1,size=0x10000,flags=0x%02X,type=%d) ok=%s ret=%s",
            fl, t, tostring(ok), ok and hex64(r) or tostring(r)))
        if ok and to_num(r) ~= 0xFFFFFFFF and to_num(r) ~= -1 then
            dump("    out:", out, 0x20)
        end
    end
end

local ok, r = pcall(function() return sc_map(0, 0x10000, 3, 0, 0) end)
print("[C] map(0,0x10000,3,0,0) ok=" .. tostring(ok) .. " ret=" .. (ok and hex64(r) or tostring(r)))
local ok2, r2 = pcall(function() return sc_unmap(0, 0x10000, 0) end)
print("[D] unmap(0,0x10000,0) ok=" .. tostring(ok2) .. " ret=" .. (ok2 and hex64(r2) or tostring(r2)))
print("[E] alive")
