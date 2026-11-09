-- CRASH_CLASS: MODERATE
-- PROBE 587a: blockpool_batch (657) allocation shapes, then blockpool_map (654)
--
-- 13.60 657 body 0xffffffff8b369f40 (narg 4): arg1 = user pointer to a 0x20-byte
-- descriptor {u32 op, u32 zero, u64 offset, u64 size, u8 flags, u8 type, ...},
-- arg2 = count, arg3 = user output array, arg4 = mode.  Dispatch table at
-- 0x8b36a0c4 accepts op 1..5; op 1 worker 0x8b36a250 requires offset and size
-- to be 0x10000 aligned, offset >= pool base, offset+size <= pool size,
-- flags masked by 0x33, type in {0,3,10}.

print("=== PROBE 587a: BLOCKPOOL BATCH ALLOC ===")

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
    for i = 0, (n or 0x20) - 1 do
        out[#out + 1] = string.format("%02X", rd(a + i) % 256)
    end
    print(tag .. table.concat(out, " "))
end

local sc_open  = make_syscall(653)
local sc_map   = make_syscall(654)
local sc_batch = make_syscall(657)

local o_ok, o = pcall(function() return sc_open(u64(0)) end)
print("[A] open(0) ok=" .. tostring(o_ok) .. " ret=" .. tostring(o))

local hdr  = memory.alloc(0x1000)
local out  = memory.alloc(0x1000)

local function batch(op, off, size, flags, typ, cnt)
    for i = 0, 0x3FF do wb(hdr + i, 0); wb(out + i, 0) end
    wd(hdr + 0x00, op)
    wd(hdr + 0x04, 0)
    wq(hdr + 0x08, off)
    wq(hdr + 0x10, size)
    wb(hdr + 0x18, flags)
    wb(hdr + 0x19, typ)
    local ok, r = pcall(function() return sc_batch(u64(hdr), cnt, u64(out), 0) end)
    return ok, r
end

local combos = {
    {1, 0x10000, 0x11, 0}, {1, 0x10000, 0x11, 3}, {1, 0x10000, 0x11, 10},
    {1, 0x10000, 0x22, 3}, {1, 0x10000, 0x33, 3}, {1, 0x10000, 0x00, 3},
}
for _, c in ipairs(combos) do
    local ok, r = batch(c[1], 0, c[2], c[3], c[4], 1)
    print(string.format("[B] batch(op=%d,size=0x%X,flags=0x%02X,type=%d,count=1) ok=%s ret=%s",
        c[1], c[2], c[3], c[4], tostring(ok), ok and hex64(r) or tostring(r)))
    dump("    out:", out, 0x20)
end

for _, c in ipairs({{1,0x20000,0x11,3},{2,0x10000,0x11,3},{3,0x10000,0x11,3}}) do
    local ok, r = batch(c[1], 0, c[2], c[3], c[4], 1)
    print(string.format("[C] batch(op=%d,size=0x%X,count=1) ok=%s ret=%s",
        c[1], c[2], tostring(ok), ok and hex64(r) or tostring(r)))
end

for idx = 0, 1 do
    for t = 0, 10 do
        local ok, r = pcall(function() return sc_map(idx, 0x10000, t, 0, 0) end)
        print(string.format("[D] map(idx=%d,type=%d) ok=%s ret=%s", idx, t, tostring(ok), ok and hex64(r) or tostring(r)))
    end
end

print("[E] alive")
