-- CRASH_CLASS: MODERATE
-- PROBE 590a: _umtx_op(454) UMTX_OP_ROBUST_LISTS (26)
--
-- The repo records op 5/21 as functional on 454 and 25/26 as never exercised.
-- FreeBSD's umtx_robust_lists(26) copies a {len, list} header and then walks the
-- caller's array of user pointers, so it is the historical source of the
-- robust-list overflow family.  This probe feeds it a well-formed list first and
-- only then grows len.

print("=== PROBE 590a: UMTX ROBUST LISTS ===")

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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return -1
end

local sc = make_syscall(454)

local hdr    = memory.alloc(0x100)
local plist  = memory.alloc(0x4000)
local lock   = memory.alloc(0x100)
for i = 0, 0x3F do wq(plist + i * 8, 0) end
wd(lock, 0)

local function robust(len, listptr)
    wq(hdr, len)
    wq(hdr + 8, listptr)
    return pcall(function() return sc(26, u64(hdr), 0, 0, 0, 0) end)
end

local lo = to_num(lock)
wq(plist, lo)
wq(plist + 8, lo + 4)

for _, len in ipairs({0, 1, 2}) do
    local ok, r = robust(len, lo and u64(plist) or u64(plist))
    print(string.format("[A] op26(len=%d,list=0x%X) ok=%s ret=%s", len, to_num(plist), tostring(ok), ok and hex64(r) or tostring(r)))
end

-- unaligned / unmapped header first, then larger lengths
local ok1, r1 = pcall(function() return sc(26, u64(0), 0, 0, 0, 0) end)
print("[B] op26(NULL header) ok=" .. tostring(ok1) .. " ret=" .. (ok1 and hex64(r1) or tostring(r1)))

for _, len in ipairs({0x10, 0x100, 0x1000}) do
    local ok, r = robust(len, to_num(plist))
    print(string.format("[C] op26(len=0x%X) ok=%s ret=%s", len, tostring(ok), ok and hex64(r) or tostring(r)))
end

-- well-formed header, list pointer that is unmapped
local ok2, r2 = robust(1, 0xDEAD0000)
print("[D] op26(len=1,bad list) ok=" .. tostring(ok2) .. " ret=" .. (ok2 and hex64(r2) or tostring(r2)))
print("[E] alive")
