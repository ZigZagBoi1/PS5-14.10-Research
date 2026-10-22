-- CRASH_CLASS: LOW (no access to the mapping; only the protection query)
-- PROBE 320a: what protection does the kernel give a physhm mapping?
--
-- 318a: reading a physhm mapping kills the process inside pcall. 319a: the
-- descriptor refuses read, write, FIODTYPE, FIONBIO and 628. So the mapping is
-- the only thing that exists, and its first access faults.
--
-- If the protection the kernel recorded for it lacks read, that fault is not a
-- bug in our probing - it is the mapping's nature, and this prints the exact
-- protection word so the record says so. 547 reports (start, end, prot) for the
-- region containing an address and is safe on any address.

print("=== PROBE 320a: physhm mapping protection ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, to_num(v.l) end
    if (h % 4294967296) == 4294967295 and (l % 4294967296) == 4294967295 then return -1 end
    if h >= 0xFFFF8000 then return -1 end
    return l
end
local function rq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if ok then return v end
    return 0
end
local function U32(v) return uint64(v) end
local function U64(x) return uint64(string.format("0x%X", x)) end

local sc629 = make_syscall(629)
local sc_mmap = make_syscall(477)
local sc_close = make_syscall(6)
local sc547 = make_syscall(547)

local out = memory.alloc(0x40)
local function prot_of(addr)
    for i = 0, 0x2F, 8 do pcall(function() memory.write_qword(out + i, uint64(0)) end) end
    local ok, rv = pcall(function() return sc547(U64(addr), uint64(out)) end)
    if not ok then return nil, "DIED" end
    return sgn(rv), out
end

-- control: a mapping we own and can read
local ctl = sgn(sc_mmap(uint64(0), U32(0x1000), U32(3), U32(0x1002), U32(0xFFFFFFFF), uint64(0)))
print(string.format("[control] anon mmap=0x%X", ctl))
if ctl > 0 then
    local r, o = prot_of(ctl)
    if o then
        print(string.format("  prot ret=%d start=0x%X end=0x%X prot=0x%X",
            r, to_num(rq(o)), to_num(rq(o + 8)), to_num(rq(o + 0x18))))
    end
end

local fd = sgn(sc629(uint64(1), U32(2), U32(0), U32(0)))
print(string.format("[physhm] fd=%d", fd))
if fd < 0 then return end
local pa = sgn(sc_mmap(uint64(0), U32(0x1000), U32(3), U32(1), U32(fd), uint64(0)))
print(string.format("  mmap=0x%X", pa))
if pa > 0 then
    local r, o = prot_of(pa)
    if o then
        print(string.format("  prot ret=%d start=0x%X end=0x%X prot=0x%X",
            r, to_num(rq(o)), to_num(rq(o + 8)), to_num(rq(o + 0x18))))
    end
end
sc_close(U32(fd))
print("=== PROBE 320a COMPLETE ===")
