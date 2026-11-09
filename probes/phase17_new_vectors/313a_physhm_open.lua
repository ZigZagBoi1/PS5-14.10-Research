-- CRASH_CLASS: MODERATE (physhm_open is the physical shared memory entry; a bad
-- shape here allocates kernel objects or faults)
-- PROBE 313a: sys 629 physhm_open called with its recovered four slots
--
-- results/kernel_handlers/analysis/sys_629.md: narg 4, slots (arg0 u64,
-- arg1 u32, arg2 u16, arg3 u32). arg0 == 1 is a sentinel that goes straight to
-- the delegate; every other arg0 is a POINTER to a NUL-terminated string that
-- is copied with a 0x400 bound, must begin with '/', and then passes a prefix
-- policy check (returns 22 for a non-absolute path, 2 for a rejected prefix).
-- The delegate is where the open actually happens.
--
-- Every earlier call to 629 used six zero arguments, which is the sentinel-0
-- path with a NULL pointer, so the handler has never been given a real shape.
-- 630 physhm_unlink takes the same first argument and is tested alongside.

print("=== PROBE 313a: SYS 629 physhm_open ===")

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
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return -1
end
local function wb(addr, b) pcall(function() memory.write_byte(addr, b) end) end

local buf = memory.alloc(0x800)
local function put_str(s, off)
    off = off or 0
    for i = 1, #s do wb(buf + off + i - 1, string.byte(s, i)) end
    wb(buf + off + #s, 0)
    return to_num(buf) + off
end
local function U32(v) return uint64(v) end

local sc629 = make_syscall(629)
local sc630 = make_syscall(630)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)

-- [A] sentinel: arg0 == 1 goes straight to the delegate
print("")
print("[A] sentinel arg0 = 1")
for _, a in ipairs({0, 1, 2, 0x10, 0x1000, 0x40000000}) do
    local ok, rv = pcall(function() return sc629(uint64(1), U32(a), U32(0), U32(0)) end)
    if ok then
        print(string.format("  629(1,0x%X,0,0) -> %d", a, sgn(rv)))
    else
        print(string.format("  629(1,0x%X,0,0) DIED: %s", a, tostring(rv)))
    end
end

-- [B] a path pointer: the string is copied with a 0x400 bound and must start with '/'
print("")
print("[B] path pointer")
local paths = {"/", "/dev", "/dev/physhm0", "/physhm0", "/tmp", "/app0",
               "/tmp/omp313a", "/dev/physhm", "/dev/dce"}
for _, p in ipairs(paths) do
    local ptr = put_str(p)
    local ok, rv = pcall(function() return sc629(uint64(ptr), U32(0), U32(0), U32(0)) end)
    if ok then
        local r = sgn(rv)
        print(string.format("  629(\"%s\") -> %d", p, r))
        if r >= 0 and r < 0x1000 then
            local ro = pcall(function() return sc_open(uint64(put_str(p)), U32(0), U32(0)) end)
            print(string.format("     that value is descriptor-shaped; open(\"%s\") itself returned %s",
                p, tostring(ro)))
        end
    else
        print(string.format("  629(\"%s\") DIED: %s", p, tostring(rv)))
    end
end

-- [C] open the physhm node names directly, since that is what an open would do
print("")
print("[C] open() the physhm node names")
for _, p in ipairs({"/dev/physhm0", "/dev/physhm", "/dev/physhm1", "/dev/physhm2"}) do
    local ptr = put_str(p)
    local ro = sgn(sc_open(uint64(ptr), U32(0), U32(0)))
    local rw = sgn(sc_open(uint64(ptr), U32(2), U32(0)))
    print(string.format("  open(\"%s\") ro=%d rw=%d", p, ro, rw))
    if rw >= 0 then sc_close(U32(rw)) end
    if ro >= 0 then sc_close(U32(ro)) end
end

-- [D] unlink with the same strings
print("")
print("[D] 630 physhm_unlink with a path pointer")
for _, p in ipairs({"/tmp/omp313a", "/dev/physhm0"}) do
    local ptr = put_str(p)
    local ok, rv = pcall(function() return sc630(uint64(ptr), U32(0), U32(0), U32(0)) end)
    if ok then
        print(string.format("  630(\"%s\") -> %d", p, sgn(rv)))
    else
        print(string.format("  630(\"%s\") DIED: %s", p, tostring(rv)))
    end
    ok, rv = pcall(function() return sc630(uint64(1), U32(0), U32(0), U32(0)) end)
    print(string.format("  630(1) -> %s", ok and tostring(sgn(rv)) or ("DIED: " .. tostring(rv))))
end

print("")
print("=== PROBE 313a COMPLETE ===")
