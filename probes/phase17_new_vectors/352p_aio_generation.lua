-- CRASH_CLASS: LOW
-- PROBE 352p: whether the generation in an identifier is checked, or only the slot
--
-- 352o cycled one slot twenty times: the high field takes exactly eight values
-- (0x22, 0x42, 0x62, 0x82, 0xA2, 0xC2, 0xE2, 0x02) and then repeats, so the
-- generation is three bits. After eight reuses an old identifier names whatever
-- now occupies the slot.
--
-- That much is bookkeeping. The question here is whether the entries compare the
-- generation at all, or mask it away and act on the slot:
--   [A] submit, then delete with the generation bumped by one
--   [B] submit, then poll with the generation bumped by one
--   [C] submit, then delete with an untouched generation (control)
-- If [A] frees the live request, or [B] reports its state, the caller's
-- generation is decoration.

print("=== PROBE 352p: AIO IDENTIFIER GENERATION ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function hi_lo(v)
    local h, l = get_hi_lo(v)
    return to_num(h), to_num(l)
end
local Z = uint64(0)
local function sc(n) return make_syscall(n) end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return -999
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end
local function open_path(path, flags)
    local ok, rv = pcall(function() return sc(5)(put_str(path), uint64(flags), Z) end)
    if not ok then return -1 end
    return sgn(rv)
end

local reqs = memory.alloc(0x200)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x200)
local ids = memory.alloc(0x200)
local states = memory.alloc(0x100)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
    wd(states + i * 4, 0)
end
for i = 0, 0x3FF do wd(data + i * 4, 0) end

local fd = open_path("/dev/zero", 0)
print(string.format("open(/dev/zero) = %d", fd))
if fd < 0 then
    print("=== 352p DONE ===")
    return
end

local function submit()
    wq(reqs + 0x00, 0)
    wq(reqs + 0x08, 16)
    local bh, bl = hi_lo(uint64(data))
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(uint64(result))
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, fd)
    wd(reqs + 0x24, 0)
    wd(result, 0)
    wd(ids, 0)
    local ok, rv = pcall(function()
        return sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    return ok and sgn(rv) or nil, rd(ids), rd(result)
end

local function poll(id)
    wd(ids, id)
    wd(states, 0)
    local ok, rv = pcall(function()
        return sc(664)(uint64(ids), uint64(1), uint64(states))
    end)
    return ok and sgn(rv) or nil, rd(states)
end

local function del(id)
    wd(ids, id)
    wd(states, 0)
    local ok, rv = pcall(function()
        return sc(662)(uint64(ids), uint64(1), uint64(states))
    end)
    return ok and sgn(rv) or nil, rd(states)
end

-- The generation occupies the three bits above the slot. Bumping it by one
-- steps 0x2000.
local function bump(id)
    local gen = math.floor(id / 0x2000) % 8
    local slot = id % 0x2000
    return ((gen + 1) % 8) * 0x2000 + slot
end

print("[A] delete with the generation bumped")
local s, idA, r = submit()
print(string.format("  submit -> %s id=0x%08X result=0x%08X", tostring(s), idA, r))
local d, dst = del(bump(idA))
print(string.format("  delete 0x%08X (bumped) -> %s state=0x%08X", bump(idA), tostring(d), dst))
local p, pst = poll(idA)
print(string.format("  poll the real 0x%08X -> %s state=0x%X  (%s)", idA, tostring(p), pst,
    pst == 0x80020003 and "the request is gone: the bump deleted it" or "the request is still there"))

print("[B] poll with the generation bumped")
local s2, idB, r2 = submit()
print(string.format("  submit -> %s id=0x%08X result=0x%08X", tostring(s2), idB, r2))
local p2, pst2 = poll(bump(idB))
print(string.format("  poll 0x%08X (bumped) -> %s state=0x%08X", bump(idB), tostring(p2), pst2))

print("[C] the control: the real identifier")
local p3, pst3 = poll(idB)
print(string.format("  poll 0x%08X -> %s state=0x%X", idB, tostring(p3), pst3))
local d3, dst3 = del(idB)
print(string.format("  delete 0x%08X -> %s state=0x%08X", idB, tostring(d3), dst3))

-- clean up anything [A] left behind
del(idA)

pcall(function() return sc(6)(uint64(fd)) end)
print("")
print("=== 352p DONE ===")
