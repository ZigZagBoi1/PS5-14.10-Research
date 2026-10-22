-- CRASH_CLASS: MODERATE
-- PROBE 352h: the AIO slot table, its capacity, and identifier reuse
--
-- Identifier sequence seen so far in one process: 0x0209, 0x2209, 0x4209 -
-- the low bits stay and bits 9-15 climb by two. That looks like a slot index
-- in the upper part and a small generation in the low part.
--
-- 352f (three submits, each deleted) worked. 352e and 352g, run later in the
-- same process, answered 0x80020005 in the result word for every request,
-- including a control that had worked before - so the submit returns 0 whether
-- or not a slot was free, and the refusal only appears in the result.
--
-- This probe measures, on a fresh process:
--   [B] how many requests can be outstanding at once, without deleting
--   [C] whether deleting frees a slot for the next submit
--   [D] whether a deleted identifier can be polled after its slot is reused,
--       which would mean the identifier is not generation-tagged

print("=== PROBE 352h: AIO SLOT TABLE ===")
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

local fd = open_path("/dev/urandom", 0)
print(string.format("fd = %d", fd))
if fd < 0 then
    print("=== 352h DONE ===")
    return
end

local function submit(off, len, buf, res, f)
    wq(reqs + 0x00, off)
    wq(reqs + 0x08, len)
    local bh, bl = hi_lo(buf)
    wd(reqs + 0x10, bl) wd(reqs + 0x14, bh)
    local rh, rl = hi_lo(res)
    wd(reqs + 0x18, rl) wd(reqs + 0x1C, rh)
    wd(reqs + 0x20, f)
    wd(reqs + 0x24, 0)
    wd(ids, 0)
    local ok, r = pcall(function()
        return sc(669)(uint64(1), uint64(reqs), uint64(1), uint64(1), uint64(ids))
    end)
    if not ok then return nil, 0 end
    return sgn(r), rd(ids)
end

local function poll_id(id)
    wd(ids, id)
    wd(states, 0)
    local ok, r = pcall(function()
        return sc(664)(uint64(ids), uint64(1), uint64(states))
    end)
    if not ok then return nil, 0 end
    return sgn(r), rd(states)
end

local function delete_id(id)
    wd(ids, id)
    wd(states, 0)
    local ok, r = pcall(function()
        return sc(662)(uint64(ids), uint64(1), uint64(states))
    end)
    if not ok then return nil end
    return sgn(r)
end

print("[A] submit without deleting, and watch the identifier and the result word")
local held = {}
local firstBad = 0
for i = 1, 24 do
    wd(result, 0)
    local r, id = submit(0, 16, uint64(data), uint64(result), fd)
    poll_id(id)
    local res0 = rd(result)
    held[i] = id
    print(string.format("  %2d submit=%s id=0x%08X result=0x%08X", i, tostring(r), id, res0))
    if res0 ~= 0x10 and firstBad == 0 then firstBad = i end
end
print(string.format("  first request whose result was not 0x10: %d", firstBad))

print("[B] delete the first four, then submit four more")
for i = 1, 4 do
    print(string.format("  delete id=0x%08X -> %s", held[i], tostring(delete_id(held[i]))))
end
for i = 1, 4 do
    wd(result, 0)
    local r, id = submit(0, 16, uint64(data), uint64(result), fd)
    poll_id(id)
    print(string.format("  new %d submit=%s id=0x%08X result=0x%08X", i, tostring(r), id, rd(result)))
end

print("[C] a deleted identifier after its slot is reused")
local rA, idA = submit(0, 16, uint64(data), uint64(result), fd)
print(string.format("  submit A -> %s id=0x%08X", tostring(rA), idA))
print(string.format("  delete A -> %s", tostring(delete_id(idA))))
local rB, idB = submit(0, 16, uint64(data), uint64(result), fd)
print(string.format("  submit B -> %s id=0x%08X", tostring(rB), idB))
local pr, ps = poll_id(idA)
print(string.format("  poll the OLD identifier 0x%08X -> %s state=0x%X (B is 0x%08X)",
    idA, tostring(pr), ps, idB))

print("[D] clean up")
for i = 5, 24 do
    if held[i] and held[i] ~= 0 then delete_id(held[i]) end
end
if idB and idB ~= 0 then delete_id(idB) end

print("")
print("=== 352h DONE ===")
