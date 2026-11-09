-- CRASH_CLASS: MODERATE
-- PROBE 352a: the batched AIO submit, with a real descriptor
--
-- The AIO range was written off after 661 killed the process with a FreeBSD
-- aiocb. results/kernel_handlers/analysis/sys_669_deep.md shows that 669 is a
-- different entry: _aio_submit_cmd, five slots (cmd, user_reqs, count 1..128,
-- class 1..3, user_ids), user descriptors of stride 0x28 (offset, byte count,
-- data pointer, result pointer, fd), allocating 40*count bytes and copying the
-- same. 662/664/666 then operate on the identifiers it returns. Nobody has ever
-- called any of this with a real descriptor, so this probe submits one request
-- against /dev/zero and walks the family with the identifier it gets back.

print("=== PROBE 352a: AIO BATCH ===")
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
    local h, l = hi_lo(uint64(value))
    pcall(function() memory.write_dword(addr + 4, h) end)
    pcall(function() memory.write_dword(addr, l) end)
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
    local p = memory.alloc(#s + 1)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

print("[A] open /dev/zero")
local fdzero = -1
local ok, rv = pcall(function() return sc(5)(put_str("/dev/zero"), uint64(0), Z) end)
if ok then
    local h, l = hi_lo(rv)
    fdzero = sgn(rv)
    print(string.format("  open(/dev/zero, O_RDONLY) = %d", fdzero))
else
    print("  open raised")
end

local reqs = memory.alloc(0x100)
local data = memory.alloc(0x1000)
local result = memory.alloc(0x100)
local ids = memory.alloc(0x100)
for i = 0, 0x3F do
    wq(reqs + i * 8, 0)
    wd(data + i * 4, 0)
    wd(result + i * 4, 0)
    wd(ids + i * 4, 0)
end

local function fill_req(base, off, len, buf, res, fd)
    wq(base + 0x00, off)
    wq(base + 0x08, len)
    local bh, bl = hi_lo(uint64(buf))
    wd(base + 0x10, bl) wd(base + 0x14, bh)
    local rh, rl = hi_lo(uint64(res))
    wd(base + 0x18, rl) wd(base + 0x1C, rh)
    wd(base + 0x20, fd)
    wd(base + 0x24, 0)
end

local function submit(cmd, count, class, label)
    local ok2, r = pcall(function()
        return sc(669)(uint64(cmd), uint64(reqs), uint64(count), uint64(class), uint64(ids))
    end)
    if not ok2 then print(string.format("  %-30s = EXC", label)) return nil end
    local id = rd(ids)
    print(string.format("  %-30s = %s  id[0]=0x%X", label, tostring(sgn(r)), id))
    return sgn(r), id
end

print("[B] submit one read request (cmd=1, class=1)")
if fdzero >= 0 then
    fill_req(reqs, 0, 16, data, result, fdzero)
else
    fill_req(reqs, 0, 16, data, result, 0)
end
local ret, id = submit(1, 1, 1, "669(cmd=1,count=1,class=1)")

print("[C] slot permutations, in case the order differs from the dossier")
local function raw(a, b, c, d, e, label)
    local ok4, r = pcall(function()
        return sc(669)(uint64(a), uint64(b), uint64(c), uint64(d), uint64(e))
    end)
    if not ok4 then print(string.format("  %-34s = EXC", label)) return end
    print(string.format("  %-34s = %s  id[0]=0x%X", label, tostring(sgn(r)), rd(ids)))
end
raw(1, reqs, 1, 1, ids, "cmd,reqs,count,class,ids")
raw(reqs, 1, 1, 1, ids, "reqs,count,class,cmd,ids")
raw(reqs, 1, 1, 1, 0, "reqs,count,class,cmd,0")
raw(reqs, 1, 1, 1, ids, "reqs,count,cmd,class,ids")

print("[D] argument gates")
submit(0, 1, 1, "cmd=0")
submit(1, 0, 1, "count=0")
submit(1, 129, 1, "count=129")
submit(1, 1, 0, "class=0")
submit(1, 1, 4, "class=4")

print("[D] the family against the identifier from [B]")
if id and id ~= 0 and id ~= 0xFFFFFFFF then
    local states = memory.alloc(0x100)
    for i = 0, 0x3F do wd(states + i * 4, 0) end
    local function fam(n, label)
        local ok3, r = pcall(function()
            return sc(n)(uint64(ids), uint64(1), uint64(states))
        end)
        if not ok3 then print(string.format("  %-12s = EXC", label)) return end
        print(string.format("  %-12s = %s  state=0x%X", label, tostring(sgn(r)), rd(states)))
    end
    fam(664, "664 poll")
    fam(666, "666 cancel")
    fam(664, "664 poll 2")
    fam(662, "662 delete")
    fam(662, "662 delete2")
else
    print("  no identifier, family not called")
end

print("")
print("=== 352a DONE ===")
