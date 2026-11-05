-- CRASH_CLASS: LOW
-- PROBE 94d: AIO status lifecycle debug
--
-- 94c: poll=0x00000001, delete=0x80020010. AIO reads on /dev/zero might not
-- complete immediately. Need to understand the status lifecycle.

print("=== PROBE 94d: AIO STATUS DEBUG ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(N(p) + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(N(p) + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- AIO syscalls
local reqs = memory.alloc(0x30)
local one_id = memory.alloc(8)
local one_st = memory.alloc(8)
local sp_buf = memory.alloc(8)

pcall(function() mk(670)() end) -- init

-- Helpers
local function aio_submit(fd, nbytes)
    local data_buf = memory.alloc(0x100)
    local result_buf = memory.alloc(0x10)
    wq(N(reqs), uint64(0))
    wq(N(reqs) + 8, uint64(nbytes or 16))
    local bh, bl = (function()
        local v = uint64(N(data_buf))
        if type(v) == "table" and v.h then return v.h, v.l end
        return 0, N(v)
    end)()
    wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
    local rh, rl = (function()
        local v = uint64(N(result_buf))
        if type(v) == "table" and v.h then return v.h, v.l end
        return 0, N(v)
    end)()
    wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
    wd(N(reqs) + 0x20, fd); wd(N(reqs) + 0x24, 0)
    wd(N(one_id), 0)
    local ok, rv = pcall(function()
        return mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
    end)
    local ret = ok and sgn(rv) or -999
    return rd(N(one_id)) or 0, ret
end

local function aio_poll(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    local ret = ok and sgn(rv) or -999
    return rd(N(one_st)) or 0xDEADDEAD, ret
end

local function aio_delete(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    local ret = ok and sgn(rv) or -999
    return rd(N(one_st)) or 0xDEADDEAD, ret
end

local function aio_wait(id)
    wd(N(one_id), id); wd(N(one_st), 0xDEADDEAD)
    local ok, rv = pcall(function()
        return mk(663)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    local ret = ok and sgn(rv) or -999
    return rd(N(one_st)) or 0xDEADDEAD, ret
end

-- ============================
-- [A] /dev/zero AIO read lifecycle
-- ============================
print("[A] /dev/zero AIO read")
local fd_zero = sgn(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("  fd_zero=" .. fd_zero)

local id_a, rv_a = aio_submit(fd_zero, 16)
print(string.format("  submit: id=0x%X rv=%d", id_a, rv_a))

local st1, rv1 = aio_poll(id_a)
print(string.format("  poll immediately: st=0x%08X rv=%d", st1, rv1))

-- Spin delay
for w = 1, 100000 do local _ = rd(N(sp_buf)) end

local st2, rv2 = aio_poll(id_a)
print(string.format("  poll after spin: st=0x%08X rv=%d", st2, rv2))

-- Try 663 wait
local st3, rv3 = aio_wait(id_a)
print(string.format("  wait(663): st=0x%08X rv=%d", st3, rv3))

local st4, rv4 = aio_poll(id_a)
print(string.format("  poll after wait: st=0x%08X rv=%d", st4, rv4))

local st5, rv5 = aio_delete(id_a)
print(string.format("  delete: st=0x%08X rv=%d", st5, rv5))

local st6, rv6 = aio_poll(id_a)
print(string.format("  poll after delete: st=0x%08X rv=%d", st6, rv6))

-- ============================
-- [B] Socketpair AIO read (blocking)
-- ============================
print("")
print("[B] Socketpair AIO read (no data = pending)")
wd(N(sp_buf), 0); wd(N(sp_buf)+4, 0)
sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp_buf)) -- SOCK_STREAM
local sp_r = rd(N(sp_buf)) or -1
local sp_w = rd(N(sp_buf)+4) or -1
print(string.format("  socketpair r=%d w=%d", sp_r, sp_w))

local id_b, rv_b = aio_submit(sp_r, 16)
print(string.format("  submit: id=0x%X rv=%d", id_b, rv_b))

local stb1, rvb1 = aio_poll(id_b)
print(string.format("  poll (no data): st=0x%08X rv=%d", stb1, rvb1))

-- Write data to unblock
local wbuf = memory.alloc(32)
for i = 0, 28, 4 do wd(N(wbuf) + i, 0x42424242) end
pcall(function() mk(4)(uint64(sp_w), uint64(N(wbuf)), uint64(16)) end)

for w = 1, 10000 do local _ = rd(N(sp_buf)) end

local stb2, rvb2 = aio_poll(id_b)
print(string.format("  poll (after write): st=0x%08X rv=%d", stb2, rvb2))

local stb3, rvb3 = aio_delete(id_b)
print(string.format("  delete: st=0x%08X rv=%d", stb3, rvb3))

pcall(function() mk(6)(uint64(sp_r)) end)
pcall(function() mk(6)(uint64(sp_w)) end)

-- ============================
-- [C] Socketpair AIO write (always completes)
-- ============================
print("")
print("[C] Socketpair AIO write")
wd(N(sp_buf), 0); wd(N(sp_buf)+4, 0)
sgn(mk(135)(uint64(1), uint64(1), uint64(0), sp_buf))
local sp_r2 = rd(N(sp_buf)) or -1
local sp_w2 = rd(N(sp_buf)+4) or -1

-- AIO WRITE (cmd=2) on the write fd
wq(N(reqs), uint64(0))
wq(N(reqs) + 8, uint64(16))
local bh, bl = (function()
    local v = uint64(N(wbuf))
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end)()
wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
local rh, rl = (function()
    local rb = memory.alloc(0x10)
    local v = uint64(N(rb))
    if type(v) == "table" and v.h then return v.h, v.l end
    return 0, N(v)
end)()
wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
wd(N(reqs) + 0x20, sp_w2); wd(N(reqs) + 0x24, 0)
wd(N(one_id), 0)
pcall(function()
    mk(669)(uint64(2), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
end)
local id_c = rd(N(one_id)) or 0
print(string.format("  submit write: id=0x%X", id_c))

local stc1, rvc1 = aio_poll(id_c)
print(string.format("  poll: st=0x%08X rv=%d", stc1, rvc1))

local stc2, rvc2 = aio_delete(id_c)
print(string.format("  delete: st=0x%08X rv=%d", stc2, rvc2))

pcall(function() mk(6)(uint64(sp_r2)) end)
pcall(function() mk(6)(uint64(sp_w2)) end)

-- ============================
-- [D] Check 666 (another AIO call)
-- ============================
print("")
print("[D] 666 (AIO reap) status check")
local id_d = aio_submit(fd_zero, 16)
if id_d ~= 0 then
    wd(N(one_id), id_d); wd(N(one_st), 0xDEADDEAD)
    local ok_d, rv_d = pcall(function()
        return mk(666)(uint64(N(one_id)), uint64(1), uint64(N(one_st)))
    end)
    local std = rd(N(one_st)) or 0xDEADDEAD
    print(string.format("  666: st=0x%08X rv=%s", std, tostring(rv_d)))
    aio_delete(id_d)
end

print("")
print("=== 94d COMPLETE ===")
