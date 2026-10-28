-- CRASH_CLASS: MODERATE
-- PROBE 71f2: Test 668 FIRST (665 kills on every shape tried)
--
-- 71f: 665(ids_ptr, 1, states_ptr) killed past pcall.
-- 71e: 665(id, 0, 0, 0, 0, 0) killed.
-- 665 faults inside the handler for every shape. Test 668 first.
--
-- 668 might be: aio_submit_single, aio_control, or aio_modify.
-- Test multiple arg layouts before touching 665.

print("=== PROBE 71f2: 668 FIRST, 665 LAST ===")
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

local pid = N(mk(20)())
print("pid=" .. pid)

-- Ignore SIGSYS
pcall(function() mk(416)(uint64(12), uint64(1), uint64(0)) end)

-- Open /dev/zero
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)
local ok, zfd_v = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local zfd = N(zfd_v)
print("zero_fd=" .. zfd)

local data_buf = memory.alloc(256)
local result_buf = memory.alloc(8)

local function aio_submit(fd)
    local req = memory.alloc(0x28)
    wq(req + 0x00, uint64(0))
    wq(req + 0x08, uint64(16))
    wq(req + 0x10, uint64(N(data_buf)))
    wq(req + 0x18, uint64(N(result_buf)))
    wq(req + 0x20, uint64(fd))
    local ib = memory.alloc(8); wd(ib, 0)
    pcall(function()
        mk(669)(uint64(1), uint64(N(req)), uint64(1), uint64(1), uint64(N(ib)))
    end)
    return rd(ib) or 0
end

local function aio_poll(aid)
    local ib = memory.alloc(8); wd(ib, aid)
    local sb = memory.alloc(8); wd(sb, 0xDEAD)
    pcall(function() mk(664)(uint64(N(ib)), uint64(1), uint64(N(sb))) end)
    return rd(sb)
end

local function aio_delete(aid)
    local ib = memory.alloc(8); wd(ib, aid)
    local sb = memory.alloc(8); wd(sb, 0xDEAD)
    pcall(function() mk(662)(uint64(N(ib)), uint64(1), uint64(N(sb))) end)
    return rd(sb)
end

local function aio_status(aid)
    local ib = memory.alloc(8); wd(ib, aid)
    local sb = memory.alloc(8); wd(sb, 0xDEAD)
    pcall(function() mk(666)(uint64(N(ib)), uint64(1), uint64(N(sb))) end)
    return rd(sb)
end

print("")

-- ============================================================
-- [A] 668 with 669-shaped args: 668(cmd, req, count, class, ids)
-- ============================================================
print("[A] 668 with 669-shape (submit?)")
local req_a = memory.alloc(0x28)
wq(req_a + 0x00, uint64(0))
wq(req_a + 0x08, uint64(16))
wq(req_a + 0x10, uint64(N(data_buf)))
wq(req_a + 0x18, uint64(N(result_buf)))
wq(req_a + 0x20, uint64(zfd))
local ids_a = memory.alloc(8); wd(ids_a, 0)

local ok_a, ret_a = pcall(function()
    return mk(668)(uint64(1), uint64(N(req_a)), uint64(1), uint64(1), uint64(N(ids_a)))
end)
local new_id_a = rd(ids_a)
print(string.format("  668(1,req,1,1,ids): ok=%s ret=%s new_id=0x%X",
    tostring(ok_a), ok_a and tostring(N(ret_a)) or "CRASH", new_id_a or 0))

if ok_a and new_id_a ~= 0 then
    print("  *** 668 IS an alternate submit! ***")
    local poll_a = aio_poll(new_id_a)
    print(string.format("    poll=0x%08X", poll_a or 0))
    local del_a = aio_delete(new_id_a)
    print(string.format("    delete=0x%08X", del_a or 0))
end
print("")

-- ============================================================
-- [B] 668 with 662-shaped args: 668(ids, count, states)
-- ============================================================
print("[B] 668 with 662-shape (batch status?)")
local id_b = aio_submit(zfd)
aio_poll(id_b)
local ids_b = memory.alloc(8); wd(ids_b, id_b)
local sts_b = memory.alloc(8); wd(sts_b, 0xDEAD)

local ok_b, ret_b = pcall(function()
    return mk(668)(uint64(N(ids_b)), uint64(1), uint64(N(sts_b)))
end)
local sts_b_val = rd(sts_b)
print(string.format("  668(ids,1,sts): ok=%s ret=%s sts=0x%08X",
    tostring(ok_b), ok_b and tostring(N(ret_b)) or "CRASH", sts_b_val or 0))
aio_delete(id_b)
print("")

-- ============================================================
-- [C] 668 with scalar args (cmd style)
-- ============================================================
print("[C] 668 with scalar args")
for _, v in ipairs({0, 1, 2, 3, 4, 5, 0x10, 0x100}) do
    local ok_c, ret_c = pcall(function()
        return mk(668)(uint64(v), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  668(%d,0,0,0,0,0): ok=%s ret=%s",
        v, tostring(ok_c), ok_c and tostring(N(ret_c)) or "CRASH"))
    if not ok_c then
        print("  *** 668 CRASHED — stopping scalar scan ***")
        break
    end
end
print("")

-- ============================================================
-- [D] 668 with AIO ID as first arg
-- ============================================================
print("[D] 668 with AIO ID as arg1")
local id_d = aio_submit(zfd)
aio_poll(id_d)
print(string.format("  id=0x%X", id_d))

-- 668(id, 0, 0) — maybe a single-ID operation?
local ok_d1, ret_d1 = pcall(function()
    return mk(668)(uint64(id_d), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  668(id,0,0,0,0,0): ok=%s ret=%s",
    tostring(ok_d1), ok_d1 and tostring(N(ret_d1)) or "CRASH"))

-- 668(id, flags, out) — maybe single cancel/query?
local out_d = memory.alloc(8); wd(out_d, 0xDEAD)
local ok_d2, ret_d2 = pcall(function()
    return mk(668)(uint64(id_d), uint64(1), uint64(N(out_d)), uint64(0), uint64(0), uint64(0))
end)
local out_d_val = rd(out_d)
print(string.format("  668(id,1,out,0,0,0): ok=%s ret=%s out=0x%08X",
    tostring(ok_d2), ok_d2 and tostring(N(ret_d2)) or "CRASH", out_d_val or 0))

aio_delete(id_d)
print("")

-- ============================================================
-- [E] 663 comparison (what does 663 return?)
-- ============================================================
print("[E] 663 vs 666 on polled requests")
for i = 1, 3 do
    local tid = aio_submit(zfd)
    aio_poll(tid)
    local s666 = aio_status(tid)

    local ib_663 = memory.alloc(8); wd(ib_663, tid)
    local sb_663 = memory.alloc(8); wd(sb_663, 0xDEAD)
    pcall(function() mk(663)(uint64(N(ib_663)), uint64(1), uint64(N(sb_663))) end)
    local s663 = rd(sb_663)

    print(string.format("  id=0x%X  666=0x%08X  663=0x%08X  %s",
        tid, s666 or 0, s663 or 0,
        (s666 == s663) and "SAME" or "DIFFERENT"))
    aio_delete(tid)
end
print("")

-- ============================================================
-- [F] 663 on UNPOLLED request (does it complete/wait?)
-- ============================================================
print("[F] 663 on unpolled request")
local id_f = aio_submit(zfd)
-- DON'T poll
local s666_f = aio_status(id_f)
print(string.format("  id=0x%X  666_unpolled=0x%08X", id_f, s666_f or 0))

local ib_f = memory.alloc(8); wd(ib_f, id_f)
local sb_f = memory.alloc(8); wd(sb_f, 0xDEAD)
pcall(function() mk(663)(uint64(N(ib_f)), uint64(1), uint64(N(sb_f))) end)
local s663_f = rd(sb_f)
print(string.format("  663_unpolled=0x%08X", s663_f or 0))

-- Check if 663 changed the state
local s666_after = aio_status(id_f)
print(string.format("  666_after_663=0x%08X", s666_after or 0))

-- Can we still poll + delete?
aio_poll(id_f)
aio_delete(id_f)
print("")

-- ============================================================
-- [G] 667 comparison
-- ============================================================
print("[G] 667 on polled request")
local id_g = aio_submit(zfd)
aio_poll(id_g)
local ib_g = memory.alloc(8); wd(ib_g, id_g)
local sb_g = memory.alloc(8); wd(sb_g, 0xDEAD)
local ok_g, ret_g = pcall(function()
    return mk(667)(uint64(N(ib_g)), uint64(1), uint64(N(sb_g)))
end)
local s667 = rd(sb_g)
print(string.format("  id=0x%X  667=0x%08X ok=%s ret=%s",
    id_g, s667 or 0, tostring(ok_g), ok_g and tostring(N(ret_g)) or "CRASH"))
aio_delete(id_g)
print("")

print("alive=YES")
print("=== PROBE 71f2 COMPLETE ===")
