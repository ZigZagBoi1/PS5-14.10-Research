-- CRASH_CLASS: MODERATE
-- PROBE 71f: Test 665 with 662-shaped args (ids, count, states)
--
-- 71e showed: 665(id,0,0,0,0,0) kills — handler dereferences null args.
-- 665 might be aio_cancel or aio_batch_cancel with the SAME shape as 662.
-- Try 665(ids_array_ptr, count, states_ptr) with valid AIO IDs.
--
-- Also test 668 with 669-shaped args.

print("=== PROBE 71f: 665/668 WITH VALID SHAPES ===")
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
-- [A] 665 with 662-shaped args: 665(ids_ptr, count, states_ptr)
-- ============================================================
print("[A] 665 with 662-shape on POLLED request")

-- Submit and poll
local id_a = aio_submit(zfd)
aio_poll(id_a)
local st_before = aio_status(id_a)
print(string.format("  id=0x%X status_before=0x%08X", id_a, st_before or 0))

local ids_a = memory.alloc(8); wd(ids_a, id_a)
local sts_a = memory.alloc(8); wd(sts_a, 0xDEAD)

local ok_a, ret_a = pcall(function()
    return mk(665)(uint64(N(ids_a)), uint64(1), uint64(N(sts_a)))
end)
local sts_a_val = rd(sts_a)
print(string.format("  665(ids,1,sts): ok=%s ret=%s sts=0x%08X",
    tostring(ok_a), ok_a and tostring(N(ret_a)) or "CRASH", sts_a_val or 0))

if ok_a then
    local st_after = aio_status(id_a)
    print(string.format("  status_after=0x%08X", st_after or 0))

    -- Compare with 662 behavior
    if sts_a_val == 0 then
        print("  *** 665 returned success (0x00000000)! ***")
        print("  *** This is a CANCEL or alternate DELETE! ***")
    elseif sts_a_val == 0x80020003 then
        print("  665 returned 0x80020003 (unknown id)")
    elseif sts_a_val == 0x80020010 then
        print("  665 returned 0x80020010 (init-poisoned)")
    else
        print(string.format("  665 returned novel status: 0x%08X", sts_a_val))
    end

    -- Can we still delete with 662?
    local del_after = aio_delete(id_a)
    print(string.format("  662_delete_after_665=0x%08X", del_after or 0))
else
    print("  665 CRASHED the process (pcall caught)")
    print("  665 doesn't accept 662-shape on polled request")
end
print("")

-- ============================================================
-- [B] 665 with 662-shape on UNPOLLED request
-- ============================================================
print("[B] 665 with 662-shape on UNPOLLED request")

local id_b = aio_submit(zfd)
-- DON'T poll
local st_b = aio_status(id_b)
print(string.format("  id=0x%X status_before=0x%08X (unpolled)", id_b, st_b or 0))

local ids_b = memory.alloc(8); wd(ids_b, id_b)
local sts_b = memory.alloc(8); wd(sts_b, 0xDEAD)

local ok_b, ret_b = pcall(function()
    return mk(665)(uint64(N(ids_b)), uint64(1), uint64(N(sts_b)))
end)
local sts_b_val = rd(sts_b)
print(string.format("  665(ids,1,sts): ok=%s ret=%s sts=0x%08X",
    tostring(ok_b), ok_b and tostring(N(ret_b)) or "CRASH", sts_b_val or 0))

if ok_b then
    local st_b_after = aio_status(id_b)
    print(string.format("  status_after=0x%08X", st_b_after or 0))
end
print("")

-- ============================================================
-- [C] 665 with 4 args: 665(ids, count, states, flags)
-- ============================================================
print("[C] 665 with 4 args (possible flags)")

local id_c = aio_submit(zfd)
aio_poll(id_c)

local ids_c = memory.alloc(8); wd(ids_c, id_c)
local sts_c = memory.alloc(8); wd(sts_c, 0xDEAD)

-- Try with arg4 = 0, 1, 2
for _, flag in ipairs({0, 1, 2}) do
    local id_cf = aio_submit(zfd)
    aio_poll(id_cf)
    wd(ids_c, id_cf)
    wd(sts_c, 0xDEAD)
    local ok_c, ret_c = pcall(function()
        return mk(665)(uint64(N(ids_c)), uint64(1), uint64(N(sts_c)), uint64(flag))
    end)
    local sts_c_val = rd(sts_c)
    print(string.format("  665(ids,1,sts,%d): ok=%s ret=%s sts=0x%08X",
        flag, tostring(ok_c), ok_c and tostring(N(ret_c)) or "CRASH", sts_c_val or 0))
    if not ok_c then break end
end
print("")

-- ============================================================
-- [D] 668 with 669-shaped args: 668(cmd, req, count, class, ids)
-- ============================================================
print("[D] 668 with 669-shape")

local req_d = memory.alloc(0x28)
wq(req_d + 0x00, uint64(0))
wq(req_d + 0x08, uint64(16))
wq(req_d + 0x10, uint64(N(data_buf)))
wq(req_d + 0x18, uint64(N(result_buf)))
wq(req_d + 0x20, uint64(zfd))
local ids_d = memory.alloc(8); wd(ids_d, 0)

local ok_d, ret_d = pcall(function()
    return mk(668)(uint64(1), uint64(N(req_d)), uint64(1), uint64(1), uint64(N(ids_d)))
end)
local new_id_d = rd(ids_d)
print(string.format("  668(1,req,1,1,ids): ok=%s ret=%s new_id=0x%X",
    tostring(ok_d), ok_d and tostring(N(ret_d)) or "CRASH", new_id_d or 0))

if ok_d and new_id_d ~= 0 then
    print("  *** 668 IS an alternate submit path! ***")
    local poll_d = aio_poll(new_id_d)
    print(string.format("    poll=0x%08X", poll_d or 0))
    local del_d = aio_delete(new_id_d)
    print(string.format("    delete=0x%08X", del_d or 0))
end
print("")

-- ============================================================
-- [E] 668 with 662-shaped args: 668(ids, count, states)
-- ============================================================
print("[E] 668 with 662-shape")

local id_e = aio_submit(zfd)
aio_poll(id_e)
local ids_e = memory.alloc(8); wd(ids_e, id_e)
local sts_e = memory.alloc(8); wd(sts_e, 0xDEAD)

local ok_e, ret_e = pcall(function()
    return mk(668)(uint64(N(ids_e)), uint64(1), uint64(N(sts_e)))
end)
local sts_e_val = rd(sts_e)
print(string.format("  668(ids,1,sts): ok=%s ret=%s sts=0x%08X",
    tostring(ok_e), ok_e and tostring(N(ret_e)) or "CRASH", sts_e_val or 0))
print("")

-- ============================================================
-- [F] 666 status reference
-- ============================================================
print("[F] 666 status reference values")
local id_f = aio_submit(zfd)
print(string.format("  fresh: 0x%08X", aio_status(id_f) or 0))
aio_poll(id_f)
print(string.format("  polled: 0x%08X", aio_status(id_f) or 0))
aio_delete(id_f)
print(string.format("  deleted: 0x%08X", aio_status(id_f) or 0))
print("")

print("alive=YES")
print("=== PROBE 71f COMPLETE ===")
