-- CRASH_CLASS: MODERATE
-- PROBE 71e: Test AIO syscalls 665 and 668 with REAL arguments
--
-- The AIO range 661-670 has two unexplored members:
--   665: kills on zeros (untested with real args)
--   668: kills on zeros (untested with real args)
--
-- These might be:
--   665: aio_cancel (cancel pending request) — different race window than 662?
--   668: aio_submit_single or aio_control — alternate submit path?
--
-- Test with valid AIO IDs from 669 submit to see their real behavior.

print("=== PROBE 71e: AIO 665/668 WITH REAL ARGS ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local pid = N(mk(20)())
print("pid=" .. pid)

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

-- Ignore SIGSYS so absent/stub calls don't kill us
pcall(function()
    mk(416)(uint64(12), uint64(1), uint64(0))  -- sigaction(SIGSYS, SIG_IGN)
end)
print("SIGSYS ignored")
print("")

-- ============================================================
-- [A] 665 with real AIO ID (various arg layouts)
-- ============================================================
print("[A] Syscall 665 with real AIO ID")
print("")

-- Create an AIO request, poll it, then try 665 on it
local id_a = aio_submit(zfd)
local poll_a = aio_poll(id_a)
print(string.format("  id=0x%X poll_status=0x%08X", id_a, poll_a or 0))

-- 665 might be: cancel(id), cancel(id_array, count), cancel(id, flags)
-- Try different arg layouts

-- Layout 1: 665(id, 0, 0, 0, 0, 0)
local ok1, r1 = pcall(function()
    return mk(665)(uint64(id_a), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  665(id,0,0,0,0,0): ok=%s ret=%s", tostring(ok1), ok1 and tostring(N(r1)) or "pcall_fail"))

-- Check if the request still exists
local st_a1 = aio_status(id_a)
print(string.format("    after: 666(id)=0x%08X", st_a1 or 0))

-- Layout 2: 665(id_array_ptr, count, output_ptr, 0, 0, 0)
local id_b = aio_submit(zfd)
aio_poll(id_b)
local ib2 = memory.alloc(8); wd(ib2, id_b)
local ob2 = memory.alloc(8); wd(ob2, 0xDEAD)
local ok2, r2 = pcall(function()
    return mk(665)(uint64(N(ib2)), uint64(1), uint64(N(ob2)), uint64(0), uint64(0), uint64(0))
end)
local ob2_val = rd(ob2)
print(string.format("  665(ids,1,out,0,0,0): ok=%s ret=%s out=0x%08X", tostring(ok2), ok2 and tostring(N(r2)) or "pcall_fail", ob2_val or 0))
local st_b1 = aio_status(id_b)
print(string.format("    after: 666(id)=0x%08X", st_b1 or 0))

-- Layout 3: 665(id_array_ptr, count, output_ptr) — same as 662 shape
local id_c = aio_submit(zfd)
aio_poll(id_c)
local ib3 = memory.alloc(8); wd(ib3, id_c)
local ob3 = memory.alloc(8); wd(ob3, 0xDEAD)
local ok3, r3 = pcall(function()
    return mk(665)(uint64(N(ib3)), uint64(1), uint64(N(ob3)))
end)
local ob3_val = rd(ob3)
print(string.format("  665(ids,1,out): ok=%s ret=%s out=0x%08X", tostring(ok3), ok3 and tostring(N(r3)) or "pcall_fail", ob3_val or 0))

-- Layout 4: 665 with UNPOLLED request
local id_d = aio_submit(zfd)
-- DO NOT poll — test if 665 works on pending requests
local ib4 = memory.alloc(8); wd(ib4, id_d)
local ob4 = memory.alloc(8); wd(ob4, 0xDEAD)
local ok4, r4 = pcall(function()
    return mk(665)(uint64(N(ib4)), uint64(1), uint64(N(ob4)), uint64(0), uint64(0), uint64(0))
end)
local ob4_val = rd(ob4)
print(string.format("  665(unpolled ids,1,out): ok=%s ret=%s out=0x%08X", tostring(ok4), ok4 and tostring(N(r4)) or "pcall_fail", ob4_val or 0))
print("")

-- ============================================================
-- [B] 668 with real AIO ID (various arg layouts)
-- ============================================================
print("[B] Syscall 668 with real AIO ID")
print("")

-- 668 might be an alternate submit or control path
local id_e = aio_submit(zfd)
aio_poll(id_e)
print(string.format("  existing id=0x%X", id_e))

-- Layout 1: 668(id, 0, 0, 0, 0, 0)
local ok5, r5 = pcall(function()
    return mk(668)(uint64(id_e), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print(string.format("  668(id,0,0,0,0,0): ok=%s ret=%s", tostring(ok5), ok5 and tostring(N(r5)) or "pcall_fail"))

-- Check if the request still exists
local st_e1 = aio_status(id_e)
print(string.format("    after: 666(id)=0x%08X", st_e1 or 0))

-- Layout 2: 668 with request struct (like 669)
local req2 = memory.alloc(0x28)
wq(req2 + 0x00, uint64(0))
wq(req2 + 0x08, uint64(16))
wq(req2 + 0x10, uint64(N(data_buf)))
wq(req2 + 0x18, uint64(N(result_buf)))
wq(req2 + 0x20, uint64(zfd))
local ib6 = memory.alloc(8); wd(ib6, 0)
local ok6, r6 = pcall(function()
    return mk(668)(uint64(1), uint64(N(req2)), uint64(1), uint64(1), uint64(N(ib6)))
end)
local new_id = rd(ib6)
print(string.format("  668(1,req,1,1,ids): ok=%s ret=%s new_id=0x%X", tostring(ok6), ok6 and tostring(N(r6)) or "pcall_fail", new_id or 0))

-- Layout 3: 668 with small integers
for _, v in ipairs({1, 2, 3, 4, 5, 0x10, 0x100}) do
    local ok7, r7 = pcall(function()
        return mk(668)(uint64(v), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    print(string.format("  668(%d,0,0,0,0,0): ok=%s ret=%s", v, tostring(ok7), ok7 and tostring(N(r7)) or "pcall_fail"))
end
print("")

-- ============================================================
-- [C] 665 as CANCEL — test on PENDING (unpolled) request
-- ============================================================
print("[C] 665 cancel-before-complete hypothesis")

-- Submit a request but DON'T poll — it might still be "pending"
-- Then try 665 as a cancel. If it works, the request transitions to "cancelled"
local id_f = aio_submit(zfd)
local st_f_before = aio_status(id_f)
print(string.format("  id=0x%X status_before=0x%08X", id_f, st_f_before or 0))

-- Try cancel with 662-shaped args
local ib_f = memory.alloc(8); wd(ib_f, id_f)
local ob_f = memory.alloc(8); wd(ob_f, 0xDEAD)
local ok_f, r_f = pcall(function()
    return mk(665)(uint64(N(ib_f)), uint64(1), uint64(N(ob_f)))
end)
local ob_f_val = rd(ob_f)
print(string.format("  665(ids,1,out): ok=%s ret=%s out=0x%08X", tostring(ok_f), ok_f and tostring(N(r_f)) or "pcall_fail", ob_f_val or 0))

local st_f_after = aio_status(id_f)
print(string.format("  status_after=0x%08X", st_f_after or 0))

-- Try to poll it now
local poll_f = aio_poll(id_f)
print(string.format("  poll_after_cancel=0x%08X", poll_f or 0))

-- Try to delete it
local del_f = aio_delete(id_f)
print(string.format("  delete=0x%08X", del_f or 0))
print("")

-- ============================================================
-- [D] What does 666 return for various states?
-- ============================================================
print("[D] 666 status values for different request states")

-- Fresh (unpolled)
local id_g = aio_submit(zfd)
local st_fresh = aio_status(id_g)
print(string.format("  fresh (unpolled): 0x%08X", st_fresh or 0))

-- After poll
aio_poll(id_g)
local st_polled = aio_status(id_g)
print(string.format("  polled: 0x%08X", st_polled or 0))

-- After delete
aio_delete(id_g)
local st_deleted = aio_status(id_g)
print(string.format("  deleted: 0x%08X", st_deleted or 0))

-- Never existed
local st_fake = aio_status(0xDEAD)
print(string.format("  fake(0xDEAD): 0x%08X", st_fake or 0))
print("")

-- Cleanup
pcall(function() mk(6)(uint64(zfd)) end)

print("alive=YES")
print("=== PROBE 71e COMPLETE ===")
