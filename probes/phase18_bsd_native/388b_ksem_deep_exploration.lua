-- CRASH_CLASS: MODERATE
-- PROBE 388b: ksem deep exploration
--
-- Context: 388a confirmed ksem_init(404) creates kernel semaphore objects on
-- 14.10. IDs are sequential (0x17+). ksem_destroy(406) returns -1.
-- ksem_getvalue after ksem_post showed val=0 (unexpected).
--
-- This probe explores:
--   [A] Full ksem family: init, post, wait, trywait, timedwait, getvalue, destroy
--   [B] ksem_open(405) — named semaphores, cross-process potential
--   [C] Destroy patterns — close(fd), different args, after wait
--   [D] Stress test — allocation ceiling, id reuse after "free"
--   [E] Race surface — post/wait from main thread (no child needed for initial)
--   [F] Kernel pointer scan in any output buffers

print("=== PROBE 388b: ksem deep exploration ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Syscalls
local sc_ksem_init    = mk(404)  -- ksem_init(semid_t *idp, unsigned int value)
local sc_ksem_open    = mk(405)  -- ksem_open(semid_t *idp, const char *name, int oflag, mode_t mode, unsigned int value)
local sc_ksem_unlink  = mk(408)  -- ksem_unlink(const char *name)
local sc_ksem_close   = mk(400)  -- ksem_close(semid_t id)
local sc_ksem_post    = mk(402)  -- ksem_post(semid_t id)
local sc_ksem_wait    = mk(401)  -- ksem_wait(semid_t id)
local sc_ksem_trywait = mk(403)  -- ksem_trywait(semid_t id)
local sc_ksem_getval  = mk(407)  -- ksem_getvalue(semid_t id, int *val)
local sc_ksem_destroy = mk(406)  -- ksem_destroy(semid_t id)
-- 441 = ksem_timedwait(semid_t id, const struct timespec *abstime)
local sc_ksem_twait   = mk(441)
local sc_close        = mk(6)

local idp = memory.alloc(16)
local val_buf = memory.alloc(16)

local function ksem_create(value)
    zero_buf(idp, 16)
    local ok, rv = pcall(function() return sc_ksem_init(idp, uint64(value or 1)) end)
    local ret = ok and N(rv) or -999
    local id = rd(N(idp))
    return ret, id or 0
end

local function ksem_getval(id)
    zero_buf(val_buf, 16)
    local ok, rv = pcall(function() return sc_ksem_getval(uint64(id), val_buf) end)
    local ret = ok and N(rv) or -999
    local val = rd(N(val_buf))
    return ret, val or -1
end

-- ===================================================================
-- [A] Basic operations on a fresh semaphore
-- ===================================================================
print("[A] basic ksem operations")

local ret, sid = ksem_create(5)
print(string.format("  create(val=5): ret=%d, id=0x%X", ret, sid))

if ret ~= 0 then print("  FATAL: ksem_init failed"); return end

-- getvalue
ret, val = ksem_getval(sid)
print(string.format("  getvalue: ret=%d, val=%d", ret, val))

-- post (increment)
local ok, rv = pcall(function() return sc_ksem_post(uint64(sid)) end)
print("  post: ret=" .. (ok and N(rv) or -999))
ret, val = ksem_getval(sid)
print(string.format("  getvalue after post: ret=%d, val=%d", ret, val))

-- trywait (decrement if > 0)
ok, rv = pcall(function() return sc_ksem_trywait(uint64(sid)) end)
print("  trywait: ret=" .. (ok and N(rv) or -999))
ret, val = ksem_getval(sid)
print(string.format("  getvalue after trywait: ret=%d, val=%d", ret, val))

-- multiple trywait to drain
for i = 1, 6 do
    ok, rv = pcall(function() return sc_ksem_trywait(uint64(sid)) end)
    local r = ok and N(rv) or -999
    if r ~= 0 then
        print(string.format("  trywait #%d: ret=%d (sem drained at count=%d)", i, r, i-1))
        break
    end
end
ret, val = ksem_getval(sid)
print(string.format("  getvalue drained: ret=%d, val=%d", ret, val))

-- timedwait with zero timeout (should fail immediately if value=0)
local ts_buf = memory.alloc(16)
zero_buf(ts_buf, 16)
-- timespec: tv_sec=0, tv_nsec=1 (1 nanosecond — essentially immediate)
wd(N(ts_buf), 0)
wd(N(ts_buf) + 8, 1)
ok, rv = pcall(function() return sc_ksem_twait(uint64(sid), ts_buf) end)
print("  timedwait(0,1ns): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Destroy/close patterns
-- ===================================================================
print("[B] destroy/close patterns")

-- B1: ksem_destroy(406) — failed in 388a
ok, rv = pcall(function() return sc_ksem_destroy(uint64(sid)) end)
print("  ksem_destroy(sid): ret=" .. (ok and N(rv) or -999))

-- B2: ksem_close(400)
ok, rv = pcall(function() return sc_ksem_close(uint64(sid)) end)
print("  ksem_close(sid): ret=" .. (ok and N(rv) or -999))

-- B3: Can we still use it after close?
ret, val = ksem_getval(sid)
print(string.format("  getvalue after close: ret=%d, val=%d", ret, val))

-- B4: close(6) on the id (treat as fd)
ok, rv = pcall(function() return sc_close(uint64(sid)) end)
print("  close(6)(sid): ret=" .. (ok and N(rv) or -999))

-- B5: Use after close(6)
ret, val = ksem_getval(sid)
print(string.format("  getvalue after close(6): ret=%d, val=%d", ret, val))

-- B6: Create new, try ksem_close
ret, sid = ksem_create(1)
print(string.format("  new sem: ret=%d, id=0x%X", ret, sid))
if ret == 0 then
    ok, rv = pcall(function() return sc_ksem_close(uint64(sid)) end)
    print("  ksem_close(new): ret=" .. (ok and N(rv) or -999))
    -- Double close
    ok, rv = pcall(function() return sc_ksem_close(uint64(sid)) end)
    print("  double ksem_close: ret=" .. (ok and N(rv) or -999))
    -- Post after close
    ok, rv = pcall(function() return sc_ksem_post(uint64(sid)) end)
    print("  post after close: ret=" .. (ok and N(rv) or -999))
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] Named semaphores (ksem_open / ksem_unlink)
-- ===================================================================
print("[C] named semaphores")

local function make_name(s)
    local buf = memory.alloc(64)
    zero_buf(buf, 64)
    for i = 0, #s - 1, 4 do
        local d = 0
        for j = 0, 3 do
            if i + j < #s then d = d + string.byte(s, i + j + 1) * (256 ^ j) end
        end
        wd(N(buf) + i, d)
    end
    return buf
end

-- C1: ksem_open with O_CREAT
local name = make_name("/test1")
zero_buf(idp, 16)
-- O_CREAT=0x200
ok, rv = pcall(function() return sc_ksem_open(idp, name, uint64(0x200), uint64(0x1FF), uint64(1)) end)
local open_ret = ok and N(rv) or -999
local open_id = rd(N(idp))
print(string.format("  ksem_open('/test1', O_CREAT): ret=%d, id=0x%X", open_ret, open_id or 0))

if open_ret == 0 and open_id and open_id > 0 then
    -- C2: Open same name again (without O_EXCL)
    zero_buf(idp, 16)
    ok, rv = pcall(function() return sc_ksem_open(idp, name, uint64(0x200), uint64(0x1FF), uint64(1)) end)
    local r2 = ok and N(rv) or -999
    local id2 = rd(N(idp))
    print(string.format("  reopen same name: ret=%d, id=0x%X (same=%s)", r2, id2 or 0, tostring(id2 == open_id)))

    -- C3: Open with O_CREAT|O_EXCL (should fail — already exists)
    zero_buf(idp, 16)
    ok, rv = pcall(function() return sc_ksem_open(idp, name, uint64(0xA00), uint64(0x1FF), uint64(1)) end)
    local r3 = ok and N(rv) or -999
    print("  open O_CREAT|O_EXCL existing: ret=" .. r3)

    -- C4: ksem_unlink
    ok, rv = pcall(function() return sc_ksem_unlink(name) end)
    print("  ksem_unlink('/test1'): ret=" .. (ok and N(rv) or -999))

    -- C5: Use after unlink
    ret, val = ksem_getval(open_id)
    print(string.format("  getvalue after unlink: ret=%d, val=%d", ret, val))

    -- C6: Close after unlink (should trigger final destroy)
    ok, rv = pcall(function() return sc_ksem_close(uint64(open_id)) end)
    print("  close after unlink: ret=" .. (ok and N(rv) or -999))

    -- C7: Use after unlink+close (UAF candidate!)
    ret, val = ksem_getval(open_id)
    print(string.format("  getvalue after unlink+close: ret=%d, val=%d ***", ret, val))
    ok, rv = pcall(function() return sc_ksem_post(uint64(open_id)) end)
    print("  post after unlink+close: ret=" .. (ok and N(rv) or -999) .. " ***")

    -- C8: If second open got a different id, close that too
    if id2 and id2 ~= open_id and id2 > 0 then
        ok, rv = pcall(function() return sc_ksem_close(uint64(id2)) end)
        print("  close id2: ret=" .. (ok and N(rv) or -999))
    end
else
    print("  ksem_open not available")
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] Allocation ceiling + ID reuse
-- ===================================================================
print("[D] allocation ceiling + ID reuse")

local created = {}
local max_sem = 200
for i = 1, max_sem do
    if not alive() then break end
    local r, id = ksem_create(1)
    if r ~= 0 then
        print(string.format("  ceiling hit at %d sems (ret=%d)", i, r))
        break
    end
    created[#created + 1] = id
    if i == max_sem then
        print(string.format("  created %d sems, last id=0x%X (no ceiling in range)", i, id))
    end
end

-- Close half and check ID reuse
if #created > 10 then
    local closed_ids = {}
    for i = 1, 5 do
        local id = created[i]
        ok, rv = pcall(function() return sc_ksem_close(uint64(id)) end)
        local r = ok and N(rv) or -999
        closed_ids[#closed_ids + 1] = {id = id, close_ret = r}
    end
    print(string.format("  closed 5 sems (first: 0x%X, close_ret=%d)", closed_ids[1].id, closed_ids[1].close_ret))

    -- Create new ones — do IDs get reused?
    local new_ids = {}
    for i = 1, 5 do
        local r, id = ksem_create(1)
        if r == 0 then new_ids[#new_ids + 1] = id end
    end
    if #new_ids > 0 then
        local strs = {}
        for _, id in ipairs(new_ids) do strs[#strs + 1] = string.format("0x%X", id) end
        print("  new IDs after close: " .. table.concat(strs, ", "))
        -- Check if any match closed IDs
        for _, nid in ipairs(new_ids) do
            for _, cid in ipairs(closed_ids) do
                if nid == cid.id then
                    print("  *** ID REUSE: 0x" .. string.format("%X", nid) .. " ***")
                end
            end
        end
    end

    -- Cleanup new
    for _, id in ipairs(new_ids) do
        pcall(function() sc_ksem_close(uint64(id)) end)
    end
end

-- Cleanup remaining
for i = 6, #created do
    pcall(function() sc_ksem_close(uint64(created[i])) end)
end

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] sys 624 VM op counting
-- ===================================================================
print("[E] sys 624 VM op count around ksem")

local sc624 = mk(624)
local function vm_ops()
    local ok, rv = pcall(function() return sc624() end)
    return ok and N(rv) or -1
end

local before = vm_ops()
local r1, id1 = ksem_create(1)
local after_create = vm_ops()
pcall(function() sc_ksem_post(uint64(id1)) end)
local after_post = vm_ops()
pcall(function() sc_ksem_close(uint64(id1)) end)
local after_close = vm_ops()

print(string.format("  VM ops: before=%d, after_create=%d (+%d), after_post=%d (+%d), after_close=%d (+%d)",
    before, after_create, after_create - before,
    after_post, after_post - after_create,
    after_close, after_close - after_post))

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] Summary
-- ===================================================================
print("[F] SUMMARY")
print("  ksem_init: WORKS (creates kernel objects)")
print("  ksem_post/trywait/getvalue: WORKS")
print("  ksem_destroy(406): " .. "needs recheck")
print("  ksem_close(400): " .. "tested above")
print("  ksem_open(405): " .. (open_ret == 0 and "WORKS (named sems)" or "ret=" .. open_ret))
print("  ksem_unlink(408): " .. "tested above")
print("  ksem_timedwait(441): tested above")

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 388b COMPLETE ===")
