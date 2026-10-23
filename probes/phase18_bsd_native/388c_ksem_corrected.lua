-- CRASH_CLASS: MODERATE
-- PROBE 388c: ksem corrected syscall numbers
--
-- Context: 388b had post/wait and destroy/unlink SWAPPED.
-- Correct FreeBSD r230171 mapping:
--   400 = ksem_close   (named only)
--   401 = ksem_post    (increment)
--   402 = ksem_wait    (decrement, blocks)
--   403 = ksem_trywait (decrement, non-blocking)
--   404 = ksem_init    (unnamed create)
--   405 = ksem_open    (named create)
--   406 = ksem_unlink  (remove name)
--   407 = ksem_getvalue
--   408 = ksem_destroy (unnamed destroy)
--   441 = ksem_timedwait
--
-- Tests:
--   [A] Real ksem_post(401) — does it increment?
--   [B] Real ksem_destroy(408) on unnamed — does it free?
--   [C] Real ksem_unlink(406) on named — remove name
--   [D] Post+trywait cycle with correct ops
--   [E] Named sem: open, unlink, close lifecycle (UAF window)
--   [F] ID reuse via destroy vs close(6)

print("=== PROBE 388c: ksem corrected syscall numbers ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- CORRECT syscall assignments
local sc_ksem_close    = mk(400)
local sc_ksem_post     = mk(401)
local sc_ksem_wait     = mk(402)
local sc_ksem_trywait  = mk(403)
local sc_ksem_init     = mk(404)
local sc_ksem_open     = mk(405)
local sc_ksem_unlink   = mk(406)
local sc_ksem_getval   = mk(407)
local sc_ksem_destroy  = mk(408)
local sc_ksem_twait    = mk(441)
local sc_close         = mk(6)

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

-- ===================================================================
-- [A] Real ksem_post(401) — should INCREMENT
-- ===================================================================
print("[A] real ksem_post(401)")

local ret, sid = ksem_create(3)
print(string.format("  create(val=3): ret=%d, id=0x%X", ret, sid))
if ret ~= 0 then print("  FATAL"); return end

ret, val = ksem_getval(sid)
print(string.format("  getvalue: ret=%d, val=%d", ret, val))

local ok, rv = pcall(function() return sc_ksem_post(uint64(sid)) end)
print("  post(401): ret=" .. (ok and N(rv) or -999))
ret, val = ksem_getval(sid)
print(string.format("  getvalue after post: ret=%d, val=%d (expect 4)", ret, val))

ok, rv = pcall(function() return sc_ksem_post(uint64(sid)) end)
print("  post(401) #2: ret=" .. (ok and N(rv) or -999))
ret, val = ksem_getval(sid)
print(string.format("  getvalue after 2nd post: ret=%d, val=%d (expect 5)", ret, val))

-- Drain with trywait to confirm
local drained = 0
for i = 1, 10 do
    ok, rv = pcall(function() return sc_ksem_trywait(uint64(sid)) end)
    if not ok or N(rv) ~= 0 then break end
    drained = drained + 1
end
print(string.format("  drained %d with trywait (should match final value)", drained))

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Real ksem_destroy(408) on unnamed
-- ===================================================================
print("[B] real ksem_destroy(408) on unnamed")

ret, sid = ksem_create(1)
print(string.format("  create: ret=%d, id=0x%X", ret, sid))

-- Try destroy(408)
ok, rv = pcall(function() return sc_ksem_destroy(uint64(sid)) end)
print("  ksem_destroy(408): ret=" .. (ok and N(rv) or -999))

-- Can we still use it?
ret, val = ksem_getval(sid)
print(string.format("  getvalue after destroy: ret=%d, val=%d", ret, val))

-- Try post after destroy
ok, rv = pcall(function() return sc_ksem_post(uint64(sid)) end)
print("  post after destroy: ret=" .. (ok and N(rv) or -999))

-- Compare: close(6) on a new one
ret, sid = ksem_create(1)
print(string.format("  new create: ret=%d, id=0x%X", ret, sid))
ok, rv = pcall(function() return sc_close(uint64(sid)) end)
print("  close(6): ret=" .. (ok and N(rv) or -999))
ret, val = ksem_getval(sid)
print(string.format("  getvalue after close(6): ret=%d, val=%d", ret, val))

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] Real ksem_unlink(406) on named
-- ===================================================================
print("[C] real ksem_unlink(406) on named")

local name1 = make_name("/probe388c")
zero_buf(idp, 16)
ok, rv = pcall(function() return sc_ksem_open(idp, name1, uint64(0x200), uint64(0x1FF), uint64(7)) end)
local oret = ok and N(rv) or -999
local oid = rd(N(idp))
print(string.format("  open('/probe388c', O_CREAT, val=7): ret=%d, id=0x%X", oret, oid or 0))

if oret == 0 and oid and oid > 0 then
    ret, val = ksem_getval(oid)
    print(string.format("  getvalue: ret=%d, val=%d", ret, val))

    -- Real unlink(406) with name
    ok, rv = pcall(function() return sc_ksem_unlink(name1) end)
    print("  ksem_unlink(406, '/probe388c'): ret=" .. (ok and N(rv) or -999))

    -- Still usable after unlink?
    ret, val = ksem_getval(oid)
    print(string.format("  getvalue after unlink: ret=%d, val=%d", ret, val))

    -- Post should still work
    ok, rv = pcall(function() return sc_ksem_post(uint64(oid)) end)
    print("  post after unlink: ret=" .. (ok and N(rv) or -999))
    ret, val = ksem_getval(oid)
    print(string.format("  getvalue: ret=%d, val=%d", ret, val))

    -- Now close — this should be the final drop
    ok, rv = pcall(function() return sc_ksem_close(uint64(oid)) end)
    print("  ksem_close(400) after unlink: ret=" .. (ok and N(rv) or -999))

    -- *** UAF TEST: use after unlink+close ***
    ret, val = ksem_getval(oid)
    print(string.format("  getvalue after unlink+close: ret=%d, val=%d *** UAF?", ret, val))

    -- Can we re-open the same name?
    zero_buf(idp, 16)
    ok, rv = pcall(function() return sc_ksem_open(idp, name1, uint64(0x200), uint64(0x1FF), uint64(99)) end)
    local r2 = ok and N(rv) or -999
    local id2 = rd(N(idp))
    print(string.format("  reopen after unlink: ret=%d, id=0x%X", r2, id2 or 0))
    if r2 == 0 and id2 and id2 > 0 then
        ret, val = ksem_getval(id2)
        print(string.format("    new getvalue: ret=%d, val=%d (should be 99 if fresh)", ret, val))
        pcall(function() sc_ksem_close(uint64(id2)) end)
    end
else
    print("  ksem_open not available")
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] Post + trywait cycle (correctness check)
-- ===================================================================
print("[D] post + trywait cycle")

ret, sid = ksem_create(0)
print(string.format("  create(val=0): ret=%d, id=0x%X", ret, sid))

-- trywait on 0 should fail
ok, rv = pcall(function() return sc_ksem_trywait(uint64(sid)) end)
print("  trywait on 0: ret=" .. (ok and N(rv) or -999) .. " (expect -1)")

-- post 3 times
for i = 1, 3 do
    pcall(function() sc_ksem_post(uint64(sid)) end)
end
ret, val = ksem_getval(sid)
print(string.format("  after 3x post: val=%d (expect 3)", val))

-- trywait 2 times
for i = 1, 2 do
    pcall(function() sc_ksem_trywait(uint64(sid)) end)
end
ret, val = ksem_getval(sid)
print(string.format("  after 2x trywait: val=%d (expect 1)", val))

-- post 1 more
pcall(function() sc_ksem_post(uint64(sid)) end)
ret, val = ksem_getval(sid)
print(string.format("  after 1x post: val=%d (expect 2)", val))

pcall(function() sc_close(uint64(sid)) end)

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] Named sem full lifecycle: open, post, unlink, close — UAF window
-- ===================================================================
print("[E] named sem lifecycle + UAF window")

local name2 = make_name("/uaf_test")
zero_buf(idp, 16)
ok, rv = pcall(function() return sc_ksem_open(idp, name2, uint64(0x200), uint64(0x1FF), uint64(1)) end)
local e_ret = ok and N(rv) or -999
local e_id1 = rd(N(idp))
print(string.format("  open #1: ret=%d, id=0x%X", e_ret, e_id1 or 0))

if e_ret == 0 and e_id1 and e_id1 > 0 then
    -- Open a second handle to same name
    zero_buf(idp, 16)
    ok, rv = pcall(function() return sc_ksem_open(idp, name2, uint64(0), uint64(0), uint64(0)) end)
    local e_id2 = rd(N(idp))
    print(string.format("  open #2 (same name): ret=%d, id=0x%X", ok and N(rv) or -999, e_id2 or 0))

    -- Post via handle 1
    pcall(function() sc_ksem_post(uint64(e_id1)) end)
    ret, val = ksem_getval(e_id1)
    print(string.format("  getvalue via #1 after post: val=%d (expect 2)", val))

    -- Getvalue via handle 2 — should see same value
    ret, val = ksem_getval(e_id2)
    print(string.format("  getvalue via #2 (shared?): val=%d (expect 2)", val))

    -- Unlink the name
    ok, rv = pcall(function() return sc_ksem_unlink(name2) end)
    print("  unlink: ret=" .. (ok and N(rv) or -999))

    -- Close handle 1
    ok, rv = pcall(function() return sc_ksem_close(uint64(e_id1)) end)
    print("  close #1: ret=" .. (ok and N(rv) or -999))

    -- Handle 2 should still work (last ref keeps object alive)
    ret, val = ksem_getval(e_id2)
    print(string.format("  getvalue via #2 after close #1: ret=%d, val=%d", ret, val))

    -- Close handle 2 — should trigger final destroy
    ok, rv = pcall(function() return sc_ksem_close(uint64(e_id2)) end)
    print("  close #2 (final): ret=" .. (ok and N(rv) or -999))

    -- Both should be dead now
    ret, val = ksem_getval(e_id1)
    print(string.format("  getvalue #1 after both closed: ret=%d ***", ret))
    ret, val = ksem_getval(e_id2)
    print(string.format("  getvalue #2 after both closed: ret=%d ***", ret))
end

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] ID reuse via destroy(408) vs close(6) on unnamed
-- ===================================================================
print("[F] ID reuse: destroy(408) vs close(6)")

-- Create 3 sems, note their IDs
local ids = {}
for i = 1, 3 do
    local r, id = ksem_create(1)
    if r == 0 then ids[#ids + 1] = id end
end
local s = {}
for _, id in ipairs(ids) do s[#s + 1] = string.format("0x%X", id) end
print("  created: " .. table.concat(s, ", "))

-- Destroy middle one via ksem_destroy(408)
if #ids >= 3 then
    local mid = ids[2]
    ok, rv = pcall(function() return sc_ksem_destroy(uint64(mid)) end)
    print(string.format("  destroy(408) id 0x%X: ret=%d", mid, ok and N(rv) or -999))

    -- Create new — does it reuse the ID?
    local r, new_id = ksem_create(1)
    print(string.format("  new after destroy: ret=%d, id=0x%X (reuse=%s)", r, new_id, tostring(new_id == mid)))

    -- Clean up with close(6)
    pcall(function() sc_close(uint64(ids[1])) end)
    pcall(function() sc_close(uint64(ids[3])) end)
    if new_id ~= mid then pcall(function() sc_close(uint64(new_id)) end) end
    -- If destroy freed mid, close it would fail, which is fine
    pcall(function() sc_close(uint64(mid)) end)
end

if not alive() then print("DEAD after [F]"); return end
print("")

-- ===================================================================
-- [G] Summary
-- ===================================================================
print("[G] SUMMARY")
print("  Syscall mapping: 401=post, 402=wait, 406=unlink, 408=destroy")
print("  ksem_post(401): tested above")
print("  ksem_destroy(408): tested above")
print("  ksem_unlink(406): tested above")
print("  Named sem shared state: tested above")
print("  ID reuse pattern: tested above")

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 388c COMPLETE ===")
