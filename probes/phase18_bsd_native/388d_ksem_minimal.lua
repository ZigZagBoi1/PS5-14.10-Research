-- CRASH_CLASS: LOW
-- PROBE 388d: ksem minimal — verify syscall numbers
--
-- Context: 388c got ret=-1 from ksem_init(404), possibly exhausted
-- system-wide semaphore pool. This probe is minimal: just verify
-- the correct post/wait/destroy/unlink numbers with one semaphore.

print("=== PROBE 388d: ksem minimal ===")
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

local sc_init     = mk(404)
local sc_getval   = mk(407)
local sc_close    = mk(6)
local idp = memory.alloc(16)
local val_buf = memory.alloc(16)

-- Step 0: Try creating one sem to see if pool is available
print("[0] pool check")
zero_buf(idp, 16)
local ok, rv = pcall(function() return sc_init(idp, uint64(1)) end)
local ret = ok and N(rv) or -999
local sid = rd(N(idp))
print(string.format("  init(val=1): ret=%d, id=0x%X", ret, sid or 0))

if ret ~= 0 then
    print("  POOL EXHAUSTED — trying to find and close leaked sems")
    -- Try closing fd range that might be leaked ksem handles
    -- Previous probes created sems with IDs in 0x17-0x34 range
    local freed = 0
    for fd = 0x17, 0x40 do
        ok, rv = pcall(function() return sc_close(uint64(fd)) end)
        if ok and N(rv) == 0 then freed = freed + 1 end
    end
    print("  freed " .. freed .. " fds in range 0x17-0x40")

    -- Retry
    zero_buf(idp, 16)
    ok, rv = pcall(function() return sc_init(idp, uint64(1)) end)
    ret = ok and N(rv) or -999
    sid = rd(N(idp))
    print(string.format("  retry init: ret=%d, id=0x%X", ret, sid or 0))
    if ret ~= 0 then
        print("  STILL EXHAUSTED — need loader restart")
        print("canary=" .. (alive() and "OK" or "FAIL"))
        return
    end
end

print(string.format("  working sem: id=0x%X", sid))
print("")

-- Step 1: Test each candidate for "post" (increment)
print("[1] which syscall is post? (test 401 and 402)")

-- Get initial value
zero_buf(val_buf, 16)
pcall(function() sc_getval(uint64(sid), val_buf) end)
local v0 = rd(N(val_buf))
print(string.format("  initial value: %d", v0))

-- Test 401
local sc401 = mk(401)
ok, rv = pcall(function() return sc401(uint64(sid)) end)
print("  call 401(sid): ret=" .. (ok and N(rv) or -999))
zero_buf(val_buf, 16)
pcall(function() sc_getval(uint64(sid), val_buf) end)
local v1 = rd(N(val_buf))
print(string.format("  value after 401: %d (delta=%d)", v1, v1 - v0))

-- Test 402
local sc402 = mk(402)
-- WARNING: if 402 is wait and value=0, it will BLOCK forever!
-- Only call if value > 0
if v1 > 0 then
    ok, rv = pcall(function() return sc402(uint64(sid)) end)
    print("  call 402(sid): ret=" .. (ok and N(rv) or -999))
    zero_buf(val_buf, 16)
    pcall(function() sc_getval(uint64(sid), val_buf) end)
    local v2 = rd(N(val_buf))
    print(string.format("  value after 402: %d (delta=%d)", v2, v2 - v1))
else
    print("  SKIP 402 (value=0, would block)")
end

-- Test 403 (trywait — should decrement without blocking)
zero_buf(val_buf, 16)
pcall(function() sc_getval(uint64(sid), val_buf) end)
local v_before = rd(N(val_buf))
local sc403 = mk(403)
ok, rv = pcall(function() return sc403(uint64(sid)) end)
local tw_ret = ok and N(rv) or -999
zero_buf(val_buf, 16)
pcall(function() sc_getval(uint64(sid), val_buf) end)
local v_after = rd(N(val_buf))
print(string.format("  call 403(sid): ret=%d, value %d->%d (delta=%d)", tw_ret, v_before, v_after, v_after - v_before))

if not alive() then print("DEAD after [1]"); return end
print("")

-- Step 2: Test destroy(408) vs unlink(406) on unnamed
print("[2] destroy vs unlink on unnamed")

-- Create a fresh one
zero_buf(idp, 16)
ok, rv = pcall(function() return sc_init(idp, uint64(1)) end)
ret = ok and N(rv) or -999
local sid2 = rd(N(idp))
print(string.format("  new sem: ret=%d, id=0x%X", ret, sid2 or 0))

if ret == 0 then
    -- Test 408 (FreeBSD ksem_destroy)
    local sc408 = mk(408)
    ok, rv = pcall(function() return sc408(uint64(sid2)) end)
    print("  408(destroy?) on unnamed: ret=" .. (ok and N(rv) or -999))
    zero_buf(val_buf, 16)
    pcall(function() sc_getval(uint64(sid2), val_buf) end)
    local v = rd(N(val_buf))
    print(string.format("  getvalue after 408: ret check, val=%d", v))

    -- Test 406 on another unnamed
    zero_buf(idp, 16)
    ok, rv = pcall(function() return sc_init(idp, uint64(1)) end)
    ret = ok and N(rv) or -999
    local sid3 = rd(N(idp))
    if ret == 0 then
        local sc406 = mk(406)
        ok, rv = pcall(function() return sc406(uint64(sid3)) end)
        print(string.format("  406(unlink?) on unnamed 0x%X: ret=%d", sid3, ok and N(rv) or -999))
        -- cleanup
        pcall(function() sc_close(uint64(sid3)) end)
    end
end

if not alive() then print("DEAD after [2]"); return end
print("")

-- Step 3: Named sem with correct unlink
print("[3] named sem lifecycle with correct unlink")

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

local sc_open = mk(405)
local sc_close400 = mk(400)

local name = make_name("/d388")
zero_buf(idp, 16)
ok, rv = pcall(function() return sc_open(idp, name, uint64(0x200), uint64(0x1FF), uint64(1)) end)
ret = ok and N(rv) or -999
local nid = rd(N(idp))
print(string.format("  open('/d388'): ret=%d, id=0x%X", ret, nid or 0))

if ret == 0 and nid and nid > 0 then
    -- unlink with 406
    local sc406 = mk(406)
    ok, rv = pcall(function() return sc406(name) end)
    print("  406(name) unlink: ret=" .. (ok and N(rv) or -999))

    -- unlink with 408
    local sc408 = mk(408)
    ok, rv = pcall(function() return sc408(name) end)
    print("  408(name) destroy?: ret=" .. (ok and N(rv) or -999))

    -- Still usable?
    zero_buf(val_buf, 16)
    pcall(function() sc_getval(uint64(nid), val_buf) end)
    local v = rd(N(val_buf))
    print(string.format("  getvalue: val=%d", v))

    -- Close
    ok, rv = pcall(function() return sc_close400(uint64(nid)) end)
    print("  close(400): ret=" .. (ok and N(rv) or -999))
end

-- Cleanup first sem
pcall(function() sc_close(uint64(sid)) end)

if not alive() then print("DEAD after [3]"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 388d COMPLETE ===")
