-- CRASH_CLASS: LOW
-- PROBE 557c: AIO table capacity diagnostic
--
-- 557b revealed: adding 64 entries to 16 existing = corruption (state 0x1).
-- All "swaps" from 540c might be table overflow, not type confusion.
--
-- Test: submit increasing batch sizes, check state after each.
-- Find the exact capacity threshold where corruption starts.
-- Also test: different sc670 init args (maybe first arg = capacity).

print("=== PROBE 557c: AIO CAPACITY DIAGNOSTIC ===")
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
local function zero(b, n) for off = 0, n - 4, 4 do wd(b + off, 0) end end
local function write_string(buf, s)
    for i = 1, #s, 4 do
        local b0 = string.byte(s, i) or 0
        local b1 = string.byte(s, i+1) or 0
        local b2 = string.byte(s, i+2) or 0
        local b3 = string.byte(s, i+3) or 0
        wd(buf + (i - 1), b0 + b1 * 256 + b2 * 65536 + b3 * 16777216)
    end
end

local Z = uint64(0)
local sc5   = mk(5)
local sc20  = mk(20)
local sc240 = mk(240)
local sc477 = mk(477)
local sc662 = mk(662)
local sc664 = mk(664)
local sc669 = mk(669)
local sc670 = mk(670)

local pid = N(sc20())
print("pid=" .. pid)

-- Open /dev/urandom
local urand_path = memory.alloc(16)
write_string(urand_path, "/dev/urandom\0")
local ok_u, urand_fd = pcall(function() return sc5(uint64(N(urand_path)), Z, Z) end)
urand_fd = ok_u and N(urand_fd) or -1
print("urandom=" .. urand_fd)

-- Helpers
local reqs_buf = memory.alloc(0x30)
local ids_out  = memory.alloc(8)
local ts_buf   = memory.alloc(16)

local function aio_submit(fd)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(N(memory.alloc(32))))
    wq(reqs_buf + 0x18, uint64(N(memory.alloc(16))))
    wd(reqs_buf + 0x20, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(1), uint64(N(reqs_buf)), uint64(1), uint64(1), uint64(N(ids_out)))
    end)
    return (ok and N(rv) or -999), (rd(ids_out) or 0)
end

local function aio_poll(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc664(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function aio_delete(id)
    local ip = memory.alloc(4); wd(ip, id)
    local sp = memory.alloc(4); wd(sp, 0x77777777)
    pcall(function() sc662(uint64(N(ip)), uint64(1), uint64(N(sp))) end)
    return rd(sp) or 0
end

local function sleep_ms(ms)
    wq(uint64(N(ts_buf)), Z)
    wq(uint64(N(ts_buf) + 8), uint64(ms * 1000000))
    pcall(function() sc240(uint64(N(ts_buf)), Z) end)
end

-- ============================================================
-- PHASE 1: AIO init with default args, find capacity
-- ============================================================
print("")
print("=== PHASE 1: Default init (all zeros) ===")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

local function test_batch(size, label)
    local ids = {}
    local created = 0
    local submit_fails = 0
    for i = 1, size do
        local rv, id = aio_submit(urand_fd)
        if rv == 0 and id > 0 then
            created = created + 1
            ids[created] = id
        else
            submit_fails = submit_fails + 1
        end
    end

    sleep_ms(200)

    -- Check states
    local states = {}
    for i = 1, created do
        local st = aio_poll(ids[i])
        local key = string.format("0x%X", st)
        states[key] = (states[key] or 0) + 1
    end

    -- Delete all
    local del_ok = 0
    local del_fail = 0
    for i = 1, created do
        local dst = aio_delete(ids[i])
        if dst == 0 then del_ok = del_ok + 1
        else del_fail = del_fail + 1 end
    end

    local state_str = ""
    for k, v in pairs(states) do state_str = state_str .. k .. "x" .. v .. " " end

    print(string.format("  %s: created=%d sfail=%d states=[%s] del(ok=%d fail=%d)",
        label, created, submit_fails, state_str, del_ok, del_fail))

    return del_ok == created
end

-- Test increasing sizes
local healthy = true
for _, size in ipairs({4, 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 128}) do
    if not healthy then
        print(string.format("  batch=%d: SKIP (system already corrupted)", size))
    else
        healthy = test_batch(size, string.format("batch=%d", size))
        if not healthy then
            print("  *** CORRUPTION THRESHOLD FOUND ***")
        end
    end
end

-- ============================================================
-- PHASE 2: Try AIO init with different first args
-- ============================================================
print("")
print("=== PHASE 2: Init arg variations ===")

-- Try different init args. First arg might be module ID or capacity.
-- Be conservative — only test values that look safe.
local init_args = {
    {0x1001, "0x1001 (module handle?)"},
    {1, "1"},
    {128, "128 (capacity hint?)"},
    {256, "256"},
    {0x100, "0x100"},
}

for _, entry in ipairs(init_args) do
    local arg = entry[1]
    local label = entry[2]
    local ok_init, rv_init = pcall(function()
        return sc670(uint64(arg), Z, Z, Z, Z, Z)
    end)
    local irv = ok_init and N(rv_init) or -999
    print(string.format("  init(%s) → rv=%d", label, irv))

    if irv == 0 then
        -- Test a batch
        local good = test_batch(64, "  post-init-64")
        if good then
            print("  *** LARGER CAPACITY WITH THIS ARG ***")
            test_batch(128, "  post-init-128")
        end
    end
end

-- ============================================================
-- PHASE 3: Submit with module handle 1 (instead of 0x1001)
-- ============================================================
print("")
print("=== PHASE 3: Submit handle variations ===")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

-- Try submit with handle=1 instead of 0x1001
local function aio_submit_h(fd, handle)
    zero(reqs_buf, 0x28)
    wq(reqs_buf + 0x08, uint64(16))
    wq(reqs_buf + 0x10, uint64(N(memory.alloc(32))))
    wq(reqs_buf + 0x18, uint64(N(memory.alloc(16))))
    wd(reqs_buf + 0x20, fd)
    wd(ids_out, 0)
    local ok, rv = pcall(function()
        return sc669(uint64(handle), uint64(N(reqs_buf)), uint64(1), uint64(1), uint64(N(ids_out)))
    end)
    return (ok and N(rv) or -999), (rd(ids_out) or 0)
end

for _, h in ipairs({0, 1, 0x1001, 0x1002}) do
    local rv, id = aio_submit_h(urand_fd, h)
    print(string.format("  submit(handle=0x%X) → rv=%d id=0x%X", h, rv, id))
    if rv == 0 and id > 0 then
        sleep_ms(100)
        local st = aio_poll(id)
        local ds = aio_delete(id)
        print(string.format("    poll=0x%X del=0x%X", st, ds))
    end
end

-- ============================================================
-- PHASE 4: Sequential submit-poll-delete (no accumulation)
-- ============================================================
print("")
print("=== PHASE 4: 100 sequential submit-poll-delete ===")
pcall(function() sc670(Z, Z, Z, Z, Z, Z) end)

local seq_ok = 0
local seq_fail = 0
for i = 1, 100 do
    local rv, id = aio_submit(urand_fd)
    if rv == 0 and id > 0 then
        sleep_ms(10)
        local st = aio_poll(id)
        local ds = aio_delete(id)
        if st >= 3 and ds == 0 then
            seq_ok = seq_ok + 1
        else
            seq_fail = seq_fail + 1
            if seq_fail <= 3 then
                print(string.format("  [%d] FAIL: poll=0x%X del=0x%X", i, st, ds))
            end
        end
    else
        seq_fail = seq_fail + 1
    end
end
print(string.format("  ok=%d fail=%d", seq_ok, seq_fail))

-- Final health
print("")
local pid2 = N(sc20())
print("pid=" .. pid2 .. (pid2 == pid and " OK" or " CHANGED"))
print("=== 557c DONE ===")
