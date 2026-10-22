-- CRASH_CLASS: LOW
-- PROBE 110a: _umtx_op(454) reachability — SHM and ROBUST_LISTS were never exercised
--
-- Context: the phase-1/2 "umtx" probes (04/10/11/12/13) and prepared probe 82a bound
-- sc_umtx_op to syscall 557, but the 13.60 capture labels 557 as namedobj_create and
-- 454 as _umtx_op (see docs/UMTX_454_EVIDENCE.md). The only saved 454 executions are
-- 56i2's [F] section: op 5 (MUTEX_LOCK) ret=0 with a TID-shaped owner writeback, and
-- op 21 (NWAKE_PRIVATE) ret=0. UMTX_OP_SHM(25) and UMTX_OP_ROBUST_LISTS(26) have never
-- run against 454, and FreeBSD 11 reads their key/params pointer from uaddr1 (4th
-- positional arg), a layout the earlier probes did not use.
--
-- This probe issues the missing calls with FreeBSD 11 argument layouts:
--   A: benign wake ops (WAKE 3, NWAKE_PRIVATE 21) — dispatch control
--   B: mutex lock(5)/unlock(6) round trips with owner readback + MUTEX_WAKE2(22)
--      plus a same-shape op-5 call against syscall 557 as a negative control
--   C: UMTX_OP_SHM(25) — key in uaddr1: create/lookup/alive/destroy/destroy/lookup,
--      50-round create+destroy churn, 10 create-without-destroy rounds
--   D: UMTX_OP_ROBUST_LISTS(26) — 24-byte params in uaddr1: correct, oversized(32),
--      zero-size
--   E: final canary
--
-- Every call is pcall'd; all syscall arguments are uint64() values; every return is
-- printed. No behaviour is claimed before a run is captured.

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function q(v)
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end
local function fmt_ret(rv)
    if rv == nil then return "nil" end
    return tostring(to_num(rv)) .. " (" .. q(rv) .. ")"
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do safe_wd(buf + off, 0) end
end

print("=== PROBE 110a: _umtx_op(454) SHM / ROBUST_LISTS REACHABILITY ===")
print("")

-- _umtx_op(obj, op, val, uaddr1, uaddr2 [, extra]) — six positional uint64 args,
-- matching the 56i2 call shape that returned ret=0.
local sc_umtx = make_syscall(454)
local sc_557  = make_syscall(557)  -- negative control only
local sc_pid  = make_syscall(20)

local function umtx_op(obj, op, val, uaddr1, uaddr2)
    local ok, rv = pcall(function()
        return sc_umtx(uint64(obj), uint64(op), uint64(val),
            uint64(uaddr1 or 0), uint64(uaddr2 or 0), uint64(0))
    end)
    if ok then return true, rv end
    return false, nil
end

-- UMTX op numbers (FreeBSD sys/umtx.h)
local OP_WAKE           = 3
local OP_MUTEX_LOCK     = 5
local OP_MUTEX_UNLOCK   = 6
local OP_NWAKE_PRIVATE  = 21
local OP_MUTEX_WAKE2    = 22
local OP_SHM            = 25
local OP_ROBUST_LISTS   = 26

-- UMTX_SHM flag words (FreeBSD sys/umtx.h)
local SHM_CREAT   = 0x0001
local SHM_LOOKUP  = 0x0002
local SHM_DESTROY = 0x0004
local SHM_ALIVE   = 0x0008

-- ============================================================
-- [0] Canary
-- ============================================================
local pid = -1
pcall(function() pid = to_num(sc_pid()) end)
print("[0] canary pid=" .. tostring(pid))
print("")

-- ============================================================
-- [A] Benign wake ops — dispatch control on 454
-- ============================================================
print("[A] benign wake ops")
do
    local word = memory.alloc(0x10)
    zero(word, 0x10)
    local ok, rv = umtx_op(word, OP_WAKE, 1, 0, 0)
    print("  WAKE(3) count=1: ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))

    local arr = memory.alloc(0x20)
    zero(arr, 0x20)
    ok, rv = umtx_op(arr, OP_NWAKE_PRIVATE, 2, 0, 0)
    print("  NWAKE_PRIVATE(21) count=2: ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))
end
print("")

-- ============================================================
-- [B] Mutex lock/unlock lifecycle + syscall 557 negative control
-- ============================================================
print("[B] mutex lifecycle on 454")
do
    for round = 1, 3 do
        local m = memory.alloc(0x40)
        zero(m, 0x40)
        local ok, rv = umtx_op(m, OP_MUTEX_LOCK, 0, 0, 0)
        local owner = safe_rd(m)
        print("  round " .. round .. " LOCK(5): ok=" .. tostring(ok) ..
            " rv=" .. fmt_ret(rv) .. " owner_word=" ..
            (owner == nil and "nil" or string.format("0x%08X", owner)))
        ok, rv = umtx_op(m, OP_MUTEX_UNLOCK, 0, 0, 0)
        owner = safe_rd(m)
        print("  round " .. round .. " UNLOCK(6): ok=" .. tostring(ok) ..
            " rv=" .. fmt_ret(rv) .. " owner_word=" ..
            (owner == nil and "nil" or string.format("0x%08X", owner)))
    end

    local m = memory.alloc(0x40)
    zero(m, 0x40)
    local ok, rv = umtx_op(m, OP_MUTEX_WAKE2, 0, 0, 0)
    print("  MUTEX_WAKE2(22): ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))

    -- Negative control: identical call shape against syscall 557 (namedobj_create
    -- in the 13.60 capture). Phase-2 probes called 557 this way ~500 times without
    -- a crash. If 554-vs-454 matters, the owner word should stay 0 here while the
    -- 454 lock above wrote a TID.
    local m2 = memory.alloc(0x40)
    zero(m2, 0x40)
    local ok2, rv2 = pcall(function()
        return sc_557(uint64(m2), uint64(OP_MUTEX_LOCK), uint64(0),
            uint64(0), uint64(0), uint64(0))
    end)
    local owner2 = safe_rd(m2)
    print("  CONTROL 557 op=5 same shape: ok=" .. tostring(ok2) ..
        " rv=" .. fmt_ret(rv2) .. " owner_word=" ..
        (owner2 == nil and "nil" or string.format("0x%08X", owner2)))
end
print("")

-- ============================================================
-- [C] UMTX_OP_SHM(25) — key address in uaddr1, flags in val
-- FreeBSD 11: __umtx_op_shm(td, uap) -> umtx_shm(td, uap->uaddr1, uap->val)
-- ============================================================
print("[C] UMTX_OP_SHM(25), key in uaddr1")
do
    local key_a = memory.alloc(0x100)
    zero(key_a, 0x100)

    local function shm(flags, key)
        return umtx_op(0, OP_SHM, flags, key, 0)
    end

    local ok, rv = shm(SHM_CREAT, key_a)
    print("  CREAT(1): ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv) ..
        " (FreeBSD: rv is a shm fd on success)")
    ok, rv = shm(SHM_LOOKUP, key_a)
    print("  LOOKUP(2): ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))
    local fd = -1
    if ok and rv ~= nil and to_num(rv) >= 0 then fd = to_num(rv) end

    -- UMTX_SHM_ALIVE checks the vm object backing the supplied address
    -- (OBJ_UMTXDEAD), not the key registration. A plain heap key is the
    -- control; the real test maps the CREAT fd and passes that mapping.
    ok, rv = shm(SHM_ALIVE, key_a)
    print("  ALIVE(8) on plain heap key (control): ok=" .. tostring(ok) ..
        " rv=" .. fmt_ret(rv))

    local sc_mmap = make_syscall(477)
    local sc_ftruncate = make_syscall(480)
    local shm_map = nil
    local fd0 = fd
    if fd0 >= 0 then
        local ok_ft, rv_ft = pcall(function()
            return sc_ftruncate(uint64(fd0), uint64(0x4000))
        end)
        print("  ftruncate(fd=" .. fd0 .. ", 0x4000): ok=" .. tostring(ok_ft) ..
            " rv=" .. fmt_ret(rv_ft))
        local ok_mm, rv_mm = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
                uint64(1), uint64(fd0), uint64(0))  -- MAP_SHARED
        end)
        local mnum = ok_mm and to_num(rv_mm) or -1
        if mnum >= 0 and mnum < 0x800000000000 then
            shm_map = rv_mm
            print("  mmap(fd=" .. fd0 .. ") -> " .. q(rv_mm))
            ok, rv = shm(SHM_ALIVE, shm_map)
            print("  ALIVE(8) on the shm mapping: ok=" .. tostring(ok) ..
                " rv=" .. fmt_ret(rv))
        else
            print("  mmap(fd=" .. fd0 .. ") failed: ok=" .. tostring(ok_mm) ..
                " rv=" .. fmt_ret(rv_mm))
        end
    end

    ok, rv = shm(SHM_DESTROY, key_a)
    print("  DESTROY(4): ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))
    if shm_map then
        ok, rv = shm(SHM_ALIVE, shm_map)
        print("  ALIVE(8) on the mapping after DESTROY: ok=" .. tostring(ok) ..
            " rv=" .. fmt_ret(rv) .. " (FreeBSD: ENOTTY once OBJ_UMTXDEAD)")
    end
    ok, rv = shm(SHM_DESTROY, key_a)
    print("  DESTROY(4) again: ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv) ..
        " (FreeBSD: ESRCH when the key is unregistered)")
    ok, rv = shm(SHM_LOOKUP, key_a)
    print("  LOOKUP(2) after dd: ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))

    -- 50-round create+destroy churn on a second key
    local key_b = memory.alloc(0x100)
    zero(key_b, 0x100)
    local created, destroyed, errs = 0, 0, 0
    for i = 1, 50 do
        local okc, rvc = shm(SHM_CREAT, key_b)
        if okc and to_num(rvc) >= 0 then created = created + 1 else errs = errs + 1 end
        local okd, rvd = shm(SHM_DESTROY, key_b)
        if okd and to_num(rvd) >= 0 then destroyed = destroyed + 1 end
    end
    print("  churn 50 rounds: created=" .. created ..
        " destroyed=" .. destroyed .. " create_errs=" .. errs)

    -- 10 create-without-destroy rounds (fd leak by design)
    local key_c = memory.alloc(0x100)
    zero(key_c, 0x100)
    local leaked = 0
    for i = 0, 9 do
        local okl, rvl = shm(SHM_CREAT, key_c + i * 8)
        if okl and to_num(rvl) >= 0 then leaked = leaked + 1 end
    end
    print("  create-no-destroy x10: ok_creates=" .. leaked)
    -- cleanup attempt on the last used key only; the rest is intentional leak
    local okx, rvx = shm(SHM_DESTROY, key_c + 72)
    print("  cleanup destroy(key_c+72): ok=" .. tostring(okx) .. " rv=" .. fmt_ret(rvx))
end
print("")

-- ============================================================
-- [D] UMTX_OP_ROBUST_LISTS(26) — 24-byte params in uaddr1, size in val
-- FreeBSD 11: __umtx_op_robust_lists copies min(val, 24) bytes from uaddr1;
-- val > 24 returns EINVAL before any copyin.
-- ============================================================
print("[D] UMTX_OP_ROBUST_LISTS(26), params in uaddr1")
do
    local params = memory.alloc(0x40)
    zero(params, 0x40)  -- three qwords: robust_list, robust_priv_list, robust_inact (all 0)

    local ok, rv = umtx_op(0, OP_ROBUST_LISTS, 24, params, 0)
    print("  register size=24: ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))
    ok, rv = umtx_op(0, OP_ROBUST_LISTS, 32, params, 0)
    print("  oversized size=32: ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv) ..
        " (FreeBSD 11: EINVAL)")
    ok, rv = umtx_op(0, OP_ROBUST_LISTS, 0, params, 0)
    print("  zero size=0: ok=" .. tostring(ok) .. " rv=" .. fmt_ret(rv))
end
print("")

-- ============================================================
-- [E] Final canary
-- ============================================================
local pid2 = -1
pcall(function() pid2 = to_num(sc_pid()) end)
print("[E] final canary pid=" .. tostring(pid2))
print("")
print("=== PROBE 110a COMPLETE ===")
