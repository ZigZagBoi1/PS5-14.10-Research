-- CRASH_CLASS: MODERATE
-- PROBE 153c: Targeted UMTX tests — skip blocking ops
--
-- Context: 153b blocked at CV_BROADCAST (15).
-- Known safe: WAKE(3)=0, CV_SIGNAL(14)=-1, NWAKE_PRIV(21)=0
-- Skip: CV_BROADCAST(15), SEM2_WAIT(20), LOCK(0), WAIT(2)

print("=== PROBE 153c: UMTX TARGETED ===")
print("")

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
local function rv_str(ok, ret)
    if not ok then return "CRASH" end
    local h, l = get_hi_lo(ret)
    if h == 0xFFFFFFFF then return "-1" end
    if h == 0 then return tostring(l) end
    return string.format("0x%X%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

-- ============================================================
-- SECTION A: Quick confirmed ops
-- ============================================================
print("")
print("--- SECTION A: KNOWN SAFE OPS ---")

-- NWAKE_PRIVATE (21) — confirmed 56i2
local nw = memory.alloc(0x40)
memory.write_qword(nw, uint64(0))
local ok21, r21 = pcall(function()
    return sc_umtx(uint64(to_num(nw)), uint64(21), uint64(1), uint64(0), uint64(0))
end)
print("NWAKE_PRIV(21): " .. rv_str(ok21, r21))

-- MUTEX_WAKE2 (22)
local mw2 = memory.alloc(0x40)
memory.write_qword(mw2, uint64(0))
local ok22, r22 = pcall(function()
    return sc_umtx(uint64(to_num(mw2)), uint64(22), uint64(0), uint64(0), uint64(0))
end)
print("MUTEX_WAKE2(22): " .. rv_str(ok22, r22))

-- SEM2_WAKE (23)
local sw = memory.alloc(0x40)
memory.write_qword(sw, uint64(0))
local ok23, r23 = pcall(function()
    return sc_umtx(uint64(to_num(sw)), uint64(23), uint64(1), uint64(0), uint64(0))
end)
print("SEM2_WAKE(23): " .. rv_str(ok23, r23))

-- ============================================================
-- SECTION B: MUTEX LOCK(10) / UNLOCK(11) / TRYLOCK(4)
-- ============================================================
print("")
print("--- SECTION B: MUTEX OPS ---")

-- MUTEX_TRYLOCK (4) — non-blocking, should succeed on zeroed word
local mtry = memory.alloc(0x40)
memory.write_qword(mtry, uint64(0))
print("pre_trylock word: 0")
local ok4, r4 = pcall(function()
    return sc_umtx(uint64(to_num(mtry)), uint64(4), uint64(0), uint64(0), uint64(0))
end)
local t4h, t4l = get_hi_lo(memory.read_qword(mtry))
print(string.format("TRYLOCK(4): ret=%s word=0x%08X_%08X", rv_str(ok4, r4), t4h, t4l))

-- MUTEX_LOCK (10) — may block if word is locked
-- Use a fresh zeroed word — should acquire immediately
local ml = memory.alloc(0x40)
memory.write_qword(ml, uint64(0))
print("pre_lock word: 0")
local ok10, r10 = pcall(function()
    return sc_umtx(uint64(to_num(ml)), uint64(10), uint64(0), uint64(0), uint64(0))
end)
local m10h, m10l = get_hi_lo(memory.read_qword(ml))
print(string.format("MUTEX_LOCK(10): ret=%s word=0x%08X_%08X", rv_str(ok10, r10), m10h, m10l))

-- MUTEX_UNLOCK (11)
if ok10 and to_num(r10) == 0 then
    local ok11, r11 = pcall(function()
        return sc_umtx(uint64(to_num(ml)), uint64(11), uint64(0), uint64(0), uint64(0))
    end)
    local m11h, m11l = get_hi_lo(memory.read_qword(ml))
    print(string.format("MUTEX_UNLOCK(11): ret=%s word=0x%08X_%08X", rv_str(ok11, r11), m11h, m11l))
end

-- ============================================================
-- SECTION C: UNLOCK(1) — old-style unlock
-- ============================================================
print("")
print("--- SECTION C: OLD UNLOCK ---")

local ou = memory.alloc(0x40)
memory.write_qword(ou, uint64(0))
local ok1, r1 = pcall(function()
    return sc_umtx(uint64(to_num(ou)), uint64(1), uint64(0), uint64(0), uint64(0))
end)
print("UNLOCK(1): " .. rv_str(ok1, r1))

-- ============================================================
-- SECTION D: RW LOCK/UNLOCK
-- ============================================================
print("")
print("--- SECTION D: RW LOCKS ---")

-- RW_RDLOCK (17) — read lock on zeroed word should succeed
local rr = memory.alloc(0x40)
memory.write_qword(rr, uint64(0))
local ok17, r17 = pcall(function()
    return sc_umtx(uint64(to_num(rr)), uint64(17), uint64(0), uint64(0), uint64(0))
end)
local r17h, r17l = get_hi_lo(memory.read_qword(rr))
print(string.format("RW_RDLOCK(17): ret=%s word=0x%08X_%08X", rv_str(ok17, r17), r17h, r17l))

-- RW_UNLOCK (19)
if ok17 and to_num(r17) == 0 then
    local ok19, r19 = pcall(function()
        return sc_umtx(uint64(to_num(rr)), uint64(19), uint64(0), uint64(0), uint64(0))
    end)
    local r19h, r19l = get_hi_lo(memory.read_qword(rr))
    print(string.format("RW_UNLOCK(19): ret=%s word=0x%08X_%08X", rv_str(ok19, r19), r19h, r19l))
end

-- RW_WRLOCK (18) — write lock on zeroed word
local rw = memory.alloc(0x40)
memory.write_qword(rw, uint64(0))
local ok18, r18 = pcall(function()
    return sc_umtx(uint64(to_num(rw)), uint64(18), uint64(0), uint64(0), uint64(0))
end)
local r18h, r18l = get_hi_lo(memory.read_qword(rw))
print(string.format("RW_WRLOCK(18): ret=%s word=0x%08X_%08X", rv_str(ok18, r18), r18h, r18l))

-- ============================================================
-- SECTION E: WAIT_UINT(16) — mismatch test
-- ============================================================
print("")
print("--- SECTION E: WAIT_UINT ---")

local wu = memory.alloc(64)
memory.write_dword(wu, 42)
local ok16, r16 = pcall(function()
    return sc_umtx(uint64(to_num(wu)), uint64(16), uint64(99), uint64(0), uint64(0))
end)
print("WAIT_UINT(16 mismatch): " .. rv_str(ok16, r16))

-- WAIT(2) — mismatch
local w2 = memory.alloc(64)
memory.write_dword(w2, 42)
local ok2, r2 = pcall(function()
    return sc_umtx(uint64(to_num(w2)), uint64(2), uint64(99), uint64(0), uint64(0))
end)
print("WAIT(2 mismatch): " .. rv_str(ok2, r2))

-- ============================================================
-- SECTION F: SET_CEILING (12)
-- ============================================================
print("")
print("--- SECTION F: SET_CEILING ---")

local sc = memory.alloc(0x40)
memory.write_qword(sc, uint64(0))
local ok12, r12 = pcall(function()
    return sc_umtx(uint64(to_num(sc)), uint64(12), uint64(5), uint64(0), uint64(0))
end)
local s12h, s12l = get_hi_lo(memory.read_qword(sc))
print(string.format("SET_CEILING(12): ret=%s word=0x%08X_%08X", rv_str(ok12, r12), s12h, s12l))

-- ============================================================
-- SECTION G: ROBUST_LISTS (26)
-- ============================================================
print("")
print("--- SECTION G: ROBUST_LISTS ---")

local rp = memory.alloc(0x40)
memory.write_qword(rp, uint64(0))
memory.write_qword(rp + 8, uint64(0))
memory.write_qword(rp + 16, uint64(0))

-- size=24 (correct)
local ok26a, r26a = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(24), uint64(to_num(rp)), uint64(0))
end)
print("ROBUST(size=24): " .. rv_str(ok26a, r26a))

-- size=0 (invalid)
local ok26b, r26b = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(0), uint64(to_num(rp)), uint64(0))
end)
print("ROBUST(size=0): " .. rv_str(ok26b, r26b))

-- size=32 (oversized)
local ok26c, r26c = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(32), uint64(to_num(rp)), uint64(0))
end)
print("ROBUST(size=32): " .. rv_str(ok26c, r26c))

-- ============================================================
-- SECTION H: Summary of op matrix so far
-- ============================================================
print("")
print("--- SECTION H: MATRIX ---")
print("op00 LOCK:         SKIP (may block)")
print("op01 UNLOCK:       " .. rv_str(ok1, r1))
print("op02 WAIT:         " .. rv_str(ok2, r2) .. " (mismatch)")
print("op03 WAKE:         0 (from 153b)")
print("op04 TRYLOCK:      " .. rv_str(ok4, r4))
print("op05 MUTEX_WAIT:   SKIP (may block)")
print("op10 MUTEX_LOCK:   " .. rv_str(ok10, r10))
print("op11 MUTEX_UNLOCK: tested above")
print("op12 SET_CEILING:  " .. rv_str(ok12, r12))
print("op14 CV_SIGNAL:    -1 (from 153b)")
print("op15 CV_BROADCAST: SKIP (blocks)")
print("op16 WAIT_UINT:    " .. rv_str(ok16, r16))
print("op17 RW_RDLOCK:    " .. rv_str(ok17, r17))
print("op18 RW_WRLOCK:    " .. rv_str(ok18, r18))
print("op19 RW_UNLOCK:    tested above")
print("op21 NWAKE_PRIV:   " .. rv_str(ok21, r21))
print("op22 MUTEX_WAKE2:  " .. rv_str(ok22, r22))
print("op23 SEM2_WAKE:    " .. rv_str(ok23, r23))
print("op25 SHM:          0 (stub)")
print("op26 ROBUST:       " .. rv_str(ok26a, r26a))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 153c COMPLETE ===")
