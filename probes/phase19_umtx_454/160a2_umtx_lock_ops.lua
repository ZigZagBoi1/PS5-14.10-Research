-- CRASH_CLASS: MODERATE
-- PROBE 160a2: UMTX lock/unlock ops — focused on race-relevant ops
--
-- Context: 160a confirmed wake ops (3,9,10,16,18,20,21) all ret=0.
-- Op 22 (MUTEX_WAKE2) ret=-1. Op 24 (SEM2_WAKE) blocked or killed.
-- Need: MUTEX_LOCK(5)/UNLOCK(6), PI mutex, RW_RDLOCK(12)/WRLOCK(13)/UNLOCK(14),
-- WAIT mismatch, TRYLOCK(4), ROBUST_LISTS(26).

print("=== PROBE 160a2: UMTX LOCK OPS ===")
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
local function rv_str(ok, ret)
    if not ok then return "CRASH" end
    if ret == nil then return "nil" end
    local h, l = get_hi_lo(ret)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return "-1" end
    if h == 0 then return tostring(l) end
    return string.format("0x%X%08X", h, l)
end

collectgarbage("stop")
local sc_umtx = make_syscall(454)
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- ============================================================
-- SECTION A: MUTEX_LOCK(5) + MUTEX_UNLOCK(6) — normal mutex
-- ============================================================
print("")
print("--- A: NORMAL MUTEX ---")

local mtx = memory.alloc(0x40)
zero(mtx, 0x40)

print("[A1] MUTEX_LOCK(5) flags=0...")
local ok5, r5 = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(5), uint64(0), uint64(0), uint64(0))
end)
local own5 = rd(mtx)
local flg5 = rd(mtx + 4)
print("  ret=" .. rv_str(ok5, r5) .. " m_owner=0x" .. string.format("%08X", own5 or 0) ..
    " m_flags=0x" .. string.format("%X", flg5 or 0))

print("[A2] MUTEX_UNLOCK(6)...")
local ok6, r6 = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(6), uint64(0), uint64(0), uint64(0))
end)
local own6 = rd(mtx)
print("  ret=" .. rv_str(ok6, r6) .. " m_owner=0x" .. string.format("%08X", own6 or 0))

-- Second round trip (verify repeatability)
print("[A3] LOCK again...")
local ok5b, r5b = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(5), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok5b, r5b) .. " m_owner=0x" .. string.format("%08X", rd(mtx) or 0))

print("[A4] UNLOCK again...")
local ok6b, r6b = pcall(function()
    return sc_umtx(uint64(to_num(mtx)), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok6b, r6b) .. " m_owner=0x" .. string.format("%08X", rd(mtx) or 0))

-- ============================================================
-- SECTION B: PI MUTEX (m_flags=UMUTEX_PRIO_INHERIT=0x4)
-- ============================================================
print("")
print("--- B: PI MUTEX ---")

local pi = memory.alloc(0x40)
zero(pi, 0x40)
wd(pi + 4, 4)  -- UMUTEX_PRIO_INHERIT

print("[B1] PI LOCK(5)...")
local okpi, rpi = pcall(function()
    return sc_umtx(uint64(to_num(pi)), uint64(5), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okpi, rpi) .. " m_owner=0x" .. string.format("%08X", rd(pi) or 0) ..
    " m_flags=0x" .. string.format("%X", rd(pi + 4) or 0))

print("[B2] PI UNLOCK(6)...")
local okpiu, rpiu = pcall(function()
    return sc_umtx(uint64(to_num(pi)), uint64(6), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okpiu, rpiu) .. " m_owner=0x" .. string.format("%08X", rd(pi) or 0))

-- ============================================================
-- SECTION C: MUTEX_TRYLOCK(4)
-- ============================================================
print("")
print("--- C: MUTEX_TRYLOCK ---")

local mtry = memory.alloc(0x40)
zero(mtry, 0x40)

print("[C1] TRYLOCK(4) on unlocked...")
local ok4, r4 = pcall(function()
    return sc_umtx(uint64(to_num(mtry)), uint64(4), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok4, r4) .. " m_owner=0x" .. string.format("%08X", rd(mtry) or 0))

-- Trylock on already-locked (by us)
print("[C2] TRYLOCK(4) on locked (should fail)...")
local ok4b, r4b = pcall(function()
    return sc_umtx(uint64(to_num(mtry)), uint64(4), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok4b, r4b))

-- Unlock
pcall(function() sc_umtx(uint64(to_num(mtry)), uint64(6), uint64(0), uint64(0), uint64(0)) end)

-- ============================================================
-- SECTION D: RW LOCKS
-- ============================================================
print("")
print("--- D: RW LOCKS ---")

-- RW_RDLOCK(12) — read lock, should be non-blocking on uncontested
local rwl = memory.alloc(0x40)
zero(rwl, 0x40)

print("[D1] RW_RDLOCK(12)...")
local ok12, r12 = pcall(function()
    return sc_umtx(uint64(to_num(rwl)), uint64(12), uint64(0), uint64(0), uint64(0))
end)
local rw_state = rd(rwl)
print("  ret=" .. rv_str(ok12, r12) .. " rw_state=0x" .. string.format("%08X", rw_state or 0))

-- RW_UNLOCK(14)
print("[D2] RW_UNLOCK(14)...")
local ok14, r14 = pcall(function()
    return sc_umtx(uint64(to_num(rwl)), uint64(14), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok14, r14) .. " rw_state=0x" .. string.format("%08X", rd(rwl) or 0))

-- RW_WRLOCK(13) — write lock
local rwl2 = memory.alloc(0x40)
zero(rwl2, 0x40)

print("[D3] RW_WRLOCK(13)...")
local ok13, r13 = pcall(function()
    return sc_umtx(uint64(to_num(rwl2)), uint64(13), uint64(0), uint64(0), uint64(0))
end)
local rw_state2 = rd(rwl2)
print("  ret=" .. rv_str(ok13, r13) .. " rw_state=0x" .. string.format("%08X", rw_state2 or 0))

-- RW_UNLOCK(14) after write lock
print("[D4] RW_UNLOCK(14) after wrlock...")
local ok14b, r14b = pcall(function()
    return sc_umtx(uint64(to_num(rwl2)), uint64(14), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok14b, r14b) .. " rw_state=0x" .. string.format("%08X", rd(rwl2) or 0))

-- ============================================================
-- SECTION E: WAIT with mismatch (should NOT block)
-- ============================================================
print("")
print("--- E: WAIT MISMATCH ---")

-- WAIT(2)
local w2 = memory.alloc(64)
wd(w2, 42)
print("[E1] WAIT(2) *=42 expect=99...")
local okw2, rw2 = pcall(function()
    return sc_umtx(uint64(to_num(w2)), uint64(2), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okw2, rw2))

-- WAIT_UINT(11)
local w11 = memory.alloc(64)
wd(w11, 42)
print("[E2] WAIT_UINT(11) *=42 expect=99...")
local okw11, rw11 = pcall(function()
    return sc_umtx(uint64(to_num(w11)), uint64(11), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okw11, rw11))

-- WAIT_UINT_PRIVATE(15) — the one that killed 153b!
local w15 = memory.alloc(64)
wd(w15, 42)
print("[E3] WAIT_UINT_PRIV(15) *=42 expect=99...")
local okw15, rw15 = pcall(function()
    return sc_umtx(uint64(to_num(w15)), uint64(15), uint64(99), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(okw15, rw15))

-- ============================================================
-- SECTION F: OLD-STYLE LOCK(0)/UNLOCK(1)
-- ============================================================
print("")
print("--- F: OLD-STYLE LOCK ---")

local olm = memory.alloc(0x40)
zero(olm, 0x40)

print("[F1] LOCK(0)...")
local ok0, r0 = pcall(function()
    return sc_umtx(uint64(to_num(olm)), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok0, r0) .. " word=0x" .. string.format("%08X", rd(olm) or 0))

print("[F2] UNLOCK(1)...")
local ok1, r1 = pcall(function()
    return sc_umtx(uint64(to_num(olm)), uint64(1), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok1, r1) .. " word=0x" .. string.format("%08X", rd(olm) or 0))

-- ============================================================
-- SECTION G: ROBUST_LISTS(26), SET_CEILING(7)
-- ============================================================
print("")
print("--- G: MISC ---")

-- ROBUST_LISTS
local rp = memory.alloc(0x40)
zero(rp, 0x40)
print("[G1] ROBUST_LISTS(26) size=24...")
local ok26, r26 = pcall(function()
    return sc_umtx(uint64(0), uint64(26), uint64(24), uint64(to_num(rp)), uint64(0))
end)
print("  ret=" .. rv_str(ok26, r26))

-- SET_CEILING(7) — CONFIRMED BLOCKS FOREVER on 14.10 (160a2 run 2026-10-21)
-- Killed the loader, required game restart. DO NOT RE-TEST.
print("[G2] SET_CEILING(7) SKIPPED — blocks forever")

-- MUTEX_WAIT(17) — should return immediately on unlocked
local mw17 = memory.alloc(0x40)
zero(mw17, 0x40)
print("[G3] MUTEX_WAIT(17) on unlocked (should return)...")
local ok17, r17 = pcall(function()
    return sc_umtx(uint64(to_num(mw17)), uint64(17), uint64(0), uint64(0), uint64(0))
end)
print("  ret=" .. rv_str(ok17, r17))

-- ============================================================
-- SECTION H: VM counter check
-- ============================================================
print("")
print("--- H: VM COUNTER ---")

local sc_624 = make_syscall(624)
local ok624a, cnt_a = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0)) end)
print("vm_before=" .. rv_str(ok624a, cnt_a))

-- PI lock/unlock cycle
local pi2 = memory.alloc(0x40)
zero(pi2, 0x40); wd(pi2 + 4, 4)
pcall(function() sc_umtx(uint64(to_num(pi2)), uint64(5), uint64(0), uint64(0), uint64(0)) end)
pcall(function() sc_umtx(uint64(to_num(pi2)), uint64(6), uint64(0), uint64(0), uint64(0)) end)
local ok624b, cnt_b = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0)) end)
print("vm_after_pi=" .. rv_str(ok624b, cnt_b))

-- mmap control
pcall(function()
    local sc_mmap = make_syscall(477)
    sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok624c, cnt_c = pcall(function() return sc_624(uint64(0), uint64(0), uint64(0)) end)
print("vm_after_mmap=" .. rv_str(ok624c, cnt_c))

print("")
print("canary=" .. pid)
print("=== PROBE 160a2 COMPLETE ===")
