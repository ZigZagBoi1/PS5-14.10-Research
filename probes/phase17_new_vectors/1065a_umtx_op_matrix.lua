-- CRASH_CLASS: MODERATE
-- PROBE 1065a: _umtx_op (454) op matrix on the FreeBSD 12 enum
--
-- Context: only UMTX_OP_MUTEX_LOCK (5) and UMTX_OP_NWAKE_PRIVATE (21) are measured on
-- 14.10 (docs/UMTX_454_EVIDENCE.md). The enum in FreeBSD 12 kern_umtx.c orders:
--   0 LOCK, 1 UNLOCK, 2 WAIT, 3 WAKE, 4 MUTEX_TRYLOCK, 5 MUTEX_LOCK, 6 MUTEX_UNLOCK,
--   7 SET_CEILING, 8 CV_WAIT, 9 CV_SIGNAL, 10 CV_BROADCAST, 11 WAIT_UINT,
--   12 RW_RDLOCK, 13 RW_WRLOCK, 14 RW_UNLOCK, 15 WAIT_UINT_PRIVATE, 16 WAKE_PRIVATE,
--   17 MUTEX_WAIT, 18 MUTEX_WAKE, 19 SEM_WAIT, 20 SEM_WAKE, 21 NWAKE_PRIVATE,
--   22 MUTEX_WAKE2, 23 SEM2_WAIT, 24 SEM2_WAKE, 25 SHM, 26 ROBUST_LISTS
-- so the "CV_RESET" the earlier draft assumed at 11 is actually WAIT_UINT, which blocks
-- on a value match and wedges the loader (observed: op 11 with word 0 and val 0 hung the
-- process at 2026-11-03 23:37; A1..A7 had already returned -1/-1/0/-1/-1/0/0).
--
-- The syscall is variadic: _umtx_op(void *obj, int op, u_long val, void *uaddr1, void *uaddr2).
-- Every blocking op here is called with a value that does not match the word, so each one
-- returns EWOULDBLOCK instead of parking the only Lua thread.
--
-- UMTX_OP_ROBUST_LISTS is the interesting one: it stores a caller pointer in the thread
-- structure and the kernel walks that list on thread exit.

print("=== PROBE 1065a: _umtx_op op matrix ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function as_addr(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end
local function wq(a, v) pcall(function() memory.write_qword(uint64(a), uint64(v)) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok and v then return to_num(v) end
    return nil
end

local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local umtx = mk(454)
local getpid = mk(20)

local page = memory.alloc(0x4000)
local head = memory.alloc(0x40)
local keep = memory.alloc(0x40)
local p0, h0, k0 = as_addr(page), as_addr(head), as_addr(keep)
if p0 == 0 or h0 == 0 or k0 == 0 then print("[!] alloc failed"); return end
wq(k0, 0)

-- robust_list_head: next == NULL so the kernel stops on the first element
wq(h0, 0)
wq(h0 + 8, 0)
wq(h0 + 0x10, 0)
wq(h0 + 0x18, 0)

print(string.format("[0] page=%X head=%X", p0, h0))

local NONMATCH = 0x12345678

local function op(label, name, code, word_off, val, a1, a2)
    local a = p0 + word_off
    wd(a, 0)
    local ok, rv = pcall(function()
        return umtx(uint64(a), uint64(code), uint64(val or 0), uint64(a1 or 0), uint64(a2 or 0))
    end)
    local now = rd(a)
    if ok then
        print(string.format("%-4s %-18s op=%2d rv=%d word=%s", label, name, code, to_num(rv), tostring(now)))
    else
        print(string.format("%-4s %-18s op=%2d THREW", label, name, code))
    end
end

op("[1]", "LOCK", 0, 0x000, 0)
op("[2]", "UNLOCK", 1, 0x000, 0)
op("[3]", "TRYLOCK", 4, 0x010, 0)
op("[4]", "MUTEX_LOCK", 5, 0x020, 0)
op("[5]", "MUTEX_UNLOCK", 6, 0x020, 0)
op("[6]", "SET_CEILING", 7, 0x030, 0x10)
op("[7]", "CV_SIGNAL", 9, 0x040, 0)
op("[8]", "CV_BROADCAST", 10, 0x040, 0)
op("[9]", "RW_RDLOCK", 12, 0x050, 0)
op("[10]", "RW_UNLOCK", 14, 0x050, 0)
op("[11]", "NWAKE_PRIVATE", 21, 0x060, 0, p0 + 0x060, 1)
op("[12]", "WAKE", 3, 0x070, 1)

print("[B] waits with a non-matching value (must return EWOULDBLOCK)")
op("[B1]", "WAIT", 2, 0x100, NONMATCH)
op("[B2]", "WAIT_UINT", 11, 0x110, NONMATCH)
op("[B3]", "WAIT_UINT_PRIVATE", 15, 0x120, NONMATCH)
op("[B4]", "CV_WAIT", 8, 0x130, NONMATCH, p0 + 0x130, 0x10)
op("[B5]", "MUTEX_WAIT", 17, 0x140, NONMATCH)
op("[B6]", "SEM_WAIT", 19, 0x150, 0, p0 + 0x150, 0x10)
op("[B7]", "SEM2_WAIT", 23, 0x160, 0, p0 + 0x160, k0)

print("[C] PI / wake2")
op("[C1]", "MUTEX_WAKE2", 22, 0x200, 1, p0 + 0x200, 0x10)
op("[C2]", "SEM_WAKE", 20, 0x210, 1, p0 + 0x210, 0x10)
op("[C3]", "SEM2_WAKE", 24, 0x220, 1, p0 + 0x220, 0x10)
op("[C4]", "MUTEX_WAKE", 18, 0x230, 1, p0 + 0x230, 0x10)

print("[D] robust lists (uaddr1 = head, uaddr2 = len)")
local function robust(label, h, len, obj)
    local ok, rv = pcall(function()
        return umtx(uint64(obj or 0), uint64(26), uint64(0), uint64(h), uint64(len))
    end)
    print(string.format("%-4s ROBUST_LISTS len=%s rv=%s", label, tostring(len), ok and tostring(to_num(rv)) or "THREW"))
end
robust("[D1]", 0, 0, 0)
robust("[D2]", h0, 0x18, 0)
robust("[D3]", h0, 0x1000, 0)
robust("[D4]", 0, 0, 0)

print("[E] SHM op")
op("[E1]", "SHM create", 25, 0x300, 1, p0 + 0x300, 0x10)

local okp, pv = pcall(function() return getpid() end)
print(string.format("[Z] alive pid=%d", okp and to_num(pv) or -1))
print("=== COMPLETE ===")
