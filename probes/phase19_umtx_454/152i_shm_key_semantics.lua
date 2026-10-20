-- CRASH_CLASS: LOW
-- PROBE 152i: Clarify SHM key semantics — address vs contents
--
-- Context: 152h showed alive() returns 0 for a NEVER-CREATED key.
-- Hypothesis: UMTX key is derived from the BUFFER ADDRESS (page + offset),
-- not buffer contents. We were reusing the same buffer, so all ops
-- hit the same SHM registration regardless of written key values.
--
-- Tests:
-- A. Different addresses → should be independent keys
-- B. Same address → should be same key (reuse behavior)
-- C. alive() return value mapping (0 = exists? or 0 = not found?)
-- D. Verify double-destroy with address-based keys

print("=== PROBE 152i: SHM KEY SEMANTICS ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)

-- ============================================================
-- SECTION A: Different addresses → independent SHM registrations?
-- ============================================================
print("")
print("--- SECTION A: ADDRESS-BASED KEYS ---")

-- Allocate 5 SEPARATE buffers at different addresses
local bufs = {}
for i = 1, 5 do
    local b = memory.alloc(0x20)
    memory.write_qword(b, uint64(0x1234))
    bufs[i] = b
    print(string.format("buf%d addr=%s", i, fmt_addr(uint64(to_num(b)))))
end

-- Create SHM on buf[1] only
local ok1, r1 = pcall(function()
    return sc_umtx(uint64(to_num(bufs[1])), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create(buf1): " .. (ok1 and tostring(r1) or "fail"))

-- Check alive on all 5 buffers
for i = 1, 5 do
    local ok, ret = pcall(function()
        return sc_umtx(uint64(to_num(bufs[i])), uint64(25), uint64(8), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    print(string.format("alive(buf%d): ret=%d%s", i, rv, (i == 1 and " (created)" or " (NOT created)")))
end

-- Destroy only buf[1]
pcall(function()
    sc_umtx(uint64(to_num(bufs[1])), uint64(25), uint64(4), uint64(0), uint64(0))
end)

-- ============================================================
-- SECTION B: Same address, different values → same key?
-- ============================================================
print("")
print("--- SECTION B: SAME ADDRESS DIFFERENT VALUES ---")

local shared = memory.alloc(0x20)
print("shared addr=" .. fmt_addr(uint64(to_num(shared))))

-- Write value A, create
memory.write_qword(shared, uint64(0xAAAAAAAA))
local ok_a, r_a = pcall(function()
    return sc_umtx(uint64(to_num(shared)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create(val=0xAAA): " .. (ok_a and tostring(r_a) or "fail"))

-- Write different value B, check alive
memory.write_qword(shared, uint64(0xBBBBBBBB))
local ok_b, r_b = pcall(function()
    return sc_umtx(uint64(to_num(shared)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("alive(val=0xBBB, same addr): " .. (ok_b and tostring(r_b) or "fail"))

-- Destroy with value B
local ok_d, r_d = pcall(function()
    return sc_umtx(uint64(to_num(shared)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy(val=0xBBB): " .. (ok_d and tostring(r_d) or "fail"))

-- Check alive again
local ok_c, r_c = pcall(function()
    return sc_umtx(uint64(to_num(shared)), uint64(25), uint64(8), uint64(0), uint64(0))
end)
print("alive(after destroy): " .. (ok_c and tostring(r_c) or "fail"))

-- ============================================================
-- SECTION C: Return value disambiguation
-- Check if 0 means "found" vs "not found" vs "success"
-- Compare with ops that have known return semantics
-- ============================================================
print("")
print("--- SECTION C: RETURN VALUE TESTING ---")

-- Test UMTX_OP_WAIT (op=5) — should return -1/EWOULDBLOCK if val != *obj
local wait_addr = memory.alloc(64)
memory.write_dword(wait_addr, 42)
local ok_w1, rw1 = pcall(function()
    return sc_umtx(uint64(to_num(wait_addr)), uint64(5), uint64(42), uint64(0), uint64(0))
end)
print("wait(*=42, val=42): " .. (ok_w1 and tostring(rw1) or "fail") .. " (should block/timeout)")

local ok_w2, rw2 = pcall(function()
    return sc_umtx(uint64(to_num(wait_addr)), uint64(5), uint64(99), uint64(0), uint64(0))
end)
print("wait(*=42, val=99): " .. (ok_w2 and tostring(rw2) or "fail") .. " (should EWOULDBLOCK)")

-- ============================================================
-- SECTION D: Double-destroy with address-based keys
-- Use SEPARATE addresses for each key
-- ============================================================
print("")
print("--- SECTION D: DD WITH SEPARATE ADDRESSES ---")

for trial = 1, 5 do
    local addr = memory.alloc(0x20)
    memory.write_qword(addr, uint64(0))

    -- Create
    local ok_c2, rc2 = pcall(function()
        return sc_umtx(uint64(to_num(addr)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)

    -- Destroy #1
    local ok_d1, rd1 = pcall(function()
        return sc_umtx(uint64(to_num(addr)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    -- Destroy #2 (double-free attempt)
    local ok_d2, rd2 = pcall(function()
        return sc_umtx(uint64(to_num(addr)), uint64(25), uint64(4), uint64(0), uint64(0))
    end)

    -- Alive check
    local ok_a2, ra2 = pcall(function()
        return sc_umtx(uint64(to_num(addr)), uint64(25), uint64(8), uint64(0), uint64(0))
    end)

    print(string.format("trial%d: c=%s d1=%s d2=%s alive=%s addr=%s",
        trial,
        ok_c2 and tostring(rc2) or "X",
        ok_d1 and tostring(rd1) or "X",
        ok_d2 and tostring(rd2) or "X",
        ok_a2 and tostring(ra2) or "X",
        fmt_addr(uint64(to_num(addr)))))
end

-- ============================================================
-- SECTION E: Verify destroy ACTUALLY removes — re-create test
-- After destroy, does create allocate a NEW registration?
-- ============================================================
print("")
print("--- SECTION E: DESTROY + RECREATE ---")

local e_addr = memory.alloc(0x20)
memory.write_qword(e_addr, uint64(0))
print("addr=" .. fmt_addr(uint64(to_num(e_addr))))

-- Create → get fd (if SHM returns an fd)
local ok_e1, re1 = pcall(function()
    return sc_umtx(uint64(to_num(e_addr)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create1: " .. (ok_e1 and tostring(re1) or "fail"))

-- Destroy
local ok_e2, re2 = pcall(function()
    return sc_umtx(uint64(to_num(e_addr)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy: " .. (ok_e2 and tostring(re2) or "fail"))

-- Recreate
local ok_e3, re3 = pcall(function()
    return sc_umtx(uint64(to_num(e_addr)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create2: " .. (ok_e3 and tostring(re3) or "fail"))

-- Destroy again
local ok_e4, re4 = pcall(function()
    return sc_umtx(uint64(to_num(e_addr)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy2: " .. (ok_e4 and tostring(re4) or "fail"))

-- ============================================================
-- SECTION F: SHM with UMTX_SHM_CREAT|UMTX_SHM_LOOKUP flags
-- FreeBSD: CREAT=1, LOOKUP=2, DESTROY=4, ALIVE=8
-- Try LOOKUP (2) alone
-- ============================================================
print("")
print("--- SECTION F: LOOKUP vs CREATE ---")

local f_addr = memory.alloc(0x20)
memory.write_qword(f_addr, uint64(0))

-- Lookup without create (should fail if not existing)
local ok_f1, rf1 = pcall(function()
    return sc_umtx(uint64(to_num(f_addr)), uint64(25), uint64(2), uint64(0), uint64(0))
end)
print("lookup_only: " .. (ok_f1 and tostring(rf1) or "fail"))

-- Create+Lookup (flags=3)
local ok_f2, rf2 = pcall(function()
    return sc_umtx(uint64(to_num(f_addr)), uint64(25), uint64(3), uint64(0), uint64(0))
end)
print("create+lookup: " .. (ok_f2 and tostring(rf2) or "fail"))

-- Lookup after create
local ok_f3, rf3 = pcall(function()
    return sc_umtx(uint64(to_num(f_addr)), uint64(25), uint64(2), uint64(0), uint64(0))
end)
print("lookup_after_create: " .. (ok_f3 and tostring(rf3) or "fail"))

-- Destroy
pcall(function()
    sc_umtx(uint64(to_num(f_addr)), uint64(25), uint64(4), uint64(0), uint64(0))
end)

-- Lookup after destroy
local ok_f4, rf4 = pcall(function()
    return sc_umtx(uint64(to_num(f_addr)), uint64(25), uint64(2), uint64(0), uint64(0))
end)
print("lookup_after_destroy: " .. (ok_f4 and tostring(rf4) or "fail"))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152i COMPLETE ===")
