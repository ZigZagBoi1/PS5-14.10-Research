-- CRASH_CLASS: LOW
-- PROBE 152j: Does SHM create produce an fd? Verify actual SHM effect.
--
-- Context: 152i proved alive() returns 0 for NEVER-CREATED keys.
-- Our "100% dangling references" claim was based on unreliable alive().
-- Need to verify SHM create/destroy actually does something observable.
--
-- FreeBSD SHM create maps a shared memory fd into the process.
-- If we can detect the fd, we can verify create and test double-free.

print("=== PROBE 152j: SHM FD CHECK ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end

collectgarbage("stop")
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local sc_umtx = make_syscall(454)
local sc_close = make_syscall(6)
local sc_fstat = make_syscall(189)  -- fstat

-- ============================================================
-- SECTION A: Count open fds before SHM create
-- ============================================================
print("")
print("--- SECTION A: FD BASELINE ---")

-- Probe which fds are open (0-100)
local function count_open_fds()
    local open = {}
    local stat_buf = memory.alloc(0x200)
    for fd = 0, 100 do
        local ok, ret = pcall(function()
            return sc_fstat(uint64(fd), uint64(to_num(stat_buf)))
        end)
        if ok and to_num(ret) == 0 then
            open[#open + 1] = fd
        end
    end
    return open
end

local fds_before = count_open_fds()
print("open_fds_before=" .. #fds_before)
if #fds_before > 0 then
    local s = ""
    for i = 1, math.min(20, #fds_before) do
        s = s .. fds_before[i] .. " "
    end
    print("fds: " .. s)
end

-- ============================================================
-- SECTION B: SHM create → check new fds
-- ============================================================
print("")
print("--- SECTION B: SHM CREATE + FD CHECK ---")

local key1 = memory.alloc(0x20)
memory.write_qword(key1, uint64(0))

local ok_c, rc = pcall(function()
    return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(1), uint64(0), uint64(0))
end)
print("create ret=" .. (ok_c and tostring(rc) or "fail"))

local fds_after_create = count_open_fds()
print("open_fds_after_create=" .. #fds_after_create)

-- Find new fds
local before_set = {}
for _, fd in ipairs(fds_before) do before_set[fd] = true end
local new_fds = {}
for _, fd in ipairs(fds_after_create) do
    if not before_set[fd] then
        new_fds[#new_fds + 1] = fd
    end
end
print("NEW fds after create: " .. (#new_fds > 0 and table.concat(new_fds, ", ") or "NONE"))

-- ============================================================
-- SECTION C: Create with CREAT|LOOKUP (3) — maybe returns fd?
-- ============================================================
print("")
print("--- SECTION C: CREAT|LOOKUP ---")

local key2 = memory.alloc(0x20)
memory.write_qword(key2, uint64(0))

local ok_cl, rcl = pcall(function()
    return sc_umtx(uint64(to_num(key2)), uint64(25), uint64(3), uint64(0), uint64(0))
end)
print("creat|lookup ret=" .. (ok_cl and tostring(rcl) or "fail"))

local fds_after_cl = count_open_fds()
print("open_fds_after_cl=" .. #fds_after_cl)

local new_fds2 = {}
for _, fd in ipairs(fds_after_cl) do
    if not before_set[fd] then
        new_fds2[#new_fds2 + 1] = fd
    end
end
print("NEW fds after creat|lookup: " .. (#new_fds2 > 0 and table.concat(new_fds2, ", ") or "NONE"))

-- ============================================================
-- SECTION D: Multiple creates at different addresses → fd growth?
-- ============================================================
print("")
print("--- SECTION D: MULTIPLE CREATES ---")

local fds_track = #fds_after_cl
for i = 1, 10 do
    local k = memory.alloc(0x20)
    memory.write_qword(k, uint64(0))
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
end

local fds_after_multi = count_open_fds()
print("open_fds_after_10_creates=" .. #fds_after_multi)
print("fd_growth=" .. (#fds_after_multi - fds_track))

-- ============================================================
-- SECTION E: Destroy → does it close an fd?
-- ============================================================
print("")
print("--- SECTION E: DESTROY + FD CHECK ---")

-- Destroy key1
local ok_d, rd = pcall(function()
    return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("destroy(key1) ret=" .. (ok_d and tostring(rd) or "fail"))

local fds_after_destroy = count_open_fds()
print("open_fds_after_destroy=" .. #fds_after_destroy)

-- Double-destroy
local ok_dd, rdd = pcall(function()
    return sc_umtx(uint64(to_num(key1)), uint64(25), uint64(4), uint64(0), uint64(0))
end)
print("double_destroy(key1) ret=" .. (ok_dd and tostring(rdd) or "fail"))

local fds_after_dd = count_open_fds()
print("open_fds_after_dd=" .. #fds_after_dd)

-- ============================================================
-- SECTION F: Side-channel — sys 624 VM op counter
-- Does SHM create trigger VM operations?
-- ============================================================
print("")
print("--- SECTION F: SYS 624 SIDE CHANNEL ---")

local sc_624 = make_syscall(624)

-- Baseline counter
local ok_624a, r624a = pcall(function()
    return sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("counter_before=" .. (ok_624a and tostring(r624a) or "fail"))

-- Do 10 SHM creates
for i = 1, 10 do
    local k = memory.alloc(0x20)
    memory.write_qword(k, uint64(0))
    pcall(function()
        sc_umtx(uint64(to_num(k)), uint64(25), uint64(1), uint64(0), uint64(0))
    end)
end

local ok_624b, r624b = pcall(function()
    return sc_624(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("counter_after_10_creates=" .. (ok_624b and tostring(r624b) or "fail"))

-- Delta
if ok_624a and ok_624b then
    local delta = to_num(r624b) - to_num(r624a)
    print("vm_ops_delta=" .. delta .. " (10 SHM creates)")
end

-- ============================================================
-- SECTION G: UMTX_OP_WAIT mismatch test (non-blocking)
-- Test that _umtx_op(454) actually works correctly
-- ============================================================
print("")
print("--- SECTION G: UMTX WAIT/WAKE VERIFY ---")

local wa = memory.alloc(64)
memory.write_dword(wa, 42)

-- Wait with MISMATCHED value — should return immediately with EWOULDBLOCK
local ok_wm, rwm = pcall(function()
    return sc_umtx(uint64(to_num(wa)), uint64(5), uint64(99), uint64(0), uint64(0))
end)
print("wait_mismatch(*=42,val=99): " .. (ok_wm and tostring(rwm) or "fail"))

-- Wake (no waiters)
local ok_wk, rwk = pcall(function()
    return sc_umtx(uint64(to_num(wa)), uint64(21), uint64(0x7FFFFFFF), uint64(0), uint64(0))
end)
print("wake_no_waiters: " .. (ok_wk and tostring(rwk) or "fail"))

print("")
print("canary=" .. to_num(syscall.getpid()))
print("=== PROBE 152j COMPLETE ===")
