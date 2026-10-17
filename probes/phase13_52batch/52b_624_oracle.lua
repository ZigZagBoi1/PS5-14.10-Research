-- CRASH_CLASS: LOW
-- PROBE 52b: Syscall 624 as a live VM-metric oracle
--
-- Context: 51a/51b confirmed syscall 624 (narg=0) is alive and returns a
-- value that CHANGES BETWEEN CONNECTIONS (0xD31 in 51a's pid, 0xD30 in 51b's
-- pid). Hypothesis: it is a live VM counter (resident pages / budget metric
-- / charge). If it tracks memory state, it becomes a side channel:
--   - every mmap/munmap moves it -> we can observe kernel VM state
--   - touching pages may move it (page-touch accounting)
--   - other allocations (sockets, kqueues) may move it
-- Procedure: baseline, then controlled 477-mmap allocations of 1..16 pages
-- re-reading 624 after each; a 512-page mmap with page-touches sampled every
-- 32 pages; munmap deltas; jitter loop of 100 tight samples; plus churn of
-- other allocation types (sockets, kqueue, Lua memory.alloc).

print("=== PROBE 52b: SYSCALL 624 ORACLE ===")
print("")

-- Standard helpers (ALWAYS include these)
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
-- uint64 for addresses >32-bit (CLAUDE.md rule: string.format hi/lo form)
local function mkaddr(addr)
    if type(addr) == "table" and addr.h then return addr end
    local n = to_num(addr)
    if n <= 0 then return uint64(0) end
    if n < 4294967296 then
        return uint64(string.format("0x%X%08X", 0, n))
    end
    local hi = math.floor(n / 4294967296)
    local lo = n - hi * 4294967296
    return uint64(string.format("0x%X%08X", hi, lo))
end

local sc624 = make_syscall(624)
local function read624()
    local ok, ret = pcall(function() return sc624() end)
    if ok then
        local h, l = get_hi_lo(ret)
        if h == 0 then return l end
        return nil
    end
    return nil
end

local sc_getpid = make_syscall(20)
local ok_pid, pid_ret = pcall(function() return sc_getpid() end)
local pid = ok_pid and to_num(pid_ret) or 0
print("PID: " .. pid .. "  (624 changed across pids in 51a/51b)")

local function fmt(v)
    if v == nil then return "FAIL" end
    return string.format("%d (0x%X)", v, v)
end

-- ============================================================
-- SECTION 1: Baseline stability (3 reads)
-- ============================================================
print("")
print("--- SECTION 1: baseline ---")
local b1, b2, b3 = read624(), read624(), read624()
print("  624 x3: " .. fmt(b1) .. " / " .. fmt(b2) .. " / " .. fmt(b3))

-- ============================================================
-- SECTION 2: mmap size sweep (1..16 pages), alloc + free deltas
-- ============================================================
print("")
print("--- SECTION 2: mmap size sweep 1..16 pages ---")

local sc_mmap   = make_syscall(477)
local sc_munmap = make_syscall(588)
local PAGE = 0x4000  -- 16KB kernel pages

local function do_mmap(sz)
    local ok, ret = pcall(function()
        return sc_mmap(mkaddr(0), mkaddr(sz), uint64(0x33),
            uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    end)
    if not ok then return nil end
    local h, l = get_hi_lo(ret)
    if h ~= 0 and h >= 0xFFFF8000 then return nil end
    if l == 0 and h == 0 then return nil end
    -- GPU mmap bases observed ~0x3xxxxxxxx -> exact as doubles
    return h * 4294967296 + l
end

local function do_munmap(addr, sz)
    pcall(function() sc_munmap(mkaddr(addr), mkaddr(sz)) end)
end

for npages = 1, 16 do
    local before_alloc = read624()
    local addr = do_mmap(npages * PAGE)
    local after_alloc = read624()
    local after_free = nil
    if addr then do_munmap(addr, npages * PAGE) end
    after_free = read624()
    print(string.format("  mmap %2dpg: before=%s after_alloc=%s after_free=%s  delta_alloc=%+d delta_free=%+d",
        npages, fmt(before_alloc), fmt(after_alloc), fmt(after_free),
        (after_alloc and before_alloc) and (after_alloc - before_alloc) or 0,
        (after_free and after_alloc) and (after_free - after_alloc) or 0))
end

-- ============================================================
-- SECTION 3: 512-page mapping + page touches (sampled every 32)
-- ============================================================
print("")
print("--- SECTION 3: 512-page mmap, touch pages, sample 624 ---")

local base = do_mmap(512 * PAGE)
if base then
    print("  mmap base=" .. string.format("0x%08X%08X",
        math.floor(base / 4294967296), base % 4294967296))
    local v_start = read624()
    print("  624 before touches: " .. fmt(v_start))

    for i = 0, 511 do
        -- write a marker qword at the start of each page (page-touch)
        safe_wq(base + i * PAGE, uint64(0))  -- harmless zero write
        safe_wd(base + i * PAGE, 0xCAFE0000 + i)
        safe_wd(base + i * PAGE + 4, 0)
        if i % 32 == 31 then
            local v = read624()
            print(string.format("  after page %3d touched: 624=%s", i + 1, fmt(v)))
        end
    end

    local v_end = read624()
    print("  624 after all 512 touches: " .. fmt(v_end))

    -- verify the mapping is really ours
    local chk = safe_rd(base)
    print("  page0 dword = " .. string.format("%08X", chk or 0))

    do_munmap(base, 512 * PAGE)
    local v_free = read624()
    print("  624 after munmap: " .. fmt(v_free) ..
        "  delta_total=" .. ((v_free and v_start) and (v_free - v_start) or 0))
else
    print("  512-page mmap FAILED (alloc caps?)")
end

-- ============================================================
-- SECTION 4: Jitter — 100 tight samples
-- ============================================================
print("")
print("--- SECTION 4: jitter, 100 tight samples ---")

local samples = {}
local n_ok = 0
for i = 1, 100 do
    local v = read624()
    samples[i] = v
    if v then n_ok = n_ok + 1 end
end
local distinct = {}
local vmin, vmax = nil, nil
for i = 1, 100 do
    local v = samples[i]
    if v then
        distinct[v] = true
        if vmin == nil or v < vmin then vmin = v end
        if vmax == nil or v > vmax then vmax = v end
    end
end
local ndist = 0
for _ in pairs(distinct) do ndist = ndist + 1 end

-- print raw sequence, 10 per row
local row = {}
for i = 1, 100 do
    if samples[i] then
        row[#row + 1] = string.format("%7d", samples[i])
    else
        row[#row + 1] = "   FAIL"
    end
    if i % 10 == 0 then
        print("  [" .. string.format("%3d-%3d", i - 9, i) .. "] " ..
            table.concat(row, " "))
        row = {}
    end
end
print(string.format("  jitter: ok=%d distinct=%d min=%s max=%s",
    n_ok, ndist, fmt(vmin), fmt(vmax)))
if ndist == 1 then
    print("  -> STABLE within a connection: supports per-VM/budget metric")
elseif vmin and vmax and (vmax - vmin) <= 2 then
    print("  -> near-stable: may be quota with small churn effects")
else
    print("  -> MOVES during runtime: live counter confirmed")
end

-- ============================================================
-- SECTION 5: Other allocation types
-- ============================================================
print("")
print("--- SECTION 5: other allocation types ---")

-- sockets
local sc_socket = make_syscall(97)
local sc_close  = make_syscall(6)
do
    local v0 = read624()
    local made = 0
    for i = 1, 10 do
        local ok, fd = pcall(function()
            return sc_socket(uint64(2), uint64(1), uint64(0), uint64(0),
                uint64(0), uint64(0))
        end)
        if ok and to_num(fd) > 0 then
            made = made + 1
            pcall(function() sc_close(to_num(fd)) end)
        end
    end
    local v1 = read624()
    print(string.format("  10 sockets: before=%s after=%s delta=%+d",
        fmt(v0), fmt(v1), (v1 and v0) and (v1 - v0) or 0))
end

-- kqueue
do
    local sc_kqueue = make_syscall(362)
    local v0 = read624()
    local ok, kq = pcall(function() return sc_kqueue() end)
    local knum = ok and to_num(kq) or -1
    local v1 = read624()
    if knum > 0 then pcall(function() sc_close(knum) end) end
    print(string.format("  kqueue: before=%s after=%s delta=%+d",
        fmt(v0), fmt(v1), (v1 and v0) and (v1 - v0) or 0))
end

-- Lua-side memory.alloc churn (C allocator, not a syscall)
do
    local v0 = read624()
    local blobs = {}
    for i = 1, 8 do blobs[i] = memory.alloc(0x1000) end
    local v1 = read624()
    print(string.format("  8x memory.alloc(0x1000): before=%s after=%s delta=%+d",
        fmt(v0), fmt(v1), (v1 and v0) and (v1 - v0) or 0))
    blobs = nil
end

-- dynlib_get_info call (kernel touches per-module info)
do
    local v0 = read624()
    local ok, v1 = pcall(function()
        local info = memory.alloc(0x200)
        safe_wd(info, 0x160)
        local sc_info = make_syscall(593)
        pcall(function() sc_info(uint64(0), mkaddr(info)) end)
        return read624()
    end)
    print(string.format("  dynlib_get_info: before=%s after=%s delta=%+d",
        fmt(v0), fmt(v1 or read624()), (v1 and v0) and (v1 - v0) or 0))
end

print("")
print("=== PROBE 52b COMPLETE ===")
