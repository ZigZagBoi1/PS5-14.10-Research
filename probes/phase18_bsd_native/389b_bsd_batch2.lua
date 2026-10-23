-- CRASH_CLASS: MODERATE
-- PROBE 389b: BSD batch 2 — next 8 promising syscalls
--
-- Context: 388a tested top-5 (ksem, kqueueex, getcontext). ksem fully
-- characterized in 388b-389a (solid, no UAF, useful for heap shaping).
-- This batch tests the next tier of BSD-native syscalls.
--
-- Tests:
--   [A] ktimer_create(235) + ktimer_settime(236) + ktimer_gettime(239)
--       + ktimer_delete(237) + ktimer_getoverrun(238) — POSIX timers
--   [B] profil(44) — kernel PC sampling into userland buffer
--   [C] netgetiflist(125) — returns 4 on zeros, interface list
--   [D] swapcontext(423) — save+load context
--   [E] fstatfs(397) — large filesystem stat struct
--   [F] uuidgen(392) — kernel UUID generation
--   [G] adjtime(140) — kernel time state
--   [H] getitimer(86)/setitimer(83) — interval timers

print("=== PROBE 389b: BSD batch 2 ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local function is_kptr(val)
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000
end

local function scan_kptr(addr, count, label)
    local found = 0
    for i = 0, count - 1 do
        local v = rq(N(addr) + i * 8)
        if v and is_kptr(v) then
            local h, l = get_hi_lo(v)
            print(string.format("    *** KPTR at +0x%X: 0x%X%08X ***", i * 8, h, l))
            found = found + 1
        end
    end
    return found
end

local function hex_dump(addr, bytes, label)
    local parts = {}
    for i = 0, bytes - 4, 4 do
        local v = rd(N(addr) + i)
        if v and v ~= 0 then
            parts[#parts + 1] = string.format("+0x%02X=%08X", i, v)
        end
    end
    if #parts > 0 then
        print("    " .. (label or "") .. table.concat(parts, " "))
    end
end

local sc_close = mk(6)

-- ===================================================================
-- [A] POSIX timers: ktimer_create(235), settime(236), delete(237),
--     getoverrun(238), gettime(239)
-- ===================================================================
print("[A] POSIX timers (ktimer_create)")

local sc235 = mk(235)  -- timer_create(clockid, sigevent*, timerid*)
local sc236 = mk(236)  -- timer_settime(timerid, flags, new, old)
local sc237 = mk(237)  -- timer_delete(timerid)
local sc238 = mk(238)  -- timer_getoverrun(timerid)
local sc239 = mk(239)  -- timer_gettime(timerid, itimerspec*)

-- sigevent: sigev_notify=SIGEV_NONE(0), rest zero
local sigev = memory.alloc(64)
zero_buf(sigev, 64)
-- sigev_notify at offset 0
wd(N(sigev), 0)  -- SIGEV_NONE

local tid_buf = memory.alloc(16)
zero_buf(tid_buf, 16)
wd(N(tid_buf), 0xFFFFFFFF)  -- sentinel

-- CLOCK_REALTIME=0
local ok, rv = pcall(function() return sc235(uint64(0), sigev, tid_buf) end)
local ret = ok and N(rv) or -999
local timer_id = rd(N(tid_buf))
print(string.format("  timer_create(CLOCK_REALTIME, SIGEV_NONE): ret=%d, id=%d", ret, timer_id or -1))

if ret == 0 and timer_id and timer_id ~= 0xFFFFFFFF then
    -- gettime — read current timer value
    local its = memory.alloc(32)
    zero_buf(its, 32)
    ok, rv = pcall(function() return sc239(uint64(timer_id), its) end)
    print("  gettime: ret=" .. (ok and N(rv) or -999))
    hex_dump(its, 32, "itimerspec: ")

    -- settime — arm timer (1 second interval, 1 second initial)
    local new_its = memory.alloc(32)
    zero_buf(new_its, 32)
    wd(N(new_its), 1)       -- it_interval.tv_sec = 1
    wd(N(new_its) + 16, 1)  -- it_value.tv_sec = 1
    local old_its = memory.alloc(32)
    zero_buf(old_its, 32)
    ok, rv = pcall(function() return sc236(uint64(timer_id), uint64(0), new_its, old_its) end)
    print("  settime(1s,1s): ret=" .. (ok and N(rv) or -999))

    -- getoverrun
    ok, rv = pcall(function() return sc238(uint64(timer_id)) end)
    print("  getoverrun: ret=" .. (ok and N(rv) or -999))

    -- Create more timers to check IDs
    local timer_ids = {timer_id}
    for i = 1, 3 do
        zero_buf(tid_buf, 16)
        wd(N(tid_buf), 0xFFFFFFFF)
        ok, rv = pcall(function() return sc235(uint64(0), sigev, tid_buf) end)
        local r = ok and N(rv) or -999
        local tid = rd(N(tid_buf))
        if r == 0 then timer_ids[#timer_ids + 1] = tid end
    end
    local s = {}
    for _, id in ipairs(timer_ids) do s[#s + 1] = tostring(id) end
    print("  timer IDs: " .. table.concat(s, ", "))

    -- Delete all
    for _, id in ipairs(timer_ids) do
        ok, rv = pcall(function() return sc237(uint64(id)) end)
    end
    -- Re-create to check reuse
    zero_buf(tid_buf, 16)
    ok, rv = pcall(function() return sc235(uint64(0), sigev, tid_buf) end)
    local r = ok and N(rv) or -999
    local new_id = rd(N(tid_buf))
    print(string.format("  after delete+recreate: ret=%d, id=%d (reuse=%s)", r, new_id or -1, tostring(new_id == timer_id)))
    if r == 0 then pcall(function() sc237(uint64(new_id)) end) end

    -- SIGEV_THREAD_ID test (notify specific thread)
    zero_buf(sigev, 64)
    wd(N(sigev), 4)  -- SIGEV_THREAD_ID
    wd(N(sigev) + 4, 14) -- SIGALRM
    -- sigev_notify_thread_id at +8 or +12 depending on struct
    wd(N(sigev) + 12, pid_val)
    zero_buf(tid_buf, 16)
    ok, rv = pcall(function() return sc235(uint64(0), sigev, tid_buf) end)
    print("  timer_create(SIGEV_THREAD_ID): ret=" .. (ok and N(rv) or -999))
    local tid2 = rd(N(tid_buf))
    if ok and N(rv) == 0 and tid2 then pcall(function() sc237(uint64(tid2)) end) end
else
    print("  timer_create FAILED")
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] profil(44) — kernel PC sampling
-- ===================================================================
print("[B] profil(44) — PC sampling")

local sc44 = mk(44)
-- profil(samples, size, offset, scale)
-- scale=0 disables, scale=0x10000 = 1:1
local samples = memory.alloc(0x1000)
zero_buf(samples, 0x1000)

-- Enable profiling: sample into buffer, offset 0, scale 1:1
ok, rv = pcall(function() return sc44(samples, uint64(0x1000), uint64(0), uint64(0x10000)) end)
print("  profil(buf, 4096, 0, 0x10000): ret=" .. (ok and N(rv) or -999))

-- If enabled, wait a bit for samples
if ok and N(rv) == 0 then
    local ts = memory.alloc(16)
    zero_buf(ts, 16)
    wd(N(ts), 0)
    wd(N(ts) + 8, 50000000)  -- 50ms
    pcall(function() mk(240)(ts, uint64(0)) end)

    -- Check if any samples written
    local nonzero = 0
    for i = 0, 0x1000 - 4, 4 do
        local v = rd(N(samples) + i)
        if v and v ~= 0 then
            nonzero = nonzero + 1
            if nonzero <= 3 then
                print(string.format("    sample at +0x%X: 0x%08X", i, v))
            end
        end
    end
    print("  nonzero samples: " .. nonzero)

    -- Disable profiling
    pcall(function() sc44(uint64(0), uint64(0), uint64(0), uint64(0)) end)
else
    print("  profil not available")
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] netgetiflist(125)
-- ===================================================================
print("[C] netgetiflist(125)")

local sc125 = mk(125)
-- Try with output buffer
local ifbuf = memory.alloc(0x400)
zero_buf(ifbuf, 0x400)

-- Various arg patterns
for _, args in ipairs({
    {uint64(0), uint64(0), uint64(0)},
    {ifbuf, uint64(0x400), uint64(0)},
    {uint64(0), ifbuf, uint64(0x400)},
    {ifbuf, uint64(0), uint64(0x400)},
}) do
    ok, rv = pcall(function() return sc125(args[1], args[2], args[3]) end)
    local r = ok and N(rv) or -999
    if r ~= -1 then
        print(string.format("  args(%s): ret=%d", tostring(N(args[1]) ~= 0) .. "," .. tostring(N(args[2]) ~= 0) .. "," .. tostring(N(args[3]) ~= 0), r))
    end
end

-- Check buf for data
local first_nz = -1
for i = 0, 0x400 - 4, 4 do
    local v = rd(N(ifbuf) + i)
    if v and v ~= 0 then first_nz = i; break end
end
if first_nz >= 0 then
    print("  buffer has data from +" .. string.format("0x%X", first_nz))
    hex_dump(ifbuf, 64, "first 64B: ")
    scan_kptr(ifbuf, 64, "ifbuf")
else
    print("  buffer empty")
end

-- ret=4 on zeros — what does 4 mean?
ok, rv = pcall(function() return sc125(uint64(0), uint64(0), uint64(0)) end)
print("  ret on zeros: " .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] swapcontext(423)
-- ===================================================================
print("[D] swapcontext(423)")

local sc423 = mk(423)
-- swapcontext(ucontext_t *oucp, const ucontext_t *ucp)
-- Saves current context to oucp, loads ucp

local oucp = memory.alloc(0x500)
zero_buf(oucp, 0x500)

-- First: try getcontext(421) to get a valid context we can swap to
local sc421 = mk(421)
local ctx = memory.alloc(0x500)
zero_buf(ctx, 0x500)
ok, rv = pcall(function() return sc421(ctx) end)
print("  getcontext: ret=" .. (ok and N(rv) or -999))

-- Try swapcontext with saved context as input (should save+restore = noop)
ok, rv = pcall(function() return sc423(oucp, ctx) end)
print("  swapcontext(oucp, ctx): ret=" .. (ok and N(rv) or -999))

-- Check oucp for kernel pointers
if ok and N(rv) == 0 then
    local kp = scan_kptr(oucp, 0x500 / 8, "oucp")
    print("  kptrs in saved context: " .. kp)
    -- Check CS/SS
    local cs = rd(N(oucp) + 0xC8)
    local ss = rd(N(oucp) + 0x100)
    print(string.format("  CS=0x%X, SS=0x%X", cs or 0, ss or 0))
end

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] fstatfs(397)
-- ===================================================================
print("[E] fstatfs(397)")

local sc397 = mk(397)
-- fstatfs(fd, struct statfs *buf)
-- struct statfs is ~400+ bytes on FreeBSD
local stfs = memory.alloc(0x400)
zero_buf(stfs, 0x400)

-- Try on fd 0 (stdin), fd 3 (likely open), an app0 fd
-- First open /app0/eboot.bin
local sc5 = mk(5)  -- open
local path_buf = memory.alloc(64)
zero_buf(path_buf, 64)
local path = "/app0/eboot.bin"
for i = 0, #path - 1, 4 do
    local d = 0
    for j = 0, 3 do
        if i + j < #path then d = d + string.byte(path, i + j + 1) * (256 ^ j) end
    end
    wd(N(path_buf) + i, d)
end
ok, rv = pcall(function() return sc5(path_buf, uint64(0), uint64(0)) end)
local eboot_fd = ok and N(rv) or -1
if eboot_fd > 0 then
    zero_buf(stfs, 0x400)
    ok, rv = pcall(function() return sc397(uint64(eboot_fd), stfs) end)
    local r = ok and N(rv) or -999
    print(string.format("  fstatfs(eboot fd=%d): ret=%d", eboot_fd, r))
    if r == 0 then
        hex_dump(stfs, 128, "first 128B: ")
        local kp = scan_kptr(stfs, 0x400 / 8, "statfs")
        print("  kptrs: " .. kp)
        -- f_mntfromname is a string at a known offset
        -- f_fstypename at +0x00 (or similar)
        local ftype = ""
        for i = 0, 15 do
            local b = rd(N(stfs) + i) or 0
            if i == 0 then b = b % 256 end
            -- just print raw
        end
    end
    pcall(function() sc_close(uint64(eboot_fd)) end)
else
    print("  can't open eboot")
end

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] uuidgen(392)
-- ===================================================================
print("[F] uuidgen(392)")

local sc392 = mk(392)
-- uuidgen(struct uuid *store, int count)
local uuid_buf = memory.alloc(64)
zero_buf(uuid_buf, 64)

ok, rv = pcall(function() return sc392(uuid_buf, uint64(1)) end)
print("  uuidgen(1): ret=" .. (ok and N(rv) or -999))
if ok and N(rv) == 0 then
    -- UUID is 16 bytes
    local parts = {}
    for i = 0, 15 do
        local b = rd(N(uuid_buf) + (i - i % 4))
        if b then
            local byte_val = math.floor(b / (256 ^ (i % 4))) % 256
            parts[#parts + 1] = string.format("%02x", byte_val)
        end
    end
    print("  uuid: " .. table.concat(parts, ""))

    -- Generate another — check if sequential
    zero_buf(uuid_buf, 64)
    pcall(function() sc392(uuid_buf, uint64(1)) end)
    parts = {}
    for i = 0, 15 do
        local b = rd(N(uuid_buf) + (i - i % 4))
        if b then
            local byte_val = math.floor(b / (256 ^ (i % 4))) % 256
            parts[#parts + 1] = string.format("%02x", byte_val)
        end
    end
    print("  uuid2: " .. table.concat(parts, ""))
end

if not alive() then print("DEAD after [F]"); return end
print("")

-- ===================================================================
-- [G] adjtime(140)
-- ===================================================================
print("[G] adjtime(140)")

local sc140 = mk(140)
-- adjtime(const struct timeval *delta, struct timeval *olddelta)
local olddelta = memory.alloc(16)
zero_buf(olddelta, 16)
wd(N(olddelta), 0xDEAD)

ok, rv = pcall(function() return sc140(uint64(0), olddelta) end)
print("  adjtime(NULL, &olddelta): ret=" .. (ok and N(rv) or -999))
local od_sec = rd(N(olddelta))
local od_usec = rd(N(olddelta) + 8)
print(string.format("  olddelta: sec=%d, usec=%d", od_sec or 0, od_usec or 0))

if not alive() then print("DEAD after [G]"); return end
print("")

-- ===================================================================
-- [H] getitimer(86)/setitimer(83)
-- ===================================================================
print("[H] getitimer(86)/setitimer(83)")

local sc86 = mk(86)  -- getitimer(which, value)
local sc83 = mk(83)  -- setitimer(which, value, ovalue)

local itv = memory.alloc(32)
-- ITIMER_REAL=0, ITIMER_VIRTUAL=1, ITIMER_PROF=2
for which = 0, 2 do
    zero_buf(itv, 32)
    ok, rv = pcall(function() return sc86(uint64(which), itv) end)
    local r = ok and N(rv) or -999
    if r == 0 then
        local iv_sec = rd(N(itv))
        local iv_usec = rd(N(itv) + 8)
        local val_sec = rd(N(itv) + 16)
        local val_usec = rd(N(itv) + 24)
        print(string.format("  getitimer(%d): ret=0, interval=%d.%06d, value=%d.%06d",
            which, iv_sec or 0, iv_usec or 0, val_sec or 0, val_usec or 0))
    else
        print(string.format("  getitimer(%d): ret=%d", which, r))
    end
end

if not alive() then print("DEAD after [H]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389b COMPLETE ===")
