-- CRASH_CLASS: LOW
-- PROBE 389c: BSD batch 2 safe — re-run without SIGEV_THREAD_ID and swapcontext
--
-- Context: 389b crashed after SIGEV_THREAD_ID timer. This re-runs
-- the remaining sections safely.
-- From 389b we know: ktimer_create WORKS (IDs 3,4,5,6), settime WORKS,
-- getoverrun ret=-1, delete works.

print("=== PROBE 389c: BSD batch 2 safe ===")
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

local function scan_kptr(addr, count)
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

local function hex_line(addr, off, len)
    local parts = {}
    for i = off, off + len - 4, 4 do
        local v = rd(N(addr) + i)
        if v then parts[#parts + 1] = string.format("%08X", v) end
    end
    return string.format("  +%03X: %s", off, table.concat(parts, " "))
end

local sc_close = mk(6)

-- ===================================================================
-- [A] profil(44) — kernel PC sampling
-- ===================================================================
print("[A] profil(44)")

local sc44 = mk(44)
local samples = memory.alloc(0x1000)
zero_buf(samples, 0x1000)

ok, rv = pcall(function() return sc44(samples, uint64(0x1000), uint64(0), uint64(0x10000)) end)
print("  enable: ret=" .. (ok and N(rv) or -999))

if ok and N(rv) == 0 then
    -- Do some work to generate PC samples
    local dummy = 0
    for i = 1, 100000 do dummy = dummy + i end
    -- Also sleep to let timer ticks accumulate
    local ts = memory.alloc(16)
    zero_buf(ts, 16)
    wd(N(ts) + 8, 100000000)  -- 100ms
    pcall(function() mk(240)(ts, uint64(0)) end)

    -- Check samples
    local nonzero = 0
    for i = 0, 0x1000 - 2, 2 do
        local w = rd(N(samples) + (i - i % 4))
        if w then
            local short_val
            if i % 4 == 0 then short_val = w % 0x10000
            else short_val = math.floor(w / 0x10000) end
            if short_val ~= 0 then nonzero = nonzero + 1 end
        end
    end
    print("  nonzero 16-bit sample bins: " .. nonzero)

    -- Disable
    pcall(function() sc44(uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] netgetiflist(125) — returns 4 on zeros
-- ===================================================================
print("[B] netgetiflist(125)")

local sc125 = mk(125)

-- Try different arg shapes
local ifbuf = memory.alloc(0x400)

-- Shape 1: just zeros (known ret=4)
ok, rv = pcall(function() return sc125(uint64(0), uint64(0), uint64(0)) end)
print("  (0,0,0): ret=" .. (ok and N(rv) or -999))

-- Shape 2: (buf, size)
zero_buf(ifbuf, 0x400)
ok, rv = pcall(function() return sc125(ifbuf, uint64(0x400)) end)
local r2 = ok and N(rv) or -999
print("  (buf, 0x400): ret=" .. r2)
if r2 >= 0 then
    local nz = 0
    for i = 0, 0x100 - 4, 4 do
        if rd(N(ifbuf) + i) ~= 0 then nz = nz + 1 end
    end
    if nz > 0 then
        print("  nonzero dwords in first 256B: " .. nz)
        print(hex_line(ifbuf, 0, 32))
        scan_kptr(ifbuf, 32)
    end
end

-- Shape 3: (0, buf, size) — maybe arg1 is a selector
zero_buf(ifbuf, 0x400)
ok, rv = pcall(function() return sc125(uint64(0), ifbuf, uint64(0x400)) end)
local r3 = ok and N(rv) or -999
print("  (0, buf, 0x400): ret=" .. r3)

-- Shape 4: (count, buf, size) — maybe ret=4 means 4 interfaces, arg1=index?
for idx = 0, 5 do
    zero_buf(ifbuf, 0x400)
    ok, rv = pcall(function() return sc125(uint64(idx), ifbuf, uint64(0x400)) end)
    local r = ok and N(rv) or -999
    local nz = 0
    for i = 0, 63 do
        if rd(N(ifbuf) + i * 4) ~= 0 then nz = nz + 1 end
    end
    if r ~= -999 then
        print(string.format("  (idx=%d, buf, 0x400): ret=%d, nz_dwords=%d", idx, r, nz))
    end
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] fstatfs(397) — filesystem stats
-- ===================================================================
print("[C] fstatfs(397)")

local sc397 = mk(397)
local stfs = memory.alloc(0x400)

-- Open /app0/eboot.bin for a valid fd
local sc5 = mk(5)
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
local efd = ok and N(rv) or -1
print(string.format("  open eboot: fd=%d", efd))

if efd > 0 then
    zero_buf(stfs, 0x400)
    ok, rv = pcall(function() return sc397(uint64(efd), stfs) end)
    local r = ok and N(rv) or -999
    print("  fstatfs: ret=" .. r)
    if r == 0 then
        -- Print nonzero regions
        for line_start = 0, 0x180, 32 do
            local has_data = false
            for i = line_start, line_start + 28, 4 do
                if rd(N(stfs) + i) ~= 0 then has_data = true; break end
            end
            if has_data then
                print(hex_line(stfs, line_start, 32))
            end
        end
        local kp = scan_kptr(stfs, 0x200 / 8)
        print("  kptrs: " .. kp)
    end
    pcall(function() sc_close(uint64(efd)) end)
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] uuidgen(392) — kernel UUID
-- ===================================================================
print("[D] uuidgen(392)")

local sc392 = mk(392)
local ub = memory.alloc(64)

for i = 1, 3 do
    zero_buf(ub, 64)
    ok, rv = pcall(function() return sc392(ub, uint64(1)) end)
    local r = ok and N(rv) or -999
    if r == 0 then
        print(string.format("  uuid%d: %08X-%04X-%04X-%04X-%08X%04X", i,
            rd(N(ub)) or 0,
            (rd(N(ub) + 4) or 0) % 0x10000,
            math.floor((rd(N(ub) + 4) or 0) / 0x10000),
            (rd(N(ub) + 8) or 0) % 0x10000,
            rd(N(ub) + 12) or 0,
            math.floor((rd(N(ub) + 8) or 0) / 0x10000)))
    else
        print("  uuidgen: ret=" .. r)
    end
end

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] adjtime(140) — kernel time state
-- ===================================================================
print("[E] adjtime(140)")

local sc140 = mk(140)
local oldd = memory.alloc(16)
zero_buf(oldd, 16)
wd(N(oldd), 0xDEADDEAD)

ok, rv = pcall(function() return sc140(uint64(0), oldd) end)
print("  adjtime(NULL, &old): ret=" .. (ok and N(rv) or -999))
print(string.format("  olddelta: %d.%06d sec", rd(N(oldd)) or 0, rd(N(oldd) + 8) or 0))

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] getitimer(86) — interval timers
-- ===================================================================
print("[F] getitimer(86)")

local sc86 = mk(86)
local itv = memory.alloc(32)

for which = 0, 2 do
    zero_buf(itv, 32)
    ok, rv = pcall(function() return sc86(uint64(which), itv) end)
    local r = ok and N(rv) or -999
    print(string.format("  which=%d: ret=%d, interval=%d.%06d, value=%d.%06d",
        which, r, rd(N(itv)) or 0, rd(N(itv) + 8) or 0,
        rd(N(itv) + 16) or 0, rd(N(itv) + 24) or 0))
end

if not alive() then print("DEAD after [F]"); return end
print("")

-- ===================================================================
-- [G] Bonus: sched_getparam(328), clock_getcpuclockid2(247)
-- ===================================================================
print("[G] bonus syscalls")

-- sched_getparam(328)
local sc328 = mk(328)
local sparam = memory.alloc(16)
zero_buf(sparam, 16)
ok, rv = pcall(function() return sc328(uint64(0), sparam) end)
print(string.format("  sched_getparam(0): ret=%d, priority=%d", ok and N(rv) or -999, rd(N(sparam)) or -1))

-- sched_getscheduler(330)
local sc330 = mk(330)
ok, rv = pcall(function() return sc330(uint64(0)) end)
print("  sched_getscheduler(0): ret=" .. (ok and N(rv) or -999))

-- clock_getcpuclockid2(247)
local sc247 = mk(247)
local ckid = memory.alloc(16)
zero_buf(ckid, 16)
-- (id=0, which=0=CPUCLOCK_WHICH_PID, *clockid)
ok, rv = pcall(function() return sc247(uint64(0), uint64(0), ckid) end)
local r = ok and N(rv) or -999
local cid = rd(N(ckid))
print(string.format("  clock_getcpuclockid2(0,PID): ret=%d, clockid=%d", r, cid or -1))

-- Try which=1 (CPUCLOCK_WHICH_TID)
zero_buf(ckid, 16)
ok, rv = pcall(function() return sc247(uint64(0), uint64(1), ckid) end)
r = ok and N(rv) or -999
cid = rd(N(ckid))
print(string.format("  clock_getcpuclockid2(0,TID): ret=%d, clockid=%d", r, cid or -1))

-- kldunloadf(444)
local sc444 = mk(444)
ok, rv = pcall(function() return sc444(uint64(0), uint64(0)) end)
print("  kldunloadf(0,0): ret=" .. (ok and N(rv) or -999))

if not alive() then print("DEAD after [G]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389c COMPLETE ===")
