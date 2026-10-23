-- CRASH_CLASS: LOW
-- PROBE 389d: BSD batch 2 — skip netgetiflist(125) which corrupts
--
-- Context: 389b/389c both crashed after netgetiflist(125) with buffer.
-- This tests the remaining sections only.

print("=== PROBE 389d: BSD batch 2 (no 125) ===")
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
            print(string.format("    *** KPTR +0x%X: 0x%X%08X ***", i * 8, h, l))
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

local ok, rv = pcall(function() return sc44(samples, uint64(0x1000), uint64(0), uint64(0x10000)) end)
print("  enable: ret=" .. (ok and N(rv) or -999))

if ok and N(rv) == 0 then
    local dummy = 0
    for i = 1, 200000 do dummy = dummy + i end
    local ts = memory.alloc(16)
    zero_buf(ts, 16)
    wd(N(ts) + 8, 200000000)  -- 200ms
    pcall(function() mk(240)(ts, uint64(0)) end)

    local nonzero = 0
    for i = 0, 0x1000 - 4, 4 do
        local v = rd(N(samples) + i)
        if v and v ~= 0 then nonzero = nonzero + 1 end
    end
    print("  nonzero dwords after 200ms: " .. nonzero)

    pcall(function() sc44(uint64(0), uint64(0), uint64(0), uint64(0)) end)
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] fstatfs(397) — filesystem stats
-- ===================================================================
print("[B] fstatfs(397)")

local sc397 = mk(397)
local stfs = memory.alloc(0x400)

local sc5 = mk(5)
local pbuf = memory.alloc(64)
zero_buf(pbuf, 64)
local p = "/app0/eboot.bin"
for i = 0, #p - 1, 4 do
    local d = 0
    for j = 0, 3 do
        if i + j < #p then d = d + string.byte(p, i + j + 1) * (256 ^ j) end
    end
    wd(N(pbuf) + i, d)
end
ok, rv = pcall(function() return sc5(pbuf, uint64(0), uint64(0)) end)
local efd = ok and N(rv) or -1

if efd > 0 then
    zero_buf(stfs, 0x400)
    ok, rv = pcall(function() return sc397(uint64(efd), stfs) end)
    local r = ok and N(rv) or -999
    print(string.format("  fstatfs(fd=%d): ret=%d", efd, r))
    if r == 0 then
        for line_start = 0, 0x200, 32 do
            local has = false
            for i = line_start, line_start + 28, 4 do
                if rd(N(stfs) + i) ~= 0 then has = true; break end
            end
            if has then print(hex_line(stfs, line_start, 32)) end
        end
        local kp = scan_kptr(stfs, 0x200 / 8)
        print("  kptrs: " .. kp)

        -- Try to extract f_fstypename (usually at some known offset)
        -- On FreeBSD, struct statfs has f_fstypename at +0x14 (MFSNAMELEN=16)
        -- and f_mntonname at +0x24 (MNAMELEN varies)
    end
    pcall(function() sc_close(uint64(efd)) end)
else
    print("  open failed: " .. efd)
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] uuidgen(392) — kernel UUID
-- ===================================================================
print("[C] uuidgen(392)")

local sc392 = mk(392)
local ub = memory.alloc(64)

for i = 1, 3 do
    zero_buf(ub, 64)
    ok, rv = pcall(function() return sc392(ub, uint64(1)) end)
    local r = ok and N(rv) or -999
    if r == 0 then
        -- Read 16 bytes as hex
        local hex = ""
        for j = 0, 3 do
            hex = hex .. string.format("%08X", rd(N(ub) + j * 4) or 0)
        end
        print("  uuid" .. i .. ": " .. hex)
    else
        print("  uuidgen: ret=" .. r)
    end
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] adjtime(140) — kernel time state
-- ===================================================================
print("[D] adjtime(140)")

local sc140 = mk(140)
local oldd = memory.alloc(16)
zero_buf(oldd, 16)

ok, rv = pcall(function() return sc140(uint64(0), oldd) end)
print("  adjtime(NULL, &old): ret=" .. (ok and N(rv) or -999))
print(string.format("  olddelta: sec=%d, usec=%d", rd(N(oldd)) or -1, rd(N(oldd) + 8) or -1))

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] getitimer(86) — interval timers
-- ===================================================================
print("[E] getitimer(86)")

local sc86 = mk(86)
local itv = memory.alloc(32)

for which = 0, 2 do
    zero_buf(itv, 32)
    ok, rv = pcall(function() return sc86(uint64(which), itv) end)
    local r = ok and N(rv) or -999
    print(string.format("  which=%d: ret=%d, iv=%d.%06d, val=%d.%06d",
        which, r, rd(N(itv)) or 0, rd(N(itv) + 8) or 0,
        rd(N(itv) + 16) or 0, rd(N(itv) + 24) or 0))
end

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] sched_getparam/getscheduler + clock_getcpuclockid2
-- ===================================================================
print("[F] scheduler + cpu clock")

local sc328 = mk(328)
local sp = memory.alloc(16)
zero_buf(sp, 16)
ok, rv = pcall(function() return sc328(uint64(0), sp) end)
print(string.format("  sched_getparam(0): ret=%d, priority=%d", ok and N(rv) or -999, rd(N(sp)) or -1))

local sc330 = mk(330)
ok, rv = pcall(function() return sc330(uint64(0)) end)
print("  sched_getscheduler(0): ret=" .. (ok and N(rv) or -999))

local sc247 = mk(247)
local ckid = memory.alloc(16)
zero_buf(ckid, 16)
ok, rv = pcall(function() return sc247(uint64(0), uint64(0), ckid) end)
print(string.format("  clock_getcpuclockid2(0,PID): ret=%d, clockid=%d", ok and N(rv) or -999, rd(N(ckid)) or -1))

zero_buf(ckid, 16)
ok, rv = pcall(function() return sc247(uint64(0), uint64(1), ckid) end)
print(string.format("  clock_getcpuclockid2(0,TID): ret=%d, clockid=%d", ok and N(rv) or -999, rd(N(ckid)) or -1))

if not alive() then print("DEAD after [F]"); return end
print("")

-- ===================================================================
-- [G] kldunloadf(444) + misc
-- ===================================================================
print("[G] misc")

local sc444 = mk(444)
ok, rv = pcall(function() return sc444(uint64(0), uint64(0)) end)
print("  kldunloadf(0,0): ret=" .. (ok and N(rv) or -999))

-- netabort(101)
local sc101 = mk(101)
ok, rv = pcall(function() return sc101(uint64(0)) end)
print("  101(0): ret=" .. (ok and N(rv) or -999))

-- netgetsockinfo(102) with a socket
local sc_socket = mk(97)
ok, rv = pcall(function() return sc_socket(uint64(2), uint64(1), uint64(0)) end)
local sockfd = ok and N(rv) or -1
if sockfd > 0 then
    local sc102 = mk(102)
    local si = memory.alloc(0x100)
    zero_buf(si, 0x100)
    ok, rv = pcall(function() return sc102(uint64(sockfd), si, uint64(0x100)) end)
    print(string.format("  102(sock=%d, buf): ret=%d", sockfd, ok and N(rv) or -999))
    if ok and N(rv) == 0 then
        local nz = 0
        for i = 0, 0x100 - 4, 4 do
            if rd(N(si) + i) ~= 0 then nz = nz + 1 end
        end
        if nz > 0 then
            print("  nz=" .. nz)
            print(hex_line(si, 0, 32))
            scan_kptr(si, 16)
        end
    end
    pcall(function() sc_close(uint64(sockfd)) end)
else
    print("  socket failed")
end

if not alive() then print("DEAD after [G]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389d COMPLETE ===")
