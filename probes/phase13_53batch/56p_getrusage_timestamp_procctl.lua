-- CRASH_CLASS: LOW
-- PROBE 56p: getrusage padding + SO_TIMESTAMP cmsg + procctl output scan
--
-- A: getrusage(117) — struct rusage has ~128B with alignment padding.
--    Scan for kernel pointers in padding fields.
-- B: SO_TIMESTAMP on loopback UDP — enable timestamp, send/recv, scan cmsg.
-- C: procctl(544) — test commands that return data for kernel pointer leak.

print("=== PROBE 56p: GETRUSAGE + TIMESTAMP + PROCCTL ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local SENTINEL = 0xDDDDDDDD

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function scan_kptr(base, len, label)
    local found = false
    for off = 0, len - 8, 4 do
        local lo = rd(base + off)
        local hi = rd(base + off + 4)
        if lo and hi then
            local uh = hi; if uh < 0 then uh = uh + 0x100000000 end
            if uh >= 0xFFFF8000 and uh < 0xFFFFFFFF then
                found = true
                local ul = lo; if ul < 0 then ul = ul + 0x100000000 end
                print(string.format("  *** %s KPTR +0x%X: 0x%08X%08X ***",
                    label, off, uh, ul))
            end
        end
    end
    return found
end

-- ============ SECTION A: getrusage ============
print("--- A: getrusage ---")

local sc117 = mk(117)  -- getrusage
-- RUSAGE_SELF=0, RUSAGE_CHILDREN=-1, RUSAGE_THREAD=1
local rusage_who = {0, 1}
local RU_SIZE = 0x100  -- struct rusage is ~128B, alloc 256 for overcopy check

for _, who in ipairs(rusage_who) do
    local ru = memory.alloc(RU_SIZE)
    local rua = N(ru)
    for off = 0, RU_SIZE - 4, 4 do wd(rua + off, SENTINEL) end

    local ok1, r1 = pcall(function()
        return sc117(uint64(who), uint64(rua))
    end)
    local rv = ok1 and N(r1) or -999
    print(string.format("  who=%d ret=%d", who, rv))

    if rv == 0 then
        -- Scan for kernel pointers in the first 256 bytes
        local kp = scan_kptr(rua, RU_SIZE, "RUSAGE" .. who)

        -- Count modified dwords and find overcopy boundary
        local last_mod = -1
        for off = 0, RU_SIZE - 4, 4 do
            local v = rd(rua + off)
            if v ~= SENTINEL then last_mod = off end
        end
        print(string.format("  last_modified=+0x%X", last_mod))

        -- Check for overcopy past 128 bytes
        local over = false
        for off = 128, RU_SIZE - 4, 4 do
            local v = rd(rua + off)
            if v ~= SENTINEL then
                if not over then
                    over = true
                    print("  OVERCOPY past 128B:")
                end
                local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("    +0x%02X: 0x%08X", off, uv))
            end
        end
        if not over then print("  no overcopy past 128B") end

        -- Dump non-zero values
        local nz = 0
        for off = 0, math.min(last_mod, 127), 8 do
            local lo = rd(rua + off) or SENTINEL
            local hi = rd(rua + off + 4) or SENTINEL
            if lo ~= SENTINEL or hi ~= SENTINEL then
                local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
                local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                if ulo ~= 0 or uhi ~= 0 then
                    nz = nz + 1
                    if nz <= 20 then
                        print(string.format("    +0x%02X: 0x%08X%08X", off, uhi, ulo))
                    end
                end
            end
        end
        if nz > 20 then print("    ... (" .. nz .. " total)") end
    end
end

if not alive() then print("DEAD after A"); return end

-- ============ SECTION B: SO_TIMESTAMP on loopback UDP ============
print("")
print("--- B: SO_TIMESTAMP on UDP ---")

local sc_socket = mk(97)
local sc_bind = mk(104)
local sc_setsockopt = mk(105)
local sc_sendto = mk(133)
local sc_recvmsg = mk(27)
local sc_close = mk(6)
local sc_mmap = mk(477)

-- Create UDP socket
local ok2, sfd = pcall(function()
    return sc_socket(uint64(2), uint64(2), uint64(17))  -- AF_INET, SOCK_DGRAM, UDP
end)
local sock = ok2 and N(sfd) or -1
print("  udp_sock=" .. sock)

if sock >= 0 then
    -- Bind to 127.0.0.1:12345
    local sa = memory.alloc(16)
    -- sockaddr_in: sin_len=0x10, sin_family=0x02, sin_port=0x3039(12345 NBO)
    -- LE dword at +0: byte0=0x10(len) byte1=0x02(AF_INET) byte2=0x30 byte3=0x39
    wd(N(sa), 0x39300210)
    wd(N(sa) + 4, 0x0100007F)   -- 127.0.0.1
    wd(N(sa) + 8, 0)
    wd(N(sa) + 12, 0)

    local ok3, r3 = pcall(function()
        return sc_bind(uint64(sock), uint64(N(sa)), uint64(16))
    end)
    print("  bind=" .. (ok3 and tostring(N(r3)) or "FAIL"))

    -- Enable SO_TIMESTAMP (0x0400) at SOL_SOCKET (0xFFFF)
    local one = memory.alloc(4)
    wd(N(one), 1)
    local ok4, r4 = pcall(function()
        return sc_setsockopt(uint64(sock), uint64(0xFFFF), uint64(0x0400),
            uint64(N(one)), uint64(4))
    end)
    print("  SO_TIMESTAMP=" .. (ok4 and tostring(N(r4)) or "FAIL"))

    -- Also try SO_BINTIME (0x2000) and SO_REALTIME (SCM_REALTIME)
    local ok4b, r4b = pcall(function()
        return sc_setsockopt(uint64(sock), uint64(0xFFFF), uint64(0x2000),
            uint64(N(one)), uint64(4))
    end)
    print("  SO_BINTIME=" .. (ok4b and tostring(N(r4b)) or "FAIL"))

    -- Send a packet to ourselves
    local snd_data = memory.alloc(8)
    wd(N(snd_data), 0x42424242)
    local ok5, r5 = pcall(function()
        return sc_sendto(uint64(sock), uint64(N(snd_data)), uint64(4), uint64(0),
            uint64(N(sa)), uint64(16))
    end)
    print("  sendto=" .. (ok5 and tostring(N(r5)) or "FAIL"))

    -- Receive with cmsg buffer
    local rcv_data = memory.alloc(64)
    local rcv_iov = memory.alloc(16)
    wq(rcv_iov, uint64(N(rcv_data)))
    wq(uint64(N(rcv_iov) + 8), uint64(64))

    local cmsg_buf = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local cba = N(cmsg_buf)
    for off = 0, 0x1000 - 4, 4 do wd(cba + off, SENTINEL) end

    -- struct msghdr (amd64)
    local rmsg = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do wd(N(rmsg) + i, 0) end
    wq(uint64(N(rmsg) + 0x10), uint64(N(rcv_iov)))   -- msg_iov @ +0x10
    wd(N(rmsg) + 0x18, 1)                              -- msg_iovlen @ +0x18
    wq(uint64(N(rmsg) + 0x20), uint64(cba))           -- msg_control @ +0x20
    wd(N(rmsg) + 0x28, 0x1000)                         -- msg_controllen @ +0x28

    -- MSG_DONTWAIT=0x80 to avoid blocking if no packet
    local ok6, r6 = pcall(function()
        return sc_recvmsg(uint64(sock), uint64(N(rmsg)), uint64(0x80))
    end)
    local recv_ret = ok6 and N(r6) or -999
    print("  recvmsg=" .. recv_ret)

    local clen = rd(N(rmsg) + 0x28) or 0
    print("  controllen=" .. clen)

    if clen > 0 then
        -- Dump and scan cmsg data
        print("  cmsg data (" .. clen .. " bytes):")
        for off = 0, math.min(clen + 32, 0x200) - 4, 4 do
            local v = rd(cba + off) or SENTINEL
            if v ~= SENTINEL then
                local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("    +0x%02X: 0x%08X", off, uv))
            end
        end
        scan_kptr(cba, math.min(clen + 64, 0x1000), "TIMESTAMP")
    else
        print("  no ancillary data")
    end

    pcall(function() sc_close(uint64(sock)) end)
else
    print("  socket creation failed")
end

if not alive() then print("DEAD after B"); return end

-- ============ SECTION C: procctl ============
print("")
print("--- C: procctl(544) ---")

local sc544 = mk(544)  -- procctl
-- procctl(idtype, id, cmd, data)
-- idtype: P_PID=0
-- Commands that might return data:
--   PROC_REAP_STATUS=3, PROC_TRAPCAP_STATUS=9,
--   PROC_ASLR_STATUS=14, PROC_STACKGAP_STATUS=18,
--   PROC_NO_NEW_PRIVS_STATUS=20, PROC_WXMAP_STATUS=27

local cmds = {
    {name="REAP_STATUS",   cmd=3,  sz=0x40},
    {name="TRAPCAP_STATUS",cmd=9,  sz=0x10},
    {name="ASLR_STATUS",   cmd=14, sz=0x10},
    {name="STACKGAP_STATUS",cmd=18,sz=0x10},
    {name="NOPRIVS_STATUS",cmd=20, sz=0x10},
    {name="WXMAP_STATUS",  cmd=27, sz=0x10},
    {name="PDEATHSIG_STATUS",cmd=22,sz=0x10},
}

for _, c in ipairs(cmds) do
    if not alive() then print("DEAD in procctl scan"); break end

    local buf = memory.alloc(0x100)
    local ba = N(buf)
    for off = 0, 0xFC, 4 do wd(ba + off, SENTINEL) end

    local ok7, r7 = pcall(function()
        return sc544(uint64(0), uint64(pid_val), uint64(c.cmd), uint64(ba))
    end)
    local rv = ok7 and N(r7) or -999

    -- Check for modified bytes
    local modified = 0
    local last = -1
    for off = 0, c.sz - 4, 4 do
        local v = rd(ba + off)
        if v ~= SENTINEL then
            modified = modified + 1
            last = off
        end
    end

    local kp = false
    if modified > 0 then
        kp = scan_kptr(ba, c.sz + 32, c.name)
    end

    local line = string.format("  %s(cmd=%d) ret=%d mod=%d",
        c.name, c.cmd, rv, modified)
    if modified > 0 and not kp then
        -- Dump first few modified values
        local vals = {}
        for off = 0, last, 4 do
            local v = rd(ba + off) or SENTINEL
            if v ~= SENTINEL then
                local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                vals[#vals + 1] = string.format("+0x%X=0x%X", off, uv)
            end
        end
        line = line .. " [" .. table.concat(vals, ", ") .. "]"
    end
    print(line)
end

-- ============ SECTION D: getrlimit scan ============
print("")
print("--- D: getrlimit ---")

local sc194 = mk(194)  -- getrlimit
-- Test several resource types
local resources = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

for _, res in ipairs(resources) do
    local rl = memory.alloc(0x20)
    local rla = N(rl)
    for off = 0, 0x1C, 4 do wd(rla + off, SENTINEL) end

    local ok8, r8 = pcall(function()
        return sc194(uint64(res), uint64(rla))
    end)
    local rv = ok8 and N(r8) or -999

    if rv == 0 then
        -- struct rlimit: rlim_cur(8), rlim_max(8)
        local cur_lo = rd(rla) or 0
        local cur_hi = rd(rla + 4) or 0
        local max_lo = rd(rla + 8) or 0
        local max_hi = rd(rla + 12) or 0

        local ucl = cur_lo; if ucl < 0 then ucl = ucl + 0x100000000 end
        local uch = cur_hi; if uch < 0 then uch = uch + 0x100000000 end
        local uml = max_lo; if uml < 0 then uml = uml + 0x100000000 end
        local umh = max_hi; if umh < 0 then umh = umh + 0x100000000 end

        -- Only print interesting ones (non-RLIM_INFINITY, non-zero)
        if uch ~= 0x7FFFFFFF or umh ~= 0x7FFFFFFF then
            print(string.format("  res=%d cur=0x%08X%08X max=0x%08X%08X",
                res, uch, ucl, umh, uml))
        end

        -- Check for kernel pointers
        if uch >= 0xFFFF8000 and uch < 0xFFFFFFFF then
            print(string.format("  *** RLIMIT KPTR res=%d cur=0x%08X%08X ***", res, uch, ucl))
        end
        if umh >= 0xFFFF8000 and umh < 0xFFFFFFFF then
            print(string.format("  *** RLIMIT KPTR res=%d max=0x%08X%08X ***", res, umh, uml))
        end

        -- Overcopy check: anything past 16 bytes?
        for off = 16, 0x1C, 4 do
            local v = rd(rla + off)
            if v ~= SENTINEL then
                local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("  res=%d OVERCOPY +0x%X=0x%08X", res, off, uv))
            end
        end
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56p COMPLETE ===")
