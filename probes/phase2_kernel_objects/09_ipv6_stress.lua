-- 14.10 Recon Probe 09: IPv6 setsockopt stress test
-- Target: pktopts UAF, heap overflow, info leak via option churn
-- SAFE: no kernel writes, just probing error paths and observing behavior

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: IPV6 SETSOCKOPT STRESS ===")
log("fw: " .. tostring(FW_VERSION))

syscall.resolve({
    sc_socket = 97, sc_close = 6,
    sc_setsockopt = 105, sc_getsockopt = 118,
    sc_pipe = 42, sc_read = 3, sc_write = 4,
})

local IPPROTO_IPV6 = 41
local IPV6_PKTINFO     = 46
local IPV6_HOPLIMIT    = 47
local IPV6_NEXTHOP     = 48
local IPV6_HOPOPTS     = 49
local IPV6_DSTOPTS     = 50
local IPV6_RTHDR       = 51
local IPV6_PKTOPTIONS  = 52
local IPV6_RECVHOPOPTS = 36
local IPV6_RECVDSTOPTS = 37
local IPV6_RECVRTHDR   = 38
local IPV6_RECVPKTINFO = 25
local IPV6_RECVHOPLIMIT = 37

-- ============================================================
-- STRESS 1: Rapid pktopts alloc/free cycle (UAF surface)
-- Setting an IPv6 option allocates an ip6_pktopts mbuf.
-- Setting it to NULL/0 frees it. Rapid cycling may hit a race.
-- ============================================================
log("")
log("--- STRESS 1: pktopts alloc/free churn ---")

local function make_ipv6_udp()
    local s = syscall.sc_socket(28, 2, 0):tonumber()
    return s
end

local fd1 = make_ipv6_udp()
log("socket fd: " .. fd1)

if fd1 >= 0 then
    local optbuf = memory.alloc(4096)
    local zero4 = memory.alloc(4)
    memory.write_dword(zero4, 0)

    -- Build a valid hop-by-hop header: len=0 means 8 bytes total
    -- Type=0 (Pad1 is single byte), but we need at least 8 bytes
    -- ip6_hbh: nxt(1) + len(1) + options(6) = 8 bytes minimum
    local hbh8 = memory.alloc(8)
    memory.write_byte(hbh8, 0)     -- ip6h_nxt = 0
    memory.write_byte(hbh8 + 1, 0) -- ip6h_len = 0 (8 bytes)
    -- rest = padding (PadN option: type=1, len=4, pad...)
    memory.write_byte(hbh8 + 2, 1) -- PadN type
    memory.write_byte(hbh8 + 3, 4) -- PadN len
    memory.write_dword(hbh8 + 4, 0) -- padding

    local crashes = 0
    local successes = 0

    for round = 1, 200 do
        -- Set HOPOPTS (allocates pktopts)
        local ok1 = pcall(function()
            syscall.sc_setsockopt(fd1, IPPROTO_IPV6, IPV6_HOPOPTS, hbh8, 8)
        end)
        if ok1 then successes = successes + 1 end

        -- Immediately clear it (frees pktopts)
        local ok2 = pcall(function()
            syscall.sc_setsockopt(fd1, IPPROTO_IPV6, IPV6_HOPOPTS, zero4, 0)
        end)

        -- Set DSTOPTS on same socket (reuses freed slot?)
        local ok3 = pcall(function()
            syscall.sc_setsockopt(fd1, IPPROTO_IPV6, IPV6_DSTOPTS, hbh8, 8)
        end)

        -- Clear DSTOPTS
        pcall(function()
            syscall.sc_setsockopt(fd1, IPPROTO_IPV6, IPV6_DSTOPTS, zero4, 0)
        end)
    end
    log("  200 alloc/free rounds: " .. successes .. " set-ok, no crash = kernel handles it")

    -- ============================================================
    -- STRESS 2: Cross-option overlap (set one, read another)
    -- If pktopts struct fields overlap, reading one option after
    -- setting another might leak adjacent heap data
    -- ============================================================
    log("")
    log("--- STRESS 2: cross-option info leak ---")

    -- Set HOPOPTS with a pattern
    local pattern = memory.alloc(64)
    memory.write_byte(pattern, 0)     -- nxt
    memory.write_byte(pattern + 1, 0) -- len=0 (8 bytes)
    memory.write_byte(pattern + 2, 1) -- PadN
    memory.write_byte(pattern + 3, 4) -- PadN len
    memory.write_dword(pattern + 4, 0xDEADBEEF) -- marker

    pcall(function()
        syscall.sc_setsockopt(fd1, IPPROTO_IPV6, IPV6_HOPOPTS, pattern, 8)
    end)

    -- Now read back various options and check for our marker or other data
    local readbuf = memory.alloc(8192)
    local optlen = memory.alloc(8)
    local opts_to_check = {
        {IPV6_PKTINFO, "PKTINFO"}, {IPV6_HOPLIMIT, "HOPLIMIT"},
        {IPV6_NEXTHOP, "NEXTHOP"}, {IPV6_HOPOPTS, "HOPOPTS"},
        {IPV6_DSTOPTS, "DSTOPTS"}, {IPV6_RTHDR, "RTHDR"},
        {IPV6_PKTOPTIONS, "PKTOPTIONS"},
    }

    for _, o in ipairs(opts_to_check) do
        -- Zero readbuf
        for i = 0, 63, 8 do memory.write_qword(readbuf + i, 0) end
        memory.write_dword(optlen, 8192)

        local ok = pcall(function()
            return syscall.sc_getsockopt(fd1, IPPROTO_IPV6, o[1], readbuf, optlen)
        end)
        if ok then
            local sz = memory.read_dword(optlen):tonumber()
            if sz > 0 then
                -- Check for our marker
                local found_marker = false
                local nonzero_bytes = 0
                local interesting = {}
                for i = 0, math.min(sz - 1, 255) do
                    local b = memory.read_byte(readbuf + i):tonumber()
                    if b ~= 0 then nonzero_bytes = nonzero_bytes + 1 end
                end
                -- Check qwords for pointers or our marker
                for i = 0, math.min(sz - 4, 252), 4 do
                    local v = memory.read_dword(readbuf + i):tonumber()
                    if v == 0xDEADBEEF then found_marker = true end
                end
                -- Check for kernel pointers in the excess bytes
                local kptrs = 0
                for i = 0, math.min(sz - 8, 8184), 8 do
                    local hi = memory.read_dword(readbuf + i + 4):tonumber()
                    if hi >= 0xFFFF0000 then kptrs = kptrs + 1 end
                end

                local extra = ""
                if found_marker then extra = extra .. " MARKER_FOUND(!)" end
                if kptrs > 0 then extra = extra .. " KPTRS=" .. kptrs .. "(!)" end
                log("  " .. o[2] .. ": " .. sz .. "B, " .. nonzero_bytes .. " nonzero" .. extra)

                -- Hex dump first 64 bytes if there's interesting data
                if nonzero_bytes > 0 and o[2] ~= "HOPOPTS" then
                    local cap = math.min(sz, 64)
                    local hex = {}
                    for i = 0, cap - 1 do
                        hex[#hex+1] = string.format("%02x", memory.read_byte(readbuf + i):tonumber())
                    end
                    log("    hex: " .. table.concat(hex, " "))
                end
            end
        end
    end

    -- ============================================================
    -- STRESS 3: Multi-socket pktopts race
    -- Create many sockets, set options on all, close in reverse
    -- order — tests allocator ordering
    -- ============================================================
    log("")
    log("--- STRESS 3: multi-socket pktopts allocator ---")

    local socks = {}
    local N = 32

    for i = 1, N do
        local s = make_ipv6_udp()
        if s >= 0 then
            socks[#socks+1] = s
            -- Set PKTINFO on each (allocates pktopts per socket)
            local pktinfo = memory.alloc(20)
            memory.write_dword(pktinfo + 16, i) -- ipi6_ifindex = i as marker
            pcall(function()
                syscall.sc_setsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, 20)
            end)
        end
    end
    log("  created " .. #socks .. " sockets with PKTINFO")

    -- Read back from each — check if any socket reads another's data
    local leaks = 0
    for idx, s in ipairs(socks) do
        for i = 0, 19 do memory.write_byte(readbuf + i, 0) end
        memory.write_dword(optlen, 20)
        local ok = pcall(function()
            return syscall.sc_getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, readbuf, optlen)
        end)
        if ok then
            local ifidx = memory.read_dword(readbuf + 16):tonumber()
            if ifidx ~= idx and ifidx ~= 0 then
                log("  LEAK: sock " .. idx .. " got ifindex=" .. ifidx .. " (expected " .. idx .. ")")
                leaks = leaks + 1
            end
        end
    end
    if leaks == 0 then
        log("  no cross-socket leaks in PKTINFO")
    end

    -- Close half in reverse, then read remaining
    for i = #socks, math.floor(#socks/2) + 1, -1 do
        syscall.sc_close(socks[i])
        socks[i] = nil
    end
    log("  closed upper half, reading lower half...")

    local uaf_signs = 0
    for idx = 1, math.floor(N/2) do
        local s = socks[idx]
        if s then
            for i = 0, 63, 8 do memory.write_qword(readbuf + i, 0) end
            memory.write_dword(optlen, 64)
            local ok = pcall(function()
                return syscall.sc_getsockopt(s, IPPROTO_IPV6, IPV6_PKTINFO, readbuf, optlen)
            end)
            if ok then
                local ifidx = memory.read_dword(readbuf + 16):tonumber()
                -- If freed memory was reused, we might see different values
                if ifidx ~= idx and ifidx ~= 0 then
                    log("  UAF?: sock " .. idx .. " now reads ifindex=" .. ifidx)
                    uaf_signs = uaf_signs + 1
                end
                -- Check for any kernel pointers in the returned data
                local sz = memory.read_dword(optlen):tonumber()
                for i = 0, math.min(sz - 8, 56), 8 do
                    local hi = memory.read_dword(readbuf + i + 4):tonumber()
                    if hi >= 0xFFFF0000 then
                        log("  UAF KPTR: sock " .. idx .. " +0x" .. string.format("%x", i) .. " = " ..
                            string.format("%08x%08x", hi, memory.read_dword(readbuf + i):tonumber()))
                        uaf_signs = uaf_signs + 1
                    end
                end
            end
        end
    end
    if uaf_signs == 0 then
        log("  no UAF signs after partial close")
    end

    -- Clean up remaining
    for _, s in pairs(socks) do
        if s then pcall(function() syscall.sc_close(s) end) end
    end

    -- ============================================================
    -- STRESS 4: IPV6_PKTOPTIONS read after option churn
    -- PKTOPTIONS returns ALL set options at once — after rapid
    -- churn, check if it returns stale/freed data
    -- ============================================================
    log("")
    log("--- STRESS 4: PKTOPTIONS stale data check ---")

    local fd2 = make_ipv6_udp()
    if fd2 >= 0 then
        -- Set various options with known patterns
        local buf_a = memory.alloc(8)
        memory.write_byte(buf_a, 0)
        memory.write_byte(buf_a + 1, 0)
        memory.write_byte(buf_a + 2, 1)
        memory.write_byte(buf_a + 3, 4)
        memory.write_dword(buf_a + 4, 0xAAAAAAAA)

        local buf_b = memory.alloc(8)
        memory.write_byte(buf_b, 0)
        memory.write_byte(buf_b + 1, 0)
        memory.write_byte(buf_b + 2, 1)
        memory.write_byte(buf_b + 3, 4)
        memory.write_dword(buf_b + 4, 0xBBBBBBBB)

        -- Churn: set A, read pktoptions, set B, clear A, read pktoptions
        for round = 1, 50 do
            pcall(function() syscall.sc_setsockopt(fd2, IPPROTO_IPV6, IPV6_HOPOPTS, buf_a, 8) end)
            pcall(function() syscall.sc_setsockopt(fd2, IPPROTO_IPV6, IPV6_DSTOPTS, buf_b, 8) end)
            pcall(function() syscall.sc_setsockopt(fd2, IPPROTO_IPV6, IPV6_HOPOPTS, zero4, 0) end)
            pcall(function() syscall.sc_setsockopt(fd2, IPPROTO_IPV6, IPV6_DSTOPTS, zero4, 0) end)
        end

        -- Read PKTOPTIONS — should be empty, but check for stale data
        for i = 0, 255, 8 do memory.write_qword(readbuf + i, 0) end
        memory.write_dword(optlen, 8192)
        local ok = pcall(function()
            return syscall.sc_getsockopt(fd2, IPPROTO_IPV6, IPV6_PKTOPTIONS, readbuf, optlen)
        end)
        if ok then
            local sz = memory.read_dword(optlen):tonumber()
            local nonzero = 0
            local found_aa = false
            local found_bb = false
            for i = 0, math.min(sz - 1, 255) do
                local b = memory.read_byte(readbuf + i):tonumber()
                if b ~= 0 then nonzero = nonzero + 1 end
                if b == 0xAA then found_aa = true end
                if b == 0xBB then found_bb = true end
            end
            local extra = ""
            if found_aa then extra = extra .. " STALE_A(!)" end
            if found_bb then extra = extra .. " STALE_B(!)" end
            log("  PKTOPTIONS after churn: " .. sz .. "B, " .. nonzero .. " nonzero" .. extra)

            if nonzero > 0 then
                local hex = {}
                for i = 0, math.min(sz - 1, 127) do
                    hex[#hex+1] = string.format("%02x", memory.read_byte(readbuf + i):tonumber())
                end
                log("  hex: " .. table.concat(hex, " "))
            end
        end

        syscall.sc_close(fd2)
    end

    -- ============================================================
    -- STRESS 5: Large RTHDR buffer (heap overflow surface)
    -- ip6_rthdr has specific format requirements; send invalid
    -- headers at various sizes to probe bounds checking
    -- ============================================================
    log("")
    log("--- STRESS 5: oversized RTHDR ---")

    local fd3 = make_ipv6_udp()
    if fd3 >= 0 then
        local big = memory.alloc(8192)

        -- Build rthdr type 0 headers of increasing sizes
        -- ip6_rthdr: nxt(1) + len(1) + type(1) + segleft(1) + data...
        local test_sizes = {8, 24, 56, 120, 248, 504, 1016, 2040, 4088, 8184}
        for _, sz in ipairs(test_sizes) do
            memory.write_byte(big, 0)   -- nxt
            memory.write_byte(big + 1, math.floor((sz - 8) / 8)) -- len in 8-byte units
            memory.write_byte(big + 2, 2)   -- type 2 (mobile IPv6)
            memory.write_byte(big + 3, 1)   -- segments left
            -- Fill rest with incremental pattern
            for i = 4, sz - 1 do
                memory.write_byte(big + i, i % 256)
            end

            local ok = pcall(function()
                return syscall.sc_setsockopt(fd3, IPPROTO_IPV6, IPV6_RTHDR, big, sz)
            end)
            local status = "REJECTED"
            if ok then
                status = "ACCEPTED"
                -- Read back and check size
                memory.write_dword(optlen, 8192)
                pcall(function()
                    syscall.sc_getsockopt(fd3, IPPROTO_IPV6, IPV6_RTHDR, readbuf, optlen)
                end)
                local got = memory.read_dword(optlen):tonumber()
                if got ~= sz then
                    status = status .. " readback=" .. got .. "(!)"
                end
                -- Clear for next test
                pcall(function()
                    syscall.sc_setsockopt(fd3, IPPROTO_IPV6, IPV6_RTHDR, zero4, 0)
                end)
            end
            log("  RTHDR size=" .. sz .. ": " .. status)
        end

        syscall.sc_close(fd3)
    end

    syscall.sc_close(fd1)
end

log("")
log("=== IPV6 STRESS DONE ===")
return table.concat(out, "\n")
