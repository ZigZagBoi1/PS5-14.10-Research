-- CRASH_CLASS: LOW
-- PROBE 1113a: sendfile on SHM sanity check
print("=== PROBE 1113a: SENDFILE SANITY ===")

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

local pid = N(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("pid=" .. pid)

-- SHM
local shm_fd = N(mk(482)(uint64(1), uint64(0x602), uint64(0x1FF)))
print("shm_fd=" .. shm_fd)
N(mk(480)(uint64(shm_fd), uint64(0x4000)))

-- Map and write sentinel
local map = mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(shm_fd), uint64(0))
local mn = N(map)
wd(mn, 0xDEAD1113)
wd(mn + 4, 0xBEEF1113)
print(string.format("map=0x%X sentinel written", mn))

-- Socketpair
local sv = memory.alloc(8)
wd(N(sv), 0); wd(N(sv) + 4, 0)
local sp = N(mk(135)(uint64(1), uint64(1), uint64(0), sv))
local rfd = rd(N(sv)) or -1
local wfd = rd(N(sv) + 4) or -1
print(string.format("socketpair ret=%d r=%d w=%d", sp, rfd, wfd))

-- Non-blocking both
pcall(function() mk(92)(uint64(rfd), uint64(4), uint64(4)) end)
pcall(function() mk(92)(uint64(wfd), uint64(4), uint64(4)) end)

-- SO_SNDBUF = 0x1001 (SOL_SOCKET=0xFFFF, SO_SNDBUF=0x1001)
local optval = memory.alloc(4)
wd(N(optval), 0x100000) -- 1MB send buffer
pcall(function() mk(105)(uint64(wfd), uint64(0xFFFF), uint64(0x1001), optval, uint64(4)) end)
print("SO_SNDBUF set")

-- sendfile
local sbytes = memory.alloc(8)
wd(N(sbytes), 0); wd(N(sbytes) + 4, 0)
local ok1, rv1 = pcall(function()
    return mk(393)(uint64(shm_fd), uint64(wfd), uint64(0), uint64(0x4000),
        uint64(0), sbytes, uint64(0))
end)
local sf_ret = ok1 and N(rv1) or -999
local sent = rd(N(sbytes)) or 0
print(string.format("sendfile: ret=%d sbytes=%d", sf_ret, sent))

-- Read it back
local rbuf = memory.alloc(0x4000)
local rn = N(rbuf)
local ok2, rv2 = pcall(function()
    return mk(3)(uint64(rfd), uint64(rn), uint64(0x4000))
end)
local nread = ok2 and N(rv2) or 0
print(string.format("read: %d bytes", nread))
if nread >= 8 then
    local d0 = rd(rn) or 0
    local d1 = rd(rn + 4) or 0
    if d0 < 0 then d0 = d0 + 0x100000000 end
    if d1 < 0 then d1 = d1 + 0x100000000 end
    print(string.format("first 8B: 0x%08X %08X (expect DEAD1113 BEEF1113)", d0, d1))
end

print("alive=" .. tostring(N(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) == pid))
print("=== PROBE 1113a COMPLETE ===")
