-- CRASH_CLASS: LOW
-- PROBE 389e: syscall 102 buffer inspection + more BSD syscalls
--
-- Context: 389d showed syscall 102 returned ret=1 with a buffer but
-- we didn't inspect it (checked ret==0). Also tests more BSD range.

print("=== PROBE 389e: sc102 + more BSD ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local function is_kptr(val)
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000
end

local function scan_kptr(addr, count)
    local found = 0
    for i = 0, count - 1 do
        local v = rq(N(addr) + i * 8)
        if v and is_kptr(v) then
            local h, l = get_hi_lo(v)
            print(string.format("    *** KPTR +0x%X: 0x%X%08X ***", i * 8, h, l))
            found = found + 1
        end
    end
    return found
end

local function hex_line(addr, off, len)
    local parts = {}
    for i = off, off + len - 4, 4 do
        local v = rd(N(addr) + i)
        if v then parts[#parts + 1] = string.format("%08X", v) end
    end
    return string.format("  +%03X: %s", off, table.concat(parts, " "))
end

local sc_close = mk(6)

-- ===================================================================
-- [A] Syscall 102 — inspect buffer on any non-negative return
-- ===================================================================
print("[A] syscall 102 with buffer inspection")

local sc102 = mk(102)
local sc_socket = mk(97)

-- TCP socket
local ok, rv = pcall(function() return sc_socket(uint64(2), uint64(1), uint64(0)) end)
local sockfd = ok and N(rv) or -1
print(string.format("  TCP socket: fd=%d", sockfd))

if sockfd > 0 then
    -- Test with sentinel-filled buffer
    local buf102 = memory.alloc(0x200)
    for i = 0, 0x200 - 4, 4 do wd(N(buf102) + i, 0xDEADDEAD) end

    -- (fd, buf, size)
    ok, rv = pcall(function() return sc102(uint64(sockfd), buf102, uint64(0x200)) end)
    local r = ok and N(rv) or -999
    print(string.format("  102(tcp, buf, 0x200): ret=%d", r))

    if r >= 0 then
        -- Find how many bytes were modified
        local modified = 0
        for i = 0, 0x200 - 4, 4 do
            if rd(N(buf102) + i) ~= 0xDEADDEAD then modified = modified + 1 end
        end
        print("  modified dwords: " .. modified)

        if modified > 0 then
            -- Print first 128 bytes
            for line = 0, 0x80, 32 do
                local has = false
                for i = line, line + 28, 4 do
                    if rd(N(buf102) + i) ~= 0xDEADDEAD then has = true; break end
                end
                if has then print(hex_line(buf102, line, 32)) end
            end
            scan_kptr(buf102, 0x100 / 8)
        end
    end

    -- Try different arg layouts: (fd, cmd, buf, size)
    for i = 0, 0x200 - 4, 4 do wd(N(buf102) + i, 0xDEADDEAD) end
    ok, rv = pcall(function() return sc102(uint64(sockfd), uint64(0), buf102, uint64(0x200)) end)
    local r2 = ok and N(rv) or -999
    if r2 ~= r then
        print(string.format("  102(tcp, 0, buf, 0x200): ret=%d", r2))
    end

    -- Try (fd, buf, size) with different sizes
    for _, sz in ipairs({0x10, 0x40, 0x100}) do
        for i = 0, sz - 4, 4 do wd(N(buf102) + i, 0xDEADDEAD) end
        ok, rv = pcall(function() return sc102(uint64(sockfd), buf102, uint64(sz)) end)
        local r3 = ok and N(rv) or -999
        local mod = 0
        for i = 0, sz - 4, 4 do
            if rd(N(buf102) + i) ~= 0xDEADDEAD then mod = mod + 1 end
        end
        if mod > 0 or r3 ~= r then
            print(string.format("  102(tcp, buf, 0x%X): ret=%d, mod=%d", sz, r3, mod))
        end
    end

    -- UDP socket too
    pcall(function() sc_close(uint64(sockfd)) end)
    ok, rv = pcall(function() return sc_socket(uint64(2), uint64(2), uint64(0)) end)
    sockfd = ok and N(rv) or -1
    if sockfd > 0 then
        for i = 0, 0x200 - 4, 4 do wd(N(buf102) + i, 0xDEADDEAD) end
        ok, rv = pcall(function() return sc102(uint64(sockfd), buf102, uint64(0x200)) end)
        r = ok and N(rv) or -999
        local mod = 0
        for i = 0, 0x200 - 4, 4 do
            if rd(N(buf102) + i) ~= 0xDEADDEAD then mod = mod + 1 end
        end
        print(string.format("  102(udp, buf, 0x200): ret=%d, mod=%d", r, mod))
        pcall(function() sc_close(uint64(sockfd)) end)
    end
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] More BSD syscalls — quick sweep
-- ===================================================================
print("[B] BSD quick sweep")

local buf = memory.alloc(0x200)

-- List of (number, name, nargs, description)
local tests = {
    {108, "shutdown", "sock,how"},
    {120, "readv", "fd,iov,iovcnt"},
    {136, "mkdir", "path,mode"},
    {137, "rmdir", "path"},
    {142, "setsid", ""},
    {147, "setsockopt", "fd,level,name,val,len"},
    {155, "nfssvc", "flag,argp"},
    {181, "setgid", "gid"},
    {203, "mlock", "addr,len"},
    {204, "munlock", "addr,len"},
    {232, "clock_settime", "id,tp"},
    {250, "minherit", "addr,len,inherit"},
    {253, "issetugid", ""},
    {274, "lchmod", "path,mode"},
    {289, "preadv", "fd,iov,iovcnt,off"},
    {324, "mlockall", "how"},
    {378, "modstat", "modid,stat"},
    {379, "modfind", "name"},
    {380, "kldload", "file"},
    {394, "getfsstat", "buf,bufsize,mode"},
    {410, "sigwait", "set,sig"},
    {415, "cap_enter", ""},
    {419, "cap_fcntls_get", "fd,fcntlrightsp"},
    {425, "cpuset_getid", "level,which,id,setid"},
    {432, "thr_self", "idp"},
    {436, "aio_cancel", "fd,aiocbp"},
    {440, "__semctl", "semid,semnum,cmd"},
    {445, "audit", "record,length"},
    {515, "__cap_rights_get", "version,fd,rightsp"},
}

for _, t in ipairs(tests) do
    if not alive() then break end
    local sc = mk(t[1])
    zero_buf(buf, 0x200)
    ok, rv = pcall(function() return sc(uint64(0), uint64(0), uint64(0)) end)
    local r = ok and N(rv) or -999
    if r ~= -1 and r ~= -999 then
        print(string.format("  %d (%s): ret=%d ***", t[1], t[2] or "?", r))
    end
end

-- Special: thr_self(432) with output pointer
zero_buf(buf, 16)
ok, rv = pcall(function() return mk(432)(buf) end)
local r = ok and N(rv) or -999
local tid_self = rd(N(buf))
print(string.format("  432 thr_self: ret=%d, tid=%d", r, tid_self or -1))

-- issetugid(253) — no args
ok, rv = pcall(function() return mk(253)() end)
print("  253 issetugid: ret=" .. (ok and N(rv) or -999))

-- getfsstat(394) with buffer
zero_buf(buf, 0x200)
ok, rv = pcall(function() return mk(394)(buf, uint64(0x200), uint64(1)) end)
r = ok and N(rv) or -999
print(string.format("  394 getfsstat(buf, 0x200, MNT_NOWAIT): ret=%d", r))
if r > 0 then
    print(hex_line(buf, 0, 32))
    scan_kptr(buf, 32)
end

-- cap_enter(415)
-- DANGEROUS — entering capability mode restricts ALL future syscalls
-- Just check if it returns something without calling
-- Actually let's skip this one entirely — it's a one-way gate

-- cpuset_getid(425) — (level=CPU_LEVEL_WHICH(3), which=CPU_WHICH_PID(2), id=-1, setid*)
local setid = memory.alloc(16)
zero_buf(setid, 16)
ok, rv = pcall(function() return mk(425)(uint64(3), uint64(2), uint64(0xFFFFFFFF), setid) end)
r = ok and N(rv) or -999
print(string.format("  425 cpuset_getid(WHICH,PID,-1): ret=%d, setid=%d", r, rd(N(setid)) or -1))

if not alive() then print("DEAD after [B]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389e COMPLETE ===")
