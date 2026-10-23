-- CRASH_CLASS: LOW
-- PROBE 389h: Strictly safe BSD tests — only known non-blocking calls
--
-- Context: 389f/389g both hung on unknown blocking syscalls in sweeps.
-- This probe tests ONLY specific calls known to be non-blocking.

print("=== PROBE 389h: safe targeted BSD ===")
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

-- Ignore SIGSYS
local sa = memory.alloc(32)
zero_buf(sa, 32)
wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local buf = memory.alloc(0x400)

-- ===================================================================
-- [A] Identity syscalls (guaranteed non-blocking, no args)
-- ===================================================================
print("[A] identity calls")

local tests_noarg = {
    {20,  "getpid"},
    {24,  "getuid"},
    {25,  "geteuid"},
    {39,  "getppid"},
    {43,  "getegid"},
    {47,  "getgid"},
    {81,  "getpgrp"},
    {142, "setsid"},
    {253, "issetugid"},
}

for _, t in ipairs(tests_noarg) do
    local ok, rv = pcall(function() return mk(t[1])() end)
    print(string.format("  %d %s: %d", t[1], t[2], ok and N(rv) or -999))
end

if not alive() then print("DEAD after [A]"); return end
print("")

-- ===================================================================
-- [B] Info syscalls with output pointer
-- ===================================================================
print("[B] info calls")

-- getdtablesize(89) — returns fd table size, no args
local ok, rv = pcall(function() return mk(89)() end)
print("  89 getdtablesize: " .. (ok and N(rv) or -999))

-- thr_self(432)
zero_buf(buf, 16)
ok, rv = pcall(function() return mk(432)(buf) end)
print(string.format("  432 thr_self: ret=%d tid=%d", ok and N(rv) or -999, rd(N(buf)) or -1))

-- getgroups(79)
zero_buf(buf, 128)
ok, rv = pcall(function() return mk(79)(uint64(16), buf) end)
local r = ok and N(rv) or -999
if r > 0 then
    local gs = {}
    for i = 0, r - 1 do gs[#gs + 1] = tostring(rd(N(buf) + i * 4) or "?") end
    print("  79 getgroups: [" .. table.concat(gs, ",") .. "]")
else
    print("  79 getgroups: ret=" .. r)
end

-- gettimeofday(116)
zero_buf(buf, 32)
ok, rv = pcall(function() return mk(116)(buf, uint64(0)) end)
r = ok and N(rv) or -999
if r == 0 then
    local sec_lo = rd(N(buf))
    local sec_hi = rd(N(buf) + 4)
    local usec = rd(N(buf) + 8)
    print(string.format("  116 gettimeofday: %d.%06d", sec_lo or 0, usec or 0))
else
    print("  116 gettimeofday: ret=" .. r)
end

-- umask(60) — get/set, restore immediately
ok, rv = pcall(function() return mk(60)(uint64(0x22)) end)
local old_mask = ok and N(rv) or -999
if old_mask >= 0 then pcall(function() mk(60)(uint64(old_mask)) end) end
print("  60 umask: " .. old_mask)

-- pathconf(191) /app0
local pbuf = memory.alloc(64)
zero_buf(pbuf, 64)
local p = "/app0"
for i = 0, #p - 1, 4 do
    local d = 0
    for j = 0, 3 do
        if i + j < #p then d = d + string.byte(p, i + j + 1) * (256 ^ j) end
    end
    wd(N(pbuf) + i, d)
end
for _, pc in ipairs({{1,"LINK_MAX"},{4,"NAME_MAX"},{5,"PATH_MAX"},{11,"SYMLINK_MAX"}}) do
    ok, rv = pcall(function() return mk(191)(pbuf, uint64(pc[1])) end)
    print(string.format("  191 pathconf(%s): %d", pc[2], ok and N(rv) or -999))
end

if not alive() then print("DEAD after [B]"); return end
print("")

-- ===================================================================
-- [C] SysV IPC — known non-blocking with proper args
-- ===================================================================
print("[C] SysV IPC")

-- shmget(231) — IPC_PRIVATE=0, IPC_CREAT=0x200
ok, rv = pcall(function() return mk(231)(uint64(0), uint64(0x4000), uint64(0x3FF)) end)
r = ok and N(rv) or -999
print("  231 shmget(PRIVATE,16K): ret=" .. r)

if r >= 0 then
    local shmid = r
    -- shmctl IPC_STAT=2
    zero_buf(buf, 0x200)
    ok, rv = pcall(function() return mk(229)(uint64(shmid), uint64(2), buf) end)
    print("  229 shmctl(STAT): ret=" .. (ok and N(rv) or -999))
    -- dump first 96 bytes
    for line = 0, 0x60 - 1, 32 do
        local parts = {}
        local has = false
        for i = line, line + 28, 4 do
            local v = rd(N(buf) + i)
            parts[#parts + 1] = string.format("%08X", v or 0)
            if v and v ~= 0 then has = true end
        end
        if has then print(string.format("    +%03X: %s", line, table.concat(parts, " "))) end
    end
    -- kptr scan
    for i = 0, 24 do
        local v = rq(N(buf) + i * 8)
        if v then
            local h, l = get_hi_lo(v)
            if h >= 0xFFFF8000 then
                print(string.format("    *** KPTR +0x%X: 0x%X%08X ***", i*8, h, l))
            end
        end
    end

    -- shmat(228) — attach
    ok, rv = pcall(function() return mk(228)(uint64(shmid), uint64(0), uint64(0)) end)
    r = ok and N(rv) or -999
    print("  228 shmat: ret=" .. r)
    if ok then
        local h, l = get_hi_lo(rv)
        if h > 0 or l > 0x1000 then
            print(string.format("    shm VA: 0x%X%08X", h, l))
            -- try read
            local test_rd = rd(l)
            print("    read [0]: " .. (test_rd or "FAULT"))
            -- try write
            local wok = pcall(function() memory.write_dword(l, 0xBEEF1234) end)
            if wok then
                local check = rd(l)
                print("    write+read: " .. string.format("0x%X", check or 0))
            else
                print("    write: FAULT")
            end
            -- detach
            pcall(function() mk(230)(rv) end)
        end
    end

    -- cleanup: IPC_RMID=0
    pcall(function() mk(229)(uint64(shmid), uint64(0), uint64(0)) end)
    print("  shmctl(RMID): done")
end

-- msgget(225)
ok, rv = pcall(function() return mk(225)(uint64(0), uint64(0x3FF)) end)
print("  225 msgget(PRIVATE): ret=" .. (ok and N(rv) or -999))
if ok and N(rv) >= 0 then
    pcall(function() mk(226)(uint64(N(rv)), uint64(0), uint64(0)) end)  -- IPC_RMID
end

-- semget(221)
ok, rv = pcall(function() return mk(221)(uint64(0), uint64(1), uint64(0x3FF)) end)
print("  221 semget(PRIVATE,1): ret=" .. (ok and N(rv) or -999))
if ok and N(rv) >= 0 then
    pcall(function() mk(222)(uint64(N(rv)), uint64(0), uint64(0), uint64(0)) end)  -- semctl IPC_RMID
end

if not alive() then print("DEAD after [C]"); return end
print("")

-- ===================================================================
-- [D] Targeted single-call tests (one at a time, alive check)
-- ===================================================================
print("[D] targeted singles")

-- Each tested individually with alive() check
local singles = {
    {83,  "getdtablesize2"},
    {132, "mkfifo"},
    {136, "mkdir"},
    {169, "semsys"},
    {170, "msgsys"},
    {171, "shmsys"},
    {203, "mlock"},
    {204, "munlock"},
    {250, "minherit"},
    {274, "lchmod"},
    {324, "mlockall"},
    {326, "getcwd"},
    {344, "extattr_set_fd"},
    {345, "__acl_get_fd"},
    {378, "modstat"},
    {379, "modfind"},
    {380, "kldload"},
    {419, "cap_fcntls_get"},
    {425, "cpuset_getid"},
    {475, "utrace"},
    {505, "setaudit_addr"},
    {515, "__cap_rights_get"},
}

for _, t in ipairs(singles) do
    if not alive() then print("  DEAD at " .. t[1]); break end
    local sc = mk(t[1])
    ok, rv = pcall(function() return sc(uint64(0)) end)
    r = ok and N(rv) or -999
    if r ~= -1 then
        print(string.format("  %d %s: ret=%d ***", t[1], t[2], r))
    end
end

-- Any -1 results too for completeness
print("  (-1 results omitted)")

if not alive() then print("DEAD after [D]"); return end
print("")

-- ===================================================================
-- [E] getcwd(326) with buffer
-- ===================================================================
print("[E] getcwd")

zero_buf(buf, 0x400)
ok, rv = pcall(function() return mk(326)(buf, uint64(0x400)) end)
r = ok and N(rv) or -999
print("  ret=" .. r)
if r == 0 then
    -- Read as string
    local chars = {}
    for i = 0, 255 do
        local b = rd(N(buf) + (i - i % 4))
        if b then
            local shift = (i % 4) * 8
            local ch = math.floor(b / (2 ^ shift)) % 256
            if ch == 0 then break end
            chars[#chars + 1] = string.char(ch)
        end
    end
    print("  cwd: " .. table.concat(chars))
end

if not alive() then print("DEAD after [E]"); return end
print("")

print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 389h COMPLETE ===")
