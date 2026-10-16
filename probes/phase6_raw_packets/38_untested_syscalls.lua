-- 14.10 Probe 38: untested syscall availability sweep (Tier 3 targets)
-- Resolves and exercises syscalls the repo has never tested.
-- Each resolve is isolated in its own pcall because some numbers
-- (e.g. sendto=133) crash the whole batch resolve.
-- Call arguments chosen to ERROR OUT cleanly (EBADF etc.) rather than
-- block or corrupt state, except where a real object is needed.

print("=== 38: UNTESTED SYSCALL SWEEP ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())

local function try_resolve(name, num)
    local ok, err = pcall(function()
        syscall.resolve({ [name] = num })
    end)
    if not ok then
        print(name .. " (" .. num .. "): RESOLVE CRASH/ERR")
        return false
    end
    -- touch it: some resolve lazily; a pcall'd bad call confirms usability
    return true
end

print("")
print("--- phase 1: resolve check ---")
local targets = {
    { "sc_ktimer_create", 235 },
    { "sc_ktimer_settime", 236 },
    { "sc_ktimer_gettime", 238 },
    { "sc_ktimer_delete", 237 },
    { "sc_accept4", 541 },
    { "sc_preadv", 289 },
    { "sc_pwritev", 290 },
    { "sc_copy_file_range", 580 },
    { "sc_msync", 226 },
    { "sc_minherit", 250 },
    { "sc_cap_rights_limit", 533 },
    { "sc_cap_rights_get", 515 },
    { "sc_ppoll", 545 },
    { "sc_getrandom", 563 },
    { "sc_memfd_create", 585 },
    { "sc_posix_fallocate", 530 },
    { "sc_fsync", 95 },
    { "sc_ftruncate", 480 },
    { "sc_getsockname", 32 },
    { "sc_getpeername", 31 },
    { "sc_sctp_peeloff", 471 },
}
for _, t in ipairs(targets) do
    local ok = try_resolve(t[1], t[2])
    print(string.format("%-24s %3d  resolve=%s", t[1], t[2], ok and "ok" or "FAIL"))
end

print("")
print("--- phase 2: safe calls (expect EBADF/EINVAL, NOT block) ---")

local function report(tag, fn)
    local ok, rv = pcall(fn)
    if not ok then
        print(tag .. ": PCALL ERR")
    elseif rv == nil then
        print(tag .. ": nil return")
    else
        local okn, n = pcall(function() return rv:tonumber() end)
        print(tag .. ": rv=" .. (okn and tostring(n) or tostring(rv)))
    end
end

-- getrandom: benign if present — great PRNG + availability signal
local grbuf = memory.alloc(32)
report("getrandom(32B)", function() return syscall.sc_getrandom(grbuf, 32, 0) end)
do
    local hex = ""
    for i = 0, 7 do hex = hex .. string.format("%02x", memory.read_byte(grbuf + i):tonumber()) end
    print("  bytes: " .. hex)
end

-- ktimer_create(CLOCK_REALTIME=0, sigevent*, timerid*)
local sevp = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(sevp + i, 0) end
-- sigev_notify = SIGEV_SIGNAL(1)? start with SIGEV_NONE-ish 0 to avoid signals
local tid = memory.alloc(8)
memory.write_qword(tid, 0xFFFFFFFFFFFFFFFF)
report("ktimer_create", function() return syscall.sc_ktimer_create(0, sevp, tid) end)
print("  timerid out: " .. string.format("0x%x", memory.read_dword(tid):tonumber()))

-- ktimer_gettime on (probably invalid) id
local its = memory.alloc(16)
report("ktimer_gettime(id=out)", function()
    return syscall.sc_ktimer_gettime(memory.read_dword(tid):tonumber(), its)
end)

-- accept4 on invalid fd (must NOT block: bad fd errors immediately)
report("accept4(-1)", function() return syscall.sc_accept4(-1, 0, 0, 0) end)

-- preadv/pwritev on invalid fd
local iov = memory.alloc(16)
local buf = memory.alloc(16)
memory.write_qword(iov, buf)
memory.write_qword(iov + 8, 16)
report("preadv(-1)", function() return syscall.sc_preadv(-1, iov, 1, 0) end)
report("pwritev(-1)", function() return syscall.sc_pwritev(-1, iov, 1, 0) end)

-- copy_file_range with invalid fds
report("copy_file_range(-1,-1)", function()
    return syscall.sc_copy_file_range(-1, 0, -1, 0, 16, 0)
end)

-- cap_rights on a real socket fd
local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 2, 17) end)
local sfd = ok_s and rv_s:tonumber() or -1
if sfd >= 0 then
    local rights = memory.alloc(80)   -- cap_rights_t: version + rights array
    for i = 0, 79, 8 do memory.write_qword(rights + i, 0) end
    memory.write_qword(rights, 0)     -- cr_version 0
    report("cap_rights_get(sock)", function() return syscall.sc_cap_rights_get(sfd, rights) end)
    report("cap_rights_limit(sock)", function() return syscall.sc_cap_rights_limit(sfd, rights) end)
end

-- getsockname / getpeername on the socket
local sa = memory.alloc(32)
local salen = memory.alloc(4)
memory.write_dword(salen, 32)
report("getsockname(sock)", function() return syscall.sc_getsockname(sfd, sa, salen) end)
if sfd >= 0 then
    print("  family=" .. memory.read_byte(sa + 1):tonumber()
        .. " port=" .. (memory.read_byte(sa + 2):tonumber() * 256 + memory.read_byte(sa + 3):tonumber()))
end

-- memfd_create (name ptr, flags) — kernel anonymous file object
local nm = memory.alloc(8)
memory.write_byte(nm, 0x6B)  -- "k"
memory.write_byte(nm + 1, 0)
report("memfd_create", function() return syscall.sc_memfd_create(nm, 0) end)

-- ppoll with nfds=0 timeout=0: immediate return
local ts = memory.alloc(16)
memory.write_qword(ts, 0)
memory.write_qword(ts + 8, 0)
report("ppoll(nfds=0)", function() return syscall.sc_ppoll(memory.alloc(8), 0, ts, 0) end)

print("")
print("--- phase 3: minherit (isolated — crashed in probe 30) ---")
local region = memory.alloc(0x4000)
-- INHERIT_SHARE=0, INHERIT_COPY=1, INHERIT_NONE=2
report("minherit(COPY)", function() return syscall.sc_minherit(region, 0x4000, 1) end)
report("minherit(NONE)", function() return syscall.sc_minherit(region, 0x4000, 2) end)
report("minherit(SHARE)", function() return syscall.sc_minherit(region, 0x4000, 0) end)
-- garbage inherit value: parser validation test
report("minherit(0x1337)", function() return syscall.sc_minherit(region, 0x4000, 0x1337) end)

print("")
print("--- phase 4: msync (LAST — crashed probe 29/30, isolate here) ---")
print("if loader dies now, msync was the probe-30 killer")
report("msync(MS_SYNC=0)", function() return syscall.sc_msync(region, 0x4000, 0) end)
report("msync(MS_INVALIDATE=2)", function() return syscall.sc_msync(region, 0x4000, 2) end)
report("msync unaligned", function() return syscall.sc_msync(region + 1, 0x4000, 0) end)

if sfd >= 0 then pcall(function() syscall.sc_close(sfd) end) end
print("=== 38 DONE ===")
