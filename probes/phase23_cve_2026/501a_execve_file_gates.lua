-- CRASH_CLASS: LOW
-- PROBE 501a: execve reachability + filesystem write gates (CVE-2026-7270 prereqs)
--
-- CVE-2026-7270 (FreeBSD-SA-26:13.exec): operator-precedence bug in execve's
-- shebang argument processing overflows a kernel memmove.  Affects FreeBSD 11+.
-- PS5 kernel is FreeBSD 11 (r230171).
--
-- Prerequisites to trigger:
--   1. execve(59) must reach the kernel handler (not blocked by sandbox)
--   2. We need a file on disk with a crafted #! line
--   3. That means we need filesystem write (open O_CREAT + write)
--
-- This probe tests those gates WITHOUT triggering the overflow.
-- It does NOT attempt exploitation — only reachability.

print("=== PROBE 501a: execve + file creation gates ===")
print("")

------------------------------------------------------------------ helpers
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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc20  = make_syscall(20)   -- getpid
local sc5   = make_syscall(5)    -- open
local sc6   = make_syscall(6)    -- close
local sc4   = make_syscall(4)    -- write
local sc3   = make_syscall(3)    -- read
local sc59  = make_syscall(59)   -- execve
local sc10  = make_syscall(10)   -- unlink
local sc188 = make_syscall(188)  -- stat
local sc416 = make_syscall(416)  -- sigaction

local pid = to_num(sc20())
print("pid: " .. pid)

------------------------------------------------------------------ [A] ignore SIGSYS
-- execve might raise SIGSYS if it's a nosys stub; ignore signal 12
print("")
print("[A] Setting SIGSYS(12) to SIG_IGN...")
local sigact = memory.alloc(0x20)
safe_wq(sigact + 0, uint64(1))  -- sa_handler = SIG_IGN
safe_wd(sigact + 8, 0)          -- sa_flags = 0
local sig_ret_ok, sig_ret = pcall(function()
    return sc416(uint64(12), uint64(to_num(sigact)), uint64(0))
end)
if sig_ret_ok then
    print("  sigaction(12, SIG_IGN) ret=" .. to_num(sig_ret))
else
    print("  sigaction failed (pcall)")
end

------------------------------------------------------------------ [B] test execve with existing file
print("")
print("[B] execve(59) reachability — with /app0/eboot.bin...")

-- build argv: {"/app0/eboot.bin", NULL}
local path_buf = memory.alloc(64)
local path_str = "/app0/eboot.bin"
for i = 1, #path_str do safe_wd(path_buf + i - 1, string.byte(path_str, i)) end
safe_wd(path_buf + #path_str, 0)

-- argv = {path, NULL}
local argv = memory.alloc(16)
safe_wq(argv + 0, path_buf)
safe_wq(argv + 8, uint64(0))

-- envp = {NULL}
local envp = memory.alloc(8)
safe_wq(envp + 0, uint64(0))

local exec_ok, exec_ret = pcall(function()
    return sc59(uint64(to_num(path_buf)), uint64(to_num(argv)), uint64(to_num(envp)))
end)
if exec_ok then
    print("  execve ret=" .. to_num(exec_ret) .. " (survived — did NOT replace process)")
else
    print("  execve CRASHED/KILLED (pcall failed)")
end

-- try with NULL path
print("  execve(NULL, NULL, NULL)...")
local exec2_ok, exec2_ret = pcall(function()
    return sc59(uint64(0), uint64(0), uint64(0))
end)
if exec2_ok then
    print("  execve(NULL) ret=" .. to_num(exec2_ret))
else
    print("  execve(NULL) CRASHED")
end

-- try with /dev/null (not an ELF or script)
print("  execve(/dev/null)...")
local devnull = memory.alloc(16)
local dn_str = "/dev/null"
for i = 1, #dn_str do safe_wd(devnull + i - 1, string.byte(dn_str, i)) end
safe_wd(devnull + #dn_str, 0)
safe_wq(argv + 0, devnull)
local exec3_ok, exec3_ret = pcall(function()
    return sc59(uint64(to_num(devnull)), uint64(to_num(argv)), uint64(to_num(envp)))
end)
if exec3_ok then
    print("  execve(/dev/null) ret=" .. to_num(exec3_ret))
else
    print("  execve(/dev/null) CRASHED")
end

------------------------------------------------------------------ [C] file creation gates
print("")
print("[C] Filesystem write — can we create files?")

local O_RDWR   = 0x0002
local O_CREAT  = 0x0200
local O_TRUNC  = 0x0400
local O_EXCL   = 0x0800

local test_paths = {
    "/system_tmp/probe501_test",
    "/tmp/probe501_test",
    "/dev/shm/probe501_test",
    "/app0/probe501_test",
    "/data/probe501_test",
}

for _, path in ipairs(test_paths) do
    local pbuf = memory.alloc(64)
    for i = 1, #path do safe_wd(pbuf + i - 1, string.byte(path, i)) end
    safe_wd(pbuf + #path, 0)

    local open_ok, open_ret = pcall(function()
        return sc5(uint64(to_num(pbuf)),
                    uint64(O_RDWR + O_CREAT + O_TRUNC),
                    uint64(0x1FF))  -- mode 0777
    end)

    if open_ok then
        local fd = to_num(open_ret)
        if fd >= 0 and fd < 0xFFFF then
            print("  " .. path .. ": OPENED fd=" .. fd)

            -- try write
            local wbuf = memory.alloc(16)
            safe_wd(wbuf + 0, 0x2F2123)  -- "#!/" in LE
            safe_wd(wbuf + 4, 0x0A6E6962) -- "bin\n" approx
            local wr_ok, wr_ret = pcall(function()
                return sc4(uint64(fd), uint64(to_num(wbuf)), uint64(8))
            end)
            if wr_ok then
                print("    write(8) ret=" .. to_num(wr_ret))
            else
                print("    write FAILED (pcall)")
            end

            -- close
            pcall(function() sc6(uint64(fd)) end)

            -- try stat to confirm file exists
            local sbuf = memory.alloc(0x100)
            local stat_ok, stat_ret = pcall(function()
                return sc188(uint64(to_num(pbuf)), uint64(to_num(sbuf)))
            end)
            if stat_ok then
                local st_size = safe_rd(sbuf + 0x48) -- st_size offset in FreeBSD stat
                print("    stat ret=" .. to_num(stat_ret) .. " size=" .. (st_size or "?"))
            else
                print("    stat FAILED")
            end

            -- cleanup: unlink
            pcall(function() sc10(uint64(to_num(pbuf))) end)
        else
            print("  " .. path .. ": open ret=" .. fd .. " (negative = refused)")
        end
    else
        print("  " .. path .. ": open CRASHED (pcall)")
    end
end

------------------------------------------------------------------ [D] shm as pseudo-file for execve
print("")
print("[D] Can execve open a shm object?")
-- shm objects live at /dev/shm or similar internal paths
-- FreeBSD shm_open creates objects in the kernel namespace
-- execve might not be able to reach them, but let's test
local sc482 = make_syscall(482) -- shm_open

-- Create named shm
local shm_name_buf = memory.alloc(32)
local shm_name = "/probe501"
for i = 1, #shm_name do safe_wd(shm_name_buf + i - 1, string.byte(shm_name, i)) end
safe_wd(shm_name_buf + #shm_name, 0)

local shm_ok, shm_ret = pcall(function()
    return sc482(uint64(to_num(shm_name_buf)), uint64(O_RDWR + O_CREAT), uint64(0x1FF))
end)
if shm_ok then
    local shm_fd = to_num(shm_ret)
    print("  shm_open('/probe501') fd=" .. shm_fd)

    if shm_fd >= 0 and shm_fd < 0xFFFF then
        -- ftruncate to 4KB
        local sc480 = make_syscall(480) -- ftruncate
        pcall(function() sc480(uint64(shm_fd), uint64(0x1000)) end)

        -- write shebang bytes
        local sc477 = make_syscall(477) -- mmap
        local mapped = sc477(uint64(0), uint64(0x1000), uint64(0x3),
            uint64(0x1), uint64(shm_fd), uint64(0))
        local m_h, m_l = get_hi_lo(mapped)
        if m_h ~= 0 or m_l ~= 0 then
            safe_wd(mapped + 0, 0x2F2123)      -- "#!/"
            safe_wd(mapped + 4, 0x006E6962)     -- "bin\0"
            print("  wrote shebang to shm mapping at " .. string.format("0x%X%08X", m_h, m_l))

            -- munmap
            local sc73 = make_syscall(73)
            pcall(function() sc73(mapped, uint64(0x1000)) end)
        end

        -- try execve on shm paths
        local shm_exec_paths = {
            "/dev/shm/probe501",
            "shm://probe501",
        }
        for _, sp in ipairs(shm_exec_paths) do
            local spbuf = memory.alloc(64)
            for i = 1, #sp do safe_wd(spbuf + i - 1, string.byte(sp, i)) end
            safe_wd(spbuf + #sp, 0)
            safe_wq(argv, spbuf)
            local e_ok, e_ret = pcall(function()
                return sc59(uint64(to_num(spbuf)), uint64(to_num(argv)), uint64(to_num(envp)))
            end)
            if e_ok then
                print("  execve('" .. sp .. "') ret=" .. to_num(e_ret))
            else
                print("  execve('" .. sp .. "') CRASHED")
            end
        end

        pcall(function() sc6(uint64(shm_fd)) end)
    end
else
    print("  shm_open FAILED")
end

------------------------------------------------------------------ [E] memfd_create as exec target
print("")
print("[E] memfd_create (if available)...")
local sc512 = make_syscall(512) -- memfd_create on newer FreeBSD
local mfd_name = memory.alloc(16)
safe_wd(mfd_name, 0x74736574) -- "test"
safe_wd(mfd_name + 4, 0)
local mfd_ok, mfd_ret = pcall(function()
    return sc512(uint64(to_num(mfd_name)), uint64(0))
end)
if mfd_ok then
    local mfd = to_num(mfd_ret)
    print("  memfd_create ret=" .. mfd)
    if mfd >= 0 and mfd < 0xFFFF then
        -- try /proc/self/fd/N path with execve
        local proc_path = "/proc/self/fd/" .. tostring(mfd)
        local ppbuf = memory.alloc(64)
        for i = 1, #proc_path do safe_wd(ppbuf + i - 1, string.byte(proc_path, i)) end
        safe_wd(ppbuf + #proc_path, 0)
        safe_wq(argv, ppbuf)
        local pe_ok, pe_ret = pcall(function()
            return sc59(uint64(to_num(ppbuf)), uint64(to_num(argv)), uint64(to_num(envp)))
        end)
        if pe_ok then
            print("  execve(proc fd) ret=" .. to_num(pe_ret))
        end
        pcall(function() sc6(uint64(mfd)) end)
    end
else
    print("  memfd_create: not available (expected)")
end

------------------------------------------------------------------ [F] fexecve via /dev/fd/N
print("")
print("[F] fexecve path: open eboot then execve /dev/fd/N...")
local eboot_fd_ok, eboot_fd_ret = pcall(function()
    local pb = memory.alloc(32)
    local ps = "/app0/eboot.bin"
    for i = 1, #ps do safe_wd(pb + i - 1, string.byte(ps, i)) end
    safe_wd(pb + #ps, 0)
    return sc5(uint64(to_num(pb)), uint64(0), uint64(0))  -- O_RDONLY
end)
if eboot_fd_ok then
    local efd = to_num(eboot_fd_ret)
    print("  open(/app0/eboot.bin) fd=" .. efd)
    if efd >= 0 and efd < 0xFFFF then
        local devfd = "/dev/fd/" .. tostring(efd)
        local dfbuf = memory.alloc(32)
        for i = 1, #devfd do safe_wd(dfbuf + i - 1, string.byte(devfd, i)) end
        safe_wd(dfbuf + #devfd, 0)
        safe_wq(argv, dfbuf)
        local fe_ok, fe_ret = pcall(function()
            return sc59(uint64(to_num(dfbuf)), uint64(to_num(argv)), uint64(to_num(envp)))
        end)
        if fe_ok then
            print("  execve(/dev/fd/" .. efd .. ") ret=" .. to_num(fe_ret))
        else
            print("  execve(/dev/fd) CRASHED")
        end
        pcall(function() sc6(uint64(efd)) end)
    end
end

------------------------------------------------------------------ verification
print("")
print("=== VERIFICATION ===")
local pid2 = to_num(sc20())
print("pid after all tests: " .. pid2 .. (pid2 == pid and " [OK — same process]" or " [CHANGED!]"))

print("")
print("=== PROBE 501a COMPLETE ===")
