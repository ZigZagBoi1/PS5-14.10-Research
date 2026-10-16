-- 14.10 Recon Probe 02: Syscall Availability Sweep
-- Just checks if syscalls resolve, does NOT call them with bad args

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: SYSCALL SWEEP ===")
log("fw: " .. tostring(FW_VERSION))

-- Resolve all interesting syscalls in one batch
local ok, err = pcall(function()
    syscall.resolve({
        sc_aio_read = 454, sc_aio_write = 455, sc_lio_listio = 456,
        sc_aio_return = 457, sc_aio_suspend = 458, sc_aio_cancel = 459,
        sc_aio_error = 460, sc_aio_waitcomplete = 461, sc_aio_fsync = 462,
        sc_aio_mlock = 463, sc_aio_readv = 466, sc_aio_writev = 467,
        sc_aio_multi_cancel = 549, sc_aio_multi_wait = 550,
        sc_umtx_op = 557,
        sc_kqueueex = 394, sc_kqueuex = 540,
        sc_setsockopt = 105, sc_getsockopt = 118,
        sc_socketpair = 135,
        sc_sendto = 133, sc_recvfrom = 134,
        sc_sendmsg = 28, sc_recvmsg = 29,
        sc_ioctl = 54, sc_dup2 = 90, sc_fcntl = 92,
        sc_readv = 120, sc_writev = 121,
        sc_getdents = 272, sc_pipe2 = 542,
        sc_mmap = 477, sc_munmap = 73, sc_mprotect = 74,
        sc_madvise = 75, sc_mincore = 78,
        sc_mlock = 197, sc_munlock = 198,
        sc_thr_new = 432, sc_thr_self = 434,
        sc_thr_kill = 435, sc_thr_kill2 = 436,
        sc_sysctl = 202,
        sc_shm_open2 = 532, sc_shm_rename = 533,
        sc_sigaction = 416, sc_sigprocmask = 340,
        sc_sysarch = 165, sc_issetugid = 253,
        sc_kldload = 363, sc_kldunload = 364,
        sc_kldfind = 365, sc_kldnext = 366,
        sc_kldstat = 367, sc_kldfirstmod = 368,
        sc_cap_rights_limit = 515, sc_cap_ioctls_limit = 516,
        sc_pdfork = 475, sc_pdkill = 476,
    })
end)
log("resolve: " .. (ok and "OK" or tostring(err):sub(1,50)))

-- Check which ones actually got registered (exist in syscall table)
local all_names = {
    "sc_aio_read", "sc_aio_write", "sc_lio_listio",
    "sc_aio_return", "sc_aio_suspend", "sc_aio_cancel",
    "sc_aio_error", "sc_aio_waitcomplete", "sc_aio_fsync",
    "sc_aio_mlock", "sc_aio_readv", "sc_aio_writev",
    "sc_aio_multi_cancel", "sc_aio_multi_wait",
    "sc_umtx_op",
    "sc_kqueueex", "sc_kqueuex",
    "sc_setsockopt", "sc_getsockopt",
    "sc_socketpair", "sc_sendto", "sc_recvfrom",
    "sc_sendmsg", "sc_recvmsg",
    "sc_ioctl", "sc_dup2", "sc_fcntl",
    "sc_readv", "sc_writev",
    "sc_getdents", "sc_pipe2",
    "sc_mmap", "sc_munmap", "sc_mprotect",
    "sc_madvise", "sc_mincore",
    "sc_mlock", "sc_munlock",
    "sc_thr_new", "sc_thr_self",
    "sc_thr_kill", "sc_thr_kill2",
    "sc_sysctl",
    "sc_shm_open2", "sc_shm_rename",
    "sc_sigaction", "sc_sigprocmask",
    "sc_sysarch", "sc_issetugid",
    "sc_kldload", "sc_kldunload",
    "sc_kldfind", "sc_kldnext",
    "sc_kldstat", "sc_kldfirstmod",
    "sc_cap_rights_limit", "sc_cap_ioctls_limit",
    "sc_pdfork", "sc_pdkill",
}

log("")
local available = {}
local missing = {}
for _, name in ipairs(all_names) do
    if syscall[name] then
        available[#available+1] = name
    else
        missing[#missing+1] = name
    end
end

log("--- AVAILABLE (" .. #available .. ") ---")
for _, n in ipairs(available) do log("  " .. n) end

log("")
log("--- MISSING (" .. #missing .. ") ---")
for _, n in ipairs(missing) do log("  " .. n) end

-- Safe test: only call syscalls that are safe with zero/dummy args
log("")
log("--- SAFE CALL TESTS ---")

-- getpid is safe
log("  getpid: " .. syscall.getpid():tonumber())

-- issetugid is safe
if syscall.sc_issetugid then
    local ok2, r = pcall(function() return syscall.sc_issetugid() end)
    log("  issetugid: " .. (ok2 and tostring(r:tonumber()) or tostring(r):sub(1,30)))
end

-- thr_self is safe
if syscall.sc_thr_self then
    local tid_buf = memory.alloc(8)
    local ok2, r = pcall(function() return syscall.sc_thr_self(tid_buf) end)
    if ok2 then
        log("  thr_self: tid=" .. memory.read_dword(tid_buf):tonumber())
    end
end

-- kqueue is safe
local ok2, kq = pcall(function() return syscall.kqueue() end)
if ok2 then
    log("  kqueue: fd=" .. kq:tonumber())
    if kq:tonumber() >= 0 then syscall.close(kq:tonumber()) end
end

-- kqueueex is safe
if syscall.sc_kqueueex then
    local ok3, kqx = pcall(function() return syscall.sc_kqueueex(0) end)
    if ok3 then
        local fd = kqx:tonumber()
        log("  kqueueex: fd=" .. fd)
        if fd >= 0 then syscall.close(fd) end
    else
        log("  kqueueex: " .. tostring(kqx):sub(1,30))
    end
end

-- kqueuex
if syscall.sc_kqueuex then
    local ok3, kqx = pcall(function() return syscall.sc_kqueuex(0) end)
    if ok3 then
        local fd = kqx:tonumber()
        log("  kqueuex: fd=" .. fd)
        if fd >= 0 then syscall.close(fd) end
    else
        log("  kqueuex: " .. tostring(kqx):sub(1,30))
    end
end

-- kldnext is safe (returns first kld id)
if syscall.sc_kldnext then
    local ok3, r = pcall(function() return syscall.sc_kldnext(0) end)
    log("  kldnext(0): " .. (ok3 and tostring(r:tonumber()) or tostring(r):sub(1,30)))
end

log("")
log("=== SYSCALL SWEEP DONE ===")
return table.concat(out, "\n")
