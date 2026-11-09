-- CRASH_CLASS: LOW
-- PROBE 396e: test native socket functions + gen_fcall_chain
--
-- make_syscall can't pass 5+ args (R8/R9). But syscall.setsockopt exists
-- as a native binding. Test it for IPv6 options + explore gen_fcall_chain.

print("=== PROBE 396e: native sockopt ===")

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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end

local stub = syscall.pipe.fn_addr

-- Enumerate native socket table APIs
print("-- syscall.setsockopt --")
if type(syscall.setsockopt) == "table" then
    for k, v in pairs(syscall.setsockopt) do
        print(string.format("  .%s = %s", tostring(k), type(v)))
    end
    print("  mt=" .. tostring(getmetatable(syscall.setsockopt)))
end

print("-- syscall.getsockopt --")
if type(syscall.getsockopt) == "table" then
    for k, v in pairs(syscall.getsockopt) do
        print(string.format("  .%s = %s", tostring(k), type(v)))
    end
end

print("-- syscall.socket --")
if type(syscall.socket) == "table" then
    for k, v in pairs(syscall.socket) do
        print(string.format("  .%s = %s", tostring(k), type(v)))
    end
end

-- Check native functions
print("-- native --")
for k, v in pairs(native) do
    print(string.format("  .%s = %s", tostring(k), type(v)))
end

-- Try calling setsockopt as a syscall table (like make_syscall pattern)
-- First make a TCP socket via native
print("")
print("-- socket tests --")

-- Try syscall.socket directly
local sok, srv = pcall(function()
    return syscall.socket(uint64(2), uint64(1), uint64(0))
end)
print(string.format("socket(2,1,0)=%s rv=%s", tostring(sok), tostring(srv)))
local fd1 = sok and N(srv) or -1
print("fd1=" .. fd1)

-- Try as table call
local sok2, srv2 = pcall(function()
    local t = {}
    for k,v in pairs(syscall.socket) do t[k]=v end
    setmetatable(t, getmetatable(syscall.socket))
    return t(uint64(2), uint64(1), uint64(0))
end)
print(string.format("socket_copy=%s rv=%s", tostring(sok2), tostring(srv2)))

-- Now try setsockopt on the socket
if fd1 >= 0 then
    -- Try: setsockopt(fd, SOL_TCP=6, TCP_NODELAY=1, &val=1, 4)
    local ok1, rv1 = pcall(function()
        return syscall.setsockopt(uint64(fd1), uint64(6), uint64(1), uint64(1), uint64(4))
    end)
    print(string.format("setsockopt(tcp,nodelay)=%s rv=%s", tostring(ok1), tostring(rv1)))

    -- Try with fewer args
    local ok2, rv2 = pcall(function()
        return syscall.setsockopt(uint64(fd1), uint64(6), uint64(1), uint64(1))
    end)
    print(string.format("setsockopt(4args)=%s rv=%s", tostring(ok2), tostring(rv2)))

    -- Try as integer args
    local ok3, rv3 = pcall(function()
        return syscall.setsockopt(fd1, 6, 1, 1)
    end)
    print(string.format("setsockopt(int)=%s rv=%s", tostring(ok3), tostring(rv3)))

    pcall(function() mk(6)(uint64(fd1)) end)
end

-- IPv6 socket via syscall.socket
local ok6, rv6 = pcall(function()
    return syscall.socket(uint64(28), uint64(2), uint64(0))
end)
local fd6 = ok6 and N(rv6) or -1
print(string.format("ipv6_socket=%d", fd6))

if fd6 >= 0 then
    -- IPV6_V6ONLY=27, IPPROTO_IPV6=41
    local ok_v, rv_v = pcall(function()
        return syscall.setsockopt(uint64(fd6), uint64(41), uint64(27), uint64(1), uint64(4))
    end)
    print(string.format("v6only=%s rv=%s", tostring(ok_v), tostring(rv_v)))

    -- IPV6_2292PKTOPTIONS=25
    local ok_p, rv_p = pcall(function()
        return syscall.setsockopt(uint64(fd6), uint64(41), uint64(25), uint64(0), uint64(64))
    end)
    print(string.format("2292pktopt=%s rv=%s", tostring(ok_p), tostring(rv_p)))

    -- IPV6_HOPLIMIT=4
    local ok_h, rv_h = pcall(function()
        return syscall.setsockopt(uint64(fd6), uint64(41), uint64(4), uint64(1), uint64(4))
    end)
    print(string.format("hoplimit=%s rv=%s", tostring(ok_h), tostring(rv_h)))

    pcall(function() mk(6)(uint64(fd6)) end)
end

-- gen_fcall_chain — explore
print("")
print("-- gen_fcall_chain --")
local ok_g, rv_g = pcall(function()
    return native.gen_fcall_chain()
end)
print(string.format("gen_fcall_chain()=%s rv=%s type=%s",
    tostring(ok_g), tostring(rv_g), type(rv_g)))

-- Try with args
local ok_g2, rv_g2 = pcall(function()
    return native.gen_fcall_chain(stub, uint64(20))
end)
print(string.format("gen_fcall_chain(stub,20)=%s type=%s", tostring(ok_g2), type(rv_g2)))
if ok_g2 and rv_g2 then
    print("  rv=" .. tostring(rv_g2))
    if type(rv_g2) == "table" then
        for k,v in pairs(rv_g2) do print(string.format("  [%s]=%s", tostring(k), tostring(v))) end
    end
end

-- get_lua_opt
print("")
local ok_lo, rv_lo = pcall(function() return native.get_lua_opt() end)
print(string.format("get_lua_opt()=%s rv=%s", tostring(ok_lo), tostring(rv_lo)))
if ok_lo and type(rv_lo) == "table" then
    for k,v in pairs(rv_lo) do print(string.format("  [%s]=%s", tostring(k), tostring(v))) end
end

print("=== 396e COMPLETE ===")
