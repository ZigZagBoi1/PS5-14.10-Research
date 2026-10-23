-- CRASH_CLASS: LOW
-- PROBE 396d: verify setsockopt arg passing
--
-- ALL IPv6 options returned -1 in 396c. Hypothesis: make_syscall stub
-- doesn't pass arg5 (R8=optlen) properly, so setsockopt reads garbage optlen.
-- Test: TCP_NODELAY (confirmed working in prior probes via native API)
-- and see if it works via make_syscall(105).

print("=== PROBE 396d: setsockopt args ===")

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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr

-- TCP socket (AF_INET=2, SOCK_STREAM=1, 0)
local ok_s, rv_s = pcall(function()
    return mk(97)(uint64(2), uint64(1), uint64(0))
end)
local fd = ok_s and N(rv_s) or -1
print(string.format("tcp_fd=%d", fd))

local buf = memory.alloc(16)

if fd >= 0 then
    -- Test 1: setsockopt via make_syscall(105) with 5 args
    -- setsockopt(fd, SOL_TCP=6, TCP_NODELAY=1, &val, sizeof(int)=4)
    wd(N(buf), 1)
    local ok1, rv1 = pcall(function()
        return mk(105)(uint64(fd), uint64(6), uint64(1), buf, uint64(4))
    end)
    print(string.format("mk105_5args=%d", ok1 and N(rv1) or -999))

    -- Test 2: same but with 6 args (extra zero)
    wd(N(buf), 1)
    local ok2, rv2 = pcall(function()
        return mk(105)(uint64(fd), uint64(6), uint64(1), buf, uint64(4), uint64(0))
    end)
    print(string.format("mk105_6args=%d", ok2 and N(rv2) or -999))

    -- Test 3: setsockopt with 4 args only (missing optlen)
    wd(N(buf), 1)
    local ok3, rv3 = pcall(function()
        return mk(105)(uint64(fd), uint64(6), uint64(1), buf)
    end)
    print(string.format("mk105_4args=%d", ok3 and N(rv3) or -999))

    -- Test 4: getsockopt(118) with 5 args
    local lenp = memory.alloc(8)
    wq(lenp, uint64(4))
    wd(N(buf), 0xCC)
    local ok4, rv4 = pcall(function()
        return mk(118)(uint64(fd), uint64(6), uint64(1), buf, lenp)
    end)
    local gval = rd(N(buf)) or 0xCC
    print(string.format("getsockopt=%d val=%X", ok4 and N(rv4) or -999, gval))

    -- Test 5: try the native setsockopt if available
    if syscall.setsockopt then
        print("native setsockopt exists!")
        local ok5 = pcall(function()
            return syscall.setsockopt(fd, 6, 1, 1)
        end)
        print("native=" .. tostring(ok5))
    else
        print("no native setsockopt")
    end

    -- Test 6: check what functions the loader has for sockets
    local socket_funcs = {}
    for k, v in pairs(syscall) do
        local s = tostring(k):lower()
        if s:find("sock") or s:find("opt") or s:find("bind") or s:find("connect")
            or s:find("listen") or s:find("accept") or s:find("send") or s:find("recv") then
            socket_funcs[#socket_funcs+1] = k .. "=" .. type(v)
        end
    end
    table.sort(socket_funcs)
    for _, f in ipairs(socket_funcs) do print("  syscall." .. f) end

    -- Test 7: check native table
    if native then
        local nat_funcs = {}
        for k, v in pairs(native) do
            local s = tostring(k):lower()
            if s:find("sock") or s:find("opt") or s:find("call") then
                nat_funcs[#nat_funcs+1] = k .. "=" .. type(v)
            end
        end
        table.sort(nat_funcs)
        for _, f in ipairs(nat_funcs) do print("  native." .. f) end
    end

    pcall(function() mk(6)(uint64(fd)) end)
end

-- Also test: IPv6 via make_syscall with explicit debug
local ok_s6, rv_s6 = pcall(function()
    return mk(97)(uint64(28), uint64(2), uint64(0))
end)
local fd6 = ok_s6 and N(rv_s6) or -1
print(string.format("ipv6_fd=%d", fd6))
if fd6 >= 0 then
    wd(N(buf), 1)
    -- IPV6_V6ONLY=27, IPPROTO_IPV6=41
    local ok6, rv6 = pcall(function()
        return mk(105)(uint64(fd6), uint64(41), uint64(27), buf, uint64(4))
    end)
    print(string.format("v6only_5args=%d", ok6 and N(rv6) or -999))

    -- Try with level=0 (some systems accept this)
    wd(N(buf), 1)
    local ok7, rv7 = pcall(function()
        return mk(105)(uint64(fd6), uint64(0), uint64(27), buf, uint64(4))
    end)
    print(string.format("v6only_lvl0=%d", ok7 and N(rv7) or -999))

    pcall(function() mk(6)(uint64(fd6)) end)
end

print("=== 396d COMPLETE ===")
