-- 14.10 Probe 40: TCP connect-back to attacker machine
-- Connects to the PC running tools/tcp_fuzz_server.py and holds the
-- connection open while the PC replies with malformed TCP segments.
-- The kernel's tcp_input()/tcp_dooptions() parses attacker-controlled
-- bytes in kernel context — outside the syscall sandbox.
--
-- >>> EDIT PC_IP to the machine running tcp_fuzz_server.py <<<

local PC_IP = {10, 0, 0, 50}   -- <-- CHANGE ME
local PC_PORT = 31337

print("=== 40: TCP CONNECT-BACK ===")
print("fw: " .. tostring(FW_VERSION))
print("pid: " .. syscall.getpid():tonumber())
print("target: " .. table.concat(PC_IP, ".") .. ":" .. PC_PORT)

syscall.resolve({
    sc_socket = 97,
    sc_connect = 98,
    sc_close = 6,
    sc_sendmsg = 28,
    sc_recvmsg = 27,
    sc_poll = 209,
    sc_getsockopt = 118,
})

local MSG_DONTWAIT = 0x80

local sa = memory.alloc(16)
for i = 0, 15 do memory.write_byte(sa + i, 0) end
memory.write_byte(sa + 0, 16)
memory.write_byte(sa + 1, 2)
memory.write_byte(sa + 2, math.floor(PC_PORT / 256))
memory.write_byte(sa + 3, PC_PORT % 256)
for i = 1, 4 do memory.write_byte(sa + 3 + i, PC_IP[i]) end

local ok_s, rv_s = pcall(function() return syscall.sc_socket(2, 1, 6) end)
local fd = ok_s and rv_s:tonumber() or -1
print("socket: fd=" .. fd)
if fd < 0 then print("=== 40 DONE (no socket) ===") return end

print("connecting (may block briefly)...")
local ok_c, rv_c = pcall(function() return syscall.sc_connect(fd, sa, 16) end)
local crv = ok_c and rv_c:tonumber() or -999
print("connect: rv=" .. crv)
if crv ~= 0 then
    print("connect failed — is tcp_fuzz_server.py running and PC_IP right?")
    print("=== 40 DONE (no connect) ===")
    return
end
print("CONNECTED — entering receive loop")

-- Announce ourselves so the fuzz server knows the 4-tuple is live
local hello = memory.alloc(4)
memory.write_byte(hello, 0x50)  -- "PS5!"
memory.write_byte(hello + 1, 0x53)
memory.write_byte(hello + 2, 0x35)
memory.write_byte(hello + 3, 0x21)
local iov = memory.alloc(16)
memory.write_qword(iov, hello)
memory.write_qword(iov + 8, 4)
local mh = memory.alloc(64)
for i = 0, 63, 8 do memory.write_qword(mh + i, 0) end
memory.write_qword(mh + 16, iov)
memory.write_qword(mh + 24, 1)
pcall(function() return syscall.sc_sendmsg(fd, mh, MSG_DONTWAIT) end)

-- Receive loop: ~60s. Report everything; SO_ERROR checked each pass.
local rbuf = memory.alloc(2048)
local riov = memory.alloc(16)
local rmh = memory.alloc(64)
local pollfd = memory.alloc(8)
local errbuf = memory.alloc(4)
local errlen = memory.alloc(4)

for iter = 1, 600 do
    memory.write_dword(pollfd, fd)
    memory.write_word(pollfd + 4, 0x0001)  -- POLLIN
    memory.write_word(pollfd + 6, 0)
    local ok_p, rv_p = pcall(function() return syscall.sc_poll(pollfd, 1, 100) end)
    local rev = memory.read_word(pollfd + 6):tonumber()

    if rev > 0 then
        memory.write_qword(riov, rbuf)
        memory.write_qword(riov + 8, 2048)
        for i = 0, 63, 8 do memory.write_qword(rmh + i, 0) end
        memory.write_qword(rmh + 16, riov)
        memory.write_qword(rmh + 24, 1)
        local ok_r, rv_r = pcall(function() return syscall.sc_recvmsg(fd, rmh, MSG_DONTWAIT) end)
        local n = ok_r and rv_r:tonumber() or -999
        if n == 0 then
            print("iter " .. iter .. ": EOF (peer closed)")
            break
        elseif n > 0 then
            local hex = ""
            for i = 0, math.min(n - 1, 31) do
                hex = hex .. string.format("%02x", memory.read_byte(rbuf + i):tonumber())
            end
            print("iter " .. iter .. ": recv=" .. n .. " flags=0x" ..
                  string.format("%x", memory.read_dword(rmh + 32):tonumber()) ..
                  " data=" .. hex)
        end
        -- msg_flags check: MSG_OOB (0x1) would mean urgent data arrived
    end

    memory.write_dword(errlen, 4)
    pcall(function() syscall.sc_getsockopt(fd, 0xFFFF, 0x1007, errbuf, errlen) end) -- SO_ERROR
    local serr = memory.read_dword(errbuf):tonumber()
    if serr ~= 0 then
        print("iter " .. iter .. ": SO_ERROR=" .. serr)
        break
    end
end

pcall(function() syscall.sc_close(fd) end)
print("NOTE: a console hang/reboot during the loop = malformed TCP hit a")
print("kernel path. Check the PC-side log for which variant was in flight.")
print("=== 40 DONE ===")
