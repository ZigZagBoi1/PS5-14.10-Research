-- CRASH_CLASS: MODERATE
-- PROBE 95b: Distinguish AIO request-ID publication from one-byte I/O completion.
-- Run only after the loader answers a ping. No indefinite blocking read is used.

print("=== PROBE 95b: AIO ONE-BYTE COMPLETION ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end

local function sc(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local function wd(p, v) memory.write_dword(p, v) end
local function wq(p, v) memory.write_qword(p, uint64(v)) end
local function rd(p) return to_num(memory.read_dword(p)) end

local pid = to_num(sc(20)())
print("pid=" .. pid)

local ok_init, init_rv = pcall(function()
    return sc(670)(uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("aio_init ok=" .. tostring(ok_init) .. " ret=" .. tostring(init_rv))

local sv = memory.alloc(8)
wd(sv, 0xFFFFFFFF); wd(sv + 4, 0xFFFFFFFF)
local ok_pair, pair_rv = pcall(function()
    return sc(135)(uint64(1), uint64(1), uint64(0), uint64(sv))
end)
local read_fd, write_fd = rd(sv), rd(sv + 4)
print("socketpair ok=" .. tostring(ok_pair) .. " ret=" .. tostring(pair_rv) ..
      " read_fd=" .. read_fd .. " write_fd=" .. write_fd)
if not ok_pair or to_num(pair_rv) ~= 0 or read_fd < 0 or read_fd > 10000 or
   write_fd < 0 or write_fd > 10000 then
    print("SETUP FAILED; no AIO request issued")
    return
end

local recv_buf = memory.alloc(8)
local send_buf = memory.alloc(8)
wd(recv_buf, 0xDEADBEEF)
wd(send_buf, 0x0000005A)  -- 'Z'

local req = memory.alloc(0x30)
for i = 0, 0x2C, 4 do wd(req + i, 0) end
wq(req + 0x00, 0)
wq(req + 0x08, 1)
wq(req + 0x10, recv_buf)
wq(req + 0x18, 0)
wd(req + 0x20, read_fd)

local ids = memory.alloc(8)
wd(ids, 0xDEADDEAD)
local ok_submit, submit_rv = pcall(function()
    return sc(669)(uint64(1), uint64(req), uint64(1), uint64(1), uint64(ids))
end)
local id = rd(ids)
print("submit_read ok=" .. tostring(ok_submit) .. " ret=" .. tostring(submit_rv) ..
      " id=0x" .. string.format("%08X", id))
if not ok_submit or to_num(submit_rv) ~= 0 or id == 0xDEADDEAD then
    print("SUBMIT FAILED; skipping poll")
    pcall(function() sc(6)(uint64(read_fd)) end)
    pcall(function() sc(6)(uint64(write_fd)) end)
    return
end

local ok_write, write_rv = pcall(function()
    return sc(4)(uint64(write_fd), uint64(send_buf), uint64(1))
end)
print("peer_write ok=" .. tostring(ok_write) .. " ret=" .. tostring(write_rv))

local states = memory.alloc(8)
local delay = memory.alloc(16)
wq(delay, 0); wq(delay + 8, 10000000) -- 10 ms
local last_state = -1
for i = 1, 20 do
    wd(states, 0xDEADDEAD)
    local ok_poll, poll_rv = pcall(function()
        return sc(664)(uint64(ids), uint64(1), uint64(states))
    end)
    last_state = rd(states)
    print("poll " .. i .. " ok=" .. tostring(ok_poll) ..
          " ret=" .. tostring(poll_rv) .. " state=0x" .. string.format("%08X", last_state))
    if not ok_poll or last_state ~= 1 then break end
    pcall(function() sc(240)(uint64(delay), uint64(0)) end)
end

local value = rd(recv_buf)
print("read_buffer=0x" .. string.format("%08X", value) ..
      " byte=0x" .. string.format("%02X", value % 256))
if value % 256 == 0x5A and last_state % 0x10000 == 3 then
    print("CONFIRMED: one-byte AIO read completed")
else
    print("NOT CONFIRMED: ID publication did not establish completed I/O")
end

local delete_result = memory.alloc(8)
wd(delete_result, 0xDEADDEAD)
local ok_delete, delete_rv = pcall(function()
    return sc(662)(uint64(ids), uint64(1), uint64(delete_result))
end)
print("delete ok=" .. tostring(ok_delete) .. " ret=" .. tostring(delete_rv) ..
      " result=0x" .. string.format("%08X", rd(delete_result)))
pcall(function() sc(6)(uint64(read_fd)) end)
pcall(function() sc(6)(uint64(write_fd)) end)
print("=== PROBE 95b COMPLETE ===")
