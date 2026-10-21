-- CRASH_CLASS: HIGH
-- PROBE 266a: aio_read with a descriptor that really exists
--
-- Every previous attempt at 661 handed it zeros and the process died, which
-- cannot separate "no handler" from "handler dereferenced nothing". 261a has now
-- opened real descriptors from this process, so this builds a full FreeBSD
-- aiocb for /dev/zero - fildes, offset, buffer, nbytes, and a sigevent that is
-- notify-on-completion rather than a signal - and calls 661 once per shape.
--
--   A  open /dev/zero, map 0x4000 bytes to read into
--   B  661(aiocb) with notify = SIGEV_NONE (0), then the same with SIGEV_KEVENT
--   C  662-664 on the aiocb in case they are aio_error/return/cancel
--
-- A kill names its own row because each row prints the pid.

print("=== PROBE 266a: aio_read on a real fd ===")
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
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function n(v)
    local t = to_num(v)
    if t > 0x7FFFFFFFFFFFFFFF then t = t - 18446744073709551616 end
    return t
end
local function call(num, a, b, c, d)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a or uint64(0), b or uint64(0), c or uint64(0), d or uint64(0)) end)
    if not ok then return nil end
    return rv
end
local function path(p)
    local b = memory.alloc(0x100)
    pcall(function() memory.write_qword(b, 0) end)
    for i = 1, #p do
        local ch = string.byte(p, i)
        pcall(function() memory.write_byte(b + i - 1, ch) end)
    end
    return b
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return 0
end
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(a, v) end)
    return ok
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok and v ~= nil then return string.format("0x%08X_%08X", v.h, v.l) end
    return "?"
end

print("[0] pid=" .. tostring(pid()))

print("")
print("[A] resources")
local zfd = n(call(5, uint64(path("/dev/zero")), uint64(0), uint64(0), uint64(0)))
print("    open(/dev/zero) -> " .. tostring(zfd))
local buf = n(call(477, uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
print("    mmap 0x4000 -> " .. tostring(buf))
local acb = memory.alloc(0x100)
pcall(function() for o = 0, 0xF8, 8 do memory.write_qword(acb + o, 0) end end)

local function build(notify, lio)
    pcall(function() for o = 0, 0xF8, 8 do memory.write_qword(acb + o, 0) end end)
    wd(acb + 0, zfd)                    -- aio_fildes
    wq(acb + 8, 0)                      -- aio_offset
    wq(acb + 16, buf)                   -- aio_buf
    wq(acb + 24, 0x1000)                -- aio_nbytes
    wd(acb + 32, notify)                -- sigev_notify
    wd(acb + 36, 0)                     -- sigev_signo
    wq(acb + 40, 0)                     -- sigev_value
    wq(acb + 48, 0)                     -- sigev_notify_function
    wq(acb + 56, 0)                     -- sigev_notify_attributes
    wd(acb + 64, lio)                   -- aio_lio_opcode
    wd(acb + 68, 0)                     -- aio_reqprio
    wq(acb + 72, 0)                     -- __next_prio
end

print("")
print("[B] 661(aiocb)")
build(0, 31)
print("    notify=0 lio=31: 661 -> " .. raw(call(661, uint64(acb), uint64(0), uint64(0), uint64(0))) .. " pid=" .. tostring(pid()))
print("    buffer[0]=" .. rq(buf))
build(1, 31)
print("    notify=1 lio=31: 661 -> " .. raw(call(661, uint64(acb), uint64(0), uint64(0), uint64(0))) .. " pid=" .. tostring(pid()))

print("")
print("[C] 662-664 on the same aiocb")
for _, num in ipairs({ 662, 663, 664 }) do
    local rv = call(num, uint64(acb), uint64(0), uint64(0), uint64(0))
    print(string.format("    %d(aiocb) -> %s  pid=%s", num, raw(rv), tostring(pid())))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 266a COMPLETE ===")
