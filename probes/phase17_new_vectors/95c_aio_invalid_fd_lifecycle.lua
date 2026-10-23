-- CRASH_CLASS: MODERATE
-- PROBE 95c: Check whether an invalid-fd AIO ID remains usable or stale.

print("=== PROBE 95c: AIO INVALID-FD LIFECYCLE ===")

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

print("pid=" .. to_num(sc(20)()))
local ok_init, init_rv = pcall(function()
    return sc(670)(uint64(0), uint64(0), uint64(0), uint64(0))
end)
print("aio_init ok=" .. tostring(ok_init) .. " ret=" .. tostring(init_rv))

local req = memory.alloc(0x30)
local buf = memory.alloc(8)
local ids = memory.alloc(8)
for i = 0, 0x2C, 4 do wd(req + i, 0) end
wd(buf, 0xDEADBEEF)
wq(req + 0x00, 0)
wq(req + 0x08, 1)
wq(req + 0x10, buf)
wq(req + 0x18, 0)
wd(req + 0x20, 0x7FFFFFFF)
wd(ids, 0xDEADDEAD)

local ok_submit, submit_rv = pcall(function()
    return sc(669)(uint64(1), uint64(req), uint64(1), uint64(1), uint64(ids))
end)
local id = rd(ids)
print("invalid_fd_submit ok=" .. tostring(ok_submit) .. " ret=" .. tostring(submit_rv) ..
      " id=0x" .. string.format("%08X", id))
if not ok_submit or to_num(submit_rv) ~= 0 or id == 0xDEADDEAD then
    print("NO PUBLISHED ID; stopping")
    return
end

local states = memory.alloc(8)
for i = 1, 3 do
    wd(states, 0xDEADDEAD)
    local ok, rv = pcall(function()
        return sc(664)(uint64(ids), uint64(1), uint64(states))
    end)
    print("poll " .. i .. " ok=" .. tostring(ok) .. " ret=" .. tostring(rv) ..
          " state=0x" .. string.format("%08X", rd(states)))
end

local cancel_result = memory.alloc(8)
wd(cancel_result, 0xDEADDEAD)
local ok_cancel, cancel_rv = pcall(function()
    return sc(666)(uint64(ids), uint64(1), uint64(cancel_result))
end)
print("cancel ok=" .. tostring(ok_cancel) .. " ret=" .. tostring(cancel_rv) ..
      " result=0x" .. string.format("%08X", rd(cancel_result)))

local delete_result = memory.alloc(8)
wd(delete_result, 0xDEADDEAD)
local ok_delete, delete_rv = pcall(function()
    return sc(662)(uint64(ids), uint64(1), uint64(delete_result))
end)
print("delete ok=" .. tostring(ok_delete) .. " ret=" .. tostring(delete_rv) ..
      " result=0x" .. string.format("%08X", rd(delete_result)))

wd(states, 0xDEADDEAD)
local ok_post, post_rv = pcall(function()
    return sc(664)(uint64(ids), uint64(1), uint64(states))
end)
print("post_delete_poll ok=" .. tostring(ok_post) .. " ret=" .. tostring(post_rv) ..
      " state=0x" .. string.format("%08X", rd(states)))
print("=== PROBE 95c COMPLETE ===")
