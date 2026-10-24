-- CRASH_CLASS: MODERATE
-- PROBE 491a: make the loader's thread helper run a syscall in a second thread
-- /savedata0/thread.lua: thread:new(obj, ...) pushes either push_syscall_with_ret
-- (when obj.syscall_no exists) or push_fcall_with_ret, wraps the chain in a
-- longjmp entry spawned by Thrd_create, and run(true) leaves it asynchronous.
-- make_syscall() returns exactly that shape, so a second OS thread can issue
-- 662. This probe only checks that the thread runs and returns a value.
print("=== PROBE 491a: syscall on a loader thread ===")
io.stdout:setvbuf("no")
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
local data = memory.alloc(0x2000)
local out  = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local res  = memory.alloc(0x400)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
local id = to_num(memory.read_dword(out))
print(string.format("[0] create ret=%s id=%d", ok and tostring(to_num(rv)) or "-", id))
pcall(function() memory.write_dword(ids, id) end)
pcall(function() memory.write_dword(res, 0x77777777) end)
print("[1] building thread chain for 664 poll")
local sc = make_syscall(664)
local built, t = pcall(function() return thread.new(sc, uint64(ids), uint64(1), uint64(res)) end)
print("[1] thread.new ok=" .. tostring(built))
if built then
  local ran, err = pcall(function() return t:run(true) end)
  print("[2] run(async) ok=" .. tostring(ran) .. " err=" .. tostring(err))
  local spins = 0
  while to_num(memory.read_dword(res)) == 0x77777777 and spins < 2000000 do spins = spins + 1 end
  print(string.format("[3] res=%#x spins=%d", to_num(memory.read_dword(res)), spins))
  local jok, jerr = pcall(function() return t:join() end)
  print("[4] join ok=" .. tostring(jok) .. " err=" .. tostring(jerr))
end
print("=== PROBE 491a COMPLETE ===")
