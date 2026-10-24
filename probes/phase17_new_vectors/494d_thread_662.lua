-- CRASH_CLASS: HIGH
-- PROBE 494d: 662 issued from the helper's thread, observed in parent memory
-- 494c proved the helper starts and joins. The thread's print goes only to
-- stdout, so the observable is the syscall's own result page: the body calls
-- 662 on an id the parent created and polled, and the parent watches the status
-- word the kernel writes into its own mapped page.
print("=== PROBE 494d: 662 from a loader thread ===")
io.stdout:setvbuf("no")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function addrnum(v)
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return to_num(v)
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
local sc669 = make_syscall(669)
local sc664 = make_syscall(664)
for off = 0, 0x2000 - 1, 4 do pcall(function() memory.write_dword(data + off, 0) end) end
local function create()
  for off = 0, 0x100 - 1, 4 do pcall(function() memory.write_dword(out + off, 0) end) end
  local ok, rv = pcall(function() return sc669(uint64(1), uint64(data), uint64(1), uint64(1), uint64(out)) end)
  if not ok then return nil end
  return to_num(memory.read_dword(out))
end
local function poll(id)
  pcall(function() memory.write_dword(ids, id) end)
  local ok, rv = pcall(function() return sc664(uint64(ids), uint64(1), uint64(res)) end)
  return ok, ok and to_num(rv) or -999
end

local body = "local t = {}\n" ..
             "for k,v in pairs(syscall.pipe) do t[k] = v end\n" ..
             "t.syscall_no = 662\n" ..
             "setmetatable(t, getmetatable(syscall.pipe))\n" ..
             string.format("pcall(function() t(%d, 1, %d) end)\n", addrnum(ids), addrnum(res))

print("[A] body alone on a polled id")
local idA = create()
local okp, prv = poll(idA)
print(string.format("    id=%s poll_ret=%d", tostring(idA), prv))
if idA then
  pcall(function() memory.write_dword(ids, idA) end)
  for off = 0, 0x40 - 1, 4 do pcall(function() memory.write_dword(res + off, 0x77777777) end) end
  local ok, thr = pcall(run_lua_code_in_new_thread, body, { async = true })
  print("    helper ok=" .. tostring(ok) .. " thr=" .. type(thr))
  if ok and type(thr) == "table" then
    local spins = 0
    while to_num(memory.read_dword(res)) == 0x77777777 and spins < 4000000 do spins = spins + 1 end
    print(string.format("    res0=%#x spins=%d", to_num(memory.read_dword(res)), spins))
    local jok = pcall(function() return thr:join() end)
    print("    join ok=" .. tostring(jok) .. " res0=" .. string.format("%#x", to_num(memory.read_dword(res))))
  end
end
print("=== PROBE 494d COMPLETE ===")
