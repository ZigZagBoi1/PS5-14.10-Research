-- CRASH_CLASS: LOW
-- PROBE 1243a: syscall 587 - argument order and the grant condition
-- Static: 587 has narg 2, thunk 0x265e00 -> body 0x4e1a70. The 55e record (ret 0, only
-- +0x0C = 0x20000000) is the DENIED path of the record builder: the granted path at
-- 0x4e1b75 memcpy's cred+0x58..+0xDF into the caller buffer, the denied path writes only a
-- tag dword at +0x00 (and only for five recognised tags) plus cred+0x60 & 0x7000000000000000
-- at +0x08. Which argument is the buffer and which is the size/pid was never measured, so
-- this probe sweeps both orders and three second-argument values and dumps what lands.
print("=== PROBE 1243a: syscall 587 shape ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function hi(v) if type(v)=="table" and v.h then return v.h end return 0 end
local function lo(v) return N(v) end

local pid = N(mk(20)())
print(string.format("[0] pid=%d", pid))
local buf = memory.alloc(0x100)
local function clr()
  for i=0,0xFC,4 do pcall(function() memory.write_dword(buf+i,0xCDCDCDCD) end) end
end
local function dump(tag)
  local s = ""
  for i=0,0x2C,4 do s = s .. string.format(" %08X", rd(buf+i)) end
  local changed, kq = 0, 0
  for i=0,0xFC,4 do if rd(buf+i) ~= 0xCDCDCDCD then changed = changed + 1 end end
  for i=0,0xF8,8 do
    local v = rq(buf+i)
    if v then local h = hi(v)
      if h >= 0xFFFF8000 then kq = kq + 1 end
    end
  end
  print(string.format("     bytes changed=%d/64 kernel-range qwords=%d", changed, kq))
  print("     first 0x30:" .. s)
end
local function call587(tag, a1, a2)
  clr()
  print(string.format("  -- %s: 587(0x%X, 0x%X)", tag, a1, a2))
  local ok, rv = pcall(function() return mk(587)(uint64(a1), uint64(a2)) end)
  if not ok then print("     PCALL-FAIL") return end
  local r = hi(rv) * 4294967296.0 + lo(rv)
  local err = ""
  if r == -1 or (type(rv)=="table" and rv.h == 0xFFFFFFFF and rv.l == 0xFFFFFFFF) then err = " err=" .. ES() end
  print(string.format("     ret=0x%08X_%08X%s", hi(rv), lo(rv), err))
  dump(tag)
end

print("[A] buffer first, size second")
call587("buf,0x88", N(buf), 0x88)
call587("buf,0x100", N(buf), 0x100)
call587("buf,0", N(buf), 0)
call587("buf,pid", N(buf), pid)
print("[B] zero first, buffer second")
call587("0,buf", 0, N(buf))
call587("pid,buf", pid, N(buf))
call587("0x88,buf", 0x88, N(buf))
print("[C] baseline, both zero")
call587("0,0", 0, 0)
print("=== DONE ===")