-- CRASH_CLASS: LOW
-- PROBE 1231b: aio cmd=2 with FreeBSD MSG_DONTWAIT (0x80, not the Linux 0x40 that blocked 1231a).
print("=== PROBE 1231b: aio write source copy ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rb(a) local ok,v=pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return -1 end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return rv end
print(string.format("[0] pid=%d", N(mk(20)())))
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
call("socketpair", function() return mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local fd0, fd1 = rd(sv), rd(sv+4)
print(string.format("    fds %d %d", fd0, fd1))
if fd0 <= 0 then print("=== DONE ===") return end
local src = memory.alloc(0x100)
for i = 0, 15 do pcall(function() memory.write_byte(src + i, 0x40 + i) end) end
local res = memory.alloc(0x20) wd(res, 0xAAAAAAAA)
local reqs = memory.alloc(0x28)
for i=0,0x24,4 do wd(reqs+i,0) end
local sa = N(uint64(src))
wd(reqs + 0x08, 16)
wd(reqs + 0x10, sa % 4294967296) wd(reqs + 0x14, math.floor(sa/4294967296))
wd(reqs + 0x20, fd0)
local ids = memory.alloc(16) wd(ids,0)
local st = memory.alloc(16)
print("[1] submit cmd=2 (write) from the marker buffer to fd0")
call("669 cmd=2", function() return mk(669)(uint64(0x1002),uint64(reqs),uint64(1),uint64(1),uint64(ids)) end)
print(string.format("    id=0x%08X", rd(ids)))
print("[2] poll states a few times")
for k = 1, 4 do
  call("664", function() return mk(664)(uint64(ids),uint64(1),uint64(st)) end)
  print(string.format("    state=0x%X result=0x%X", rd(st), rd(res)))
  if rd(st) == 3 or rd(st) == 4 then break end
end
print("[3] receive on the peer with MSG_DONTWAIT=0x80")
local rbuf = memory.alloc(0x100)
call("recvfrom", function() return mk(29)(uint64(fd1),uint64(rbuf),uint64(32),uint64(0x80),uint64(0),uint64(0)) end)
local s = {}
for i=0,15 do s[#s+1] = string.format("%02X", rb(rbuf+i)) end
print("    peer bytes: " .. table.concat(s, " "))
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")