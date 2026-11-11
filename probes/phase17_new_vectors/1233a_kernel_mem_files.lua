-- CRASH_CLASS: LOW
-- PROBE 1233a: the classic kernel-memory files. If any of /proc/kcore, /dev/kmem, /dev/mem opens,
-- a reader exists with no exploit at all. Cheap, no risk.
print("=== PROBE 1233a: kernel memory files ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function rb(a) local ok,v=pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return rv end
print(string.format("[0] pid=%d", N(mk(20)())))
local paths = {"/proc/kcore","/proc/kallsyms","/proc/self/mem","/dev/kmem","/dev/mem","/dev/mem0","/dev/physmem","/proc/self/maps"}
local buf = memory.alloc(0x200)
local rbuf = memory.alloc(0x100)
local O_RDONLY = 0
for i = 1, #paths do
  local p = paths[i]
  for j = 1, #p do pcall(function() memory.write_byte(buf + j - 1, string.byte(p, j)) end) end
  pcall(function() memory.write_byte(buf + #p, 0) end)
  local fd = N(mk(5)(uint64(buf),uint64(O_RDONLY),uint64(0),uint64(0),uint64(0),uint64(0)))
  print(string.format("  open(%s) = %d err=%s", p, fd, ES()))
  if fd > 0 and fd < 0x1000 then
    local rv = N(mk(3)(uint64(fd),uint64(rbuf),uint64(16),uint64(0),uint64(0),uint64(0)))
    local s = {}
    for k=0,15 do s[#s+1] = string.format("%02X", rb(rbuf+k)) end
    print(string.format("     read16 = %d bytes: %s", rv, table.concat(s, " ")))
    pcall(function() mk(6)(uint64(fd),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  end
end
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")