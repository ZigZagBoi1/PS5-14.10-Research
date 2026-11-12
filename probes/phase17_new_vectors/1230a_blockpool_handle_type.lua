-- CRASH_CLASS: LOW
-- PROBE 1230a: is 653 blockpool_open returning a file descriptor? fstat/read/close decide it.
print("=== PROBE 1230a: blockpool handle type ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function call(tag, fn) local ok, rv = pcall(fn) if not ok then print("  ["..tag.."] PCALL-FAIL") return nil end local h,l = hilo(rv) print(string.format("  [%s] ret=0x%08X_%08X err=%s", tag, h, l, ES())) return rv end
print(string.format("[0] pid=%d", N(mk(20)())))
local h = N(mk(653)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[1] 653 = 0x%X (%d) err=%s", h, h, ES()))
if h < 0 or h > 0x1000 then print("no handle"); print("=== DONE ===") return end
local sb = memory.alloc(0x100)
for i=0,0xFC,4 do wd(sb+i,0) end
call("fstat(handle)", function() return mk(189)(uint64(h),uint64(sb),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    stat mode=0x%X links=%d size=0x%X", rd(sb+4), rd(sb+6), rd(sb+0x20)))
local rbuf = memory.alloc(0x40)
call("read(handle,16)", function() return mk(3)(uint64(h),uint64(rbuf),uint64(16),uint64(0),uint64(0),uint64(0)) end)
call("ioctl FIONBIO", function() return mk(54)(uint64(h),uint64(0x8004667E),uint64(sb),uint64(0),uint64(0),uint64(0)) end)
print("[2] mmap with the handle before closing it")
for _, sh in ipairs({{3,1},{3,2},{3,0x1002}}) do
  local rv = N(mk(477)(uint64(0),uint64(0x10000),uint64(sh[1]),uint64(sh[2]),uint64(h),uint64(0)))
  print(string.format("    prot=0x%X flags=0x%X -> 0x%X err=%s", sh[1], sh[2], rv, ES()))
end
call("close(handle)", function() return mk(6)(uint64(h),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) end)
print(string.format("[Z] pid_end=%d", N(mk(20)())))
print("=== DONE ===")