-- CRASH_CLASS: LOW
-- PROBE 1150a: what errno does a devfs open() actually return on 14.10?
-- 1073a learned that the 12 nodes which list in /dev refuse open(), but the wire only carries
-- -1: the loader normalises the failure, so EACCES and ENXIO look identical. Those two answers
-- mean opposite things. EACCES is a credential gate (the bit-62 hypothesis) and worth attacking;
-- ENXIO/ENODEV means no device is attached to the node and the gate does not exist at all.
-- get_error_string() reads TLS errno through libc __error()+strerror(), so if the syscall path
-- maintains errno we get the kernel's own answer instead of a guess. The controls decide whether
-- the readout is trustworthy: /dev/zero must open, a nonsense name must say ENOENT.
print("=== PROBE 1150a: DEVFS OPEN ERRNO ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end

local sc_open=mk(5); local sc_close=mk(6)
local PB=0x100
local pa=as_addr(memory.alloc(PB))
local function setpath(p) for i=0,PB/4-1 do wd(pa+i*4,0) end for i=1,#p do wd(pa+i-1,p:byte(i)) end end

local function errstr()
  local ok,r=pcall(get_error_string)
  if ok then return tostring(r) end
  return "<err:"..tostring(r):sub(1,40)..">"
end

local seen={}
local function try(path)
  if seen[path] then return end
  seen[path]=true
  setpath(path)
  local ok,rv=pcall(function() return sc_open(uint64(pa),uint64(0)) end)
  local r=ok and to_num(rv) or -999
  if ok and r>=0 and r<0x10000 then pcall(function() sc_close(uint64(r)) end) end
  print(string.format("[%s] rv=%s hex=%s errno=%s", path, tostring(r), string.format("0x%X", r%0x100000000), errstr()))
end

-- controls first: if these two do not read as open/ENOENT, the errno readout is not usable
try("/dev/zero")
try("/dev/no_such_node_1150a")

-- the twelve that list and refuse (docs/DEVFS_NAMESPACE_14_10.md)
local names={"a53mm","a53mmsys","dbggc","sbl_srv","encdec","fttrm","duid","mp3","acm","lvd3","hmd2_image","hmd2_slam_trace"}
for _,n in ipairs(names) do try("/dev/"..n) end

print("")
print("=== DONE ===")