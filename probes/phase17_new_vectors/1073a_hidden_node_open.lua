-- CRASH_CLASS: LOW
-- PROBE 1073a: open() only - no reads, so nothing can block. The complete 1070a listing (78
-- entries) contains no mem/kmem/physmem/msr/cpuctl/pci node, but devfs can hide a node from
-- readdir while leaving lookup intact, so absence from the listing is not proof of absence.
-- This is a membership test over the names FreeBSD would give a physical-memory or MSR
-- interface, plus a control set that the listing already proves exists.
--
-- open() alone cannot answer membership: this loader normalises every failure to -1, so a
-- present-but-privileged node and an absent one look identical. The capture proves it -
-- notification1 and ctty are both in the 78-entry listing and both refuse open(). So each name
-- is also passed to stat(188), which separates "the vnode does not exist" from "the open was
-- refused", and each open is tried with O_RDONLY|O_NONBLOCK and then O_RDWR.
print("=== PROBE 1073a: HIDDEN DEVFS NODE MEMBERSHIP ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end

local sc_sig=mk(416); local sc_open=mk(5); local sc_close=mk(6); local sc_pid=mk(20); local sc_stat=mk(188)
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local okS,vS=pcall(function() return sc_sig(uint64(12),uint64(aa),uint64(0)) end)
print(string.format("[S] sigsys-ignore ok=%s rv=%s pid=%s", tostring(okS), okS and tostring(to_num(vS)) or "-",
  tostring(to_num(select(2,pcall(function() return sc_pid() end))))))
print("")

local PB=0x100
local pa=as_addr(memory.alloc(PB))
local function setpath(p) for i=0,PB/4-1 do wd(pa+i*4,0) end for i=1,#p do wd(pa+i-1,p:byte(i)) end end

local names={
  "mem","kmem","physmem","dmem0","null","zero",
  "gc","gce","dce","dcei","ajm","ajmi","gic","usbctl","usb","xhci0",
  "bpf","bpf0","pf","pflog0","divert0","enc0","tap0","tun0",
  "audit","kaudit","console","ctty","klog","ttyv0","ttyu0","uart",
  "ada0","da0","cd0","nvme0","nvme0ns1","mmcsd0","md0",
  "pci","pcib0","smb0","iic0","spi0","gpio","cpuctl","msr",
  "notification0","notification1","camera","dmass","sceKernel","scevfs","scezlib","sce_zlib",
}
local stbuf=memory.alloc(0x180); local st=as_addr(stbuf)
local found={}; local present={}
for _,d in ipairs(names) do
  setpath("/dev/"..d)
  local okf,fdv=pcall(function() return sc_open(uint64(pa),uint64(4),uint64(0)) end)
  local fd = okf and to_num(fdv) or -999
  local ro = "-"
  if fd>=0 then
    ro = tostring(fd)
    pcall(function() sc_close(uint64(fd)) end)
  end
  local ok2,f2=pcall(function() return sc_open(uint64(pa),uint64(2),uint64(0)) end)
  local fdv2 = ok2 and to_num(f2) or -999
  local rw = "-"
  if fdv2>=0 then
    rw = tostring(fdv2)
    pcall(function() sc_close(uint64(fdv2)) end)
  end
  for i=0,0x17C,4 do wd(st+i,0) end
  local oks,rv=pcall(function() return sc_stat(uint64(pa),uint64(st)) end)
  local sr = oks and to_num(rv) or -999
  if sr==0 then present[#present+1]=d end
  if ro~="-" or rw~="-" then found[#found+1]=d end
  print(string.format("[O] %-14s ro=%-4s rw=%-4s stat=%d", d, ro, rw, sr))
end
print("")
print(string.format("[F] openable: %d/%d -> %s", #found, #names, table.concat(found,",")))
print(string.format("[F] stat-present: %d/%d -> %s", #present, #names, table.concat(present,",")))
print("=== DONE 1073a ===")
