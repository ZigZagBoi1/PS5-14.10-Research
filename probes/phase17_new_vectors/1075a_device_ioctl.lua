-- CRASH_CLASS: MODERATE
-- PROBE 1075a: ioctl on the newly enumerated device nodes. This extends probe 43n rather than
-- opening a new surface: 43n already opened /dev/hid (fd 23) and issued ioctl(54) on that fd,
-- recording Sony error 0x80740004 for every code (docs/PROBE_INDEX.md:115). Many earlier ioctl
-- probes used the loader's own tty, so "ioctl was never tested on a device" is false; what was
-- never done is a sweep across the thirteen nodes that this devfs actually exposes
-- (docs/DEVFS_NAMESPACE_14_10.md), including the ones whose read() returns -1.
--
-- Two measurement rules this probe follows:
--   rv != -1 is not success. 22 is EINVAL and also the fd number camera returned, so EINVAL is
--   counted separately instead of being folded into a "hit" total.
--   A write-shaped request cannot be refused by a read-only descriptor and be read as
--   "unsupported", so every device is tried once O_RDONLY and once O_RDWR.
print("=== PROBE 1075a: DEVICE IOCTL ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h,q.l end local n=to_num(q) return math.floor(n/4294967296), n%4294967296 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rqw(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end

local sc_open=mk(5)  -- open(path, flags, mode)
local sc_ioctl=mk(54)
local sc_close=mk(6)

local NB=0x400
local buf=memory.alloc(NB); local ba=as_addr(buf)
local sbuf=memory.alloc(0x40); local sa=as_addr(sbuf)
-- 0xCDCDCDCDCDCDCDCD as a number literal rounds above 2^53 and stores CDCDCDCD_CDCDD000, so the
-- sentinel is written as two dwords instead of one qword.
local function fill() for i=0,NB/8-1 do wd(ba+i*8,0xCDCDCDCD); wd(ba+i*8+4,0xCDCDCDCD) end end

-- notification0 last: its read() blocks even with O_NONBLOCK, so its ioctl may too
local devs={"null","zero","sce_zlib","dmem0","dmem1","dmem2","gc","dce","ajm","ajmi","gic","usbctl","usb","camera","notification0"}
local cmds={}
for c=0,9 do cmds[#cmds+1]=c end
local pre={
  -- codes that answered on a real device fd in earlier probes (gamic/gc/generic tty-shaped)
  0xC0104701, 0x80888123, 0xC0048125, 0x4004667A, 0x20006601,
  -- one code per direction bit and one with no size, to separate "rejected by direction" from
  -- "rejected by the driver"
  0x40080000,0x40080001,0x40046400,0x80080000,0x80080001,0x80046400,0xC0080000,0xC0080001,
  0xC0200000,0xC0200001,0x80000000,0xC0000000,0x40000000,0x20000000,0xC0180000,0xC0100000}
for _,c in ipairs(pre) do cmds[#cmds+1]=c end

local opened=0; local asswered=0; local einval=0
for _,name in ipairs(devs) do
  local path="/dev/"..name
  local pb=memory.alloc(#path+1); local pa=as_addr(pb)
  for i=1,#path do wd(pa+i-1,path:byte(i)) end
  wd(pa+#path,0)
  for _,mode in ipairs({4,2}) do -- O_RDONLY|O_NONBLOCK, then O_RDWR
    local ok,f=pcall(function() return sc_open(uint64(pa),uint64(mode),uint64(0)) end)
    local fd = ok and to_num(f) or -1
    if fd>=0 then
      if mode==4 then opened=opened+1 end
      local nr=0; local ne=0
      for _,cmd in ipairs(cmds) do
        fill(); wd(sa,0); wd(sa+4,0); wd(sa+8,0); wd(sa+12,0)
        print(string.format("  > %s fl=%d %X", name, mode, cmd))
        local ok2,rv=pcall(function() return sc_ioctl(uint64(fd),uint64(cmd),uint64(ba)) end)
        local r = ok2 and to_num(rv) or -999
        if r~=-1 then
          nr=nr+1
          if r==22 then ne=ne+1 else asswered=asswered+1 end
          local vq=rqw(ba); local h,l=hi_of(vq)
          print(string.format("  I %s fl=%d cmd=%X rv=%d buf0=%X_%08X", name, mode, cmd, r, h, l))
        end
      end
      einval=einval+ne
      print(string.format("[D] %s fd=%d fl=%d rv_ne_m1=%d of_which_EINVAL22=%d", name, fd, mode, nr, ne))
      pcall(function() sc_close(uint64(fd)) end)
    else
      print(string.format("[D] %s open=FAIL fl=%d", name, mode))
    end
  end
end
print("")
print(string.format("[F] opened=%d cmd_answered_nonEINVAL=%d EINVAL22_total=%d", opened, asswered, einval))
print("=== DONE 1075a ===")
