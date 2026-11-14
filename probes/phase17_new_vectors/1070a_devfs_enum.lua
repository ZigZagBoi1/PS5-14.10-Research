-- CRASH_CLASS: LOW
-- PROBE 1070a: enumerate the filesystem with getdirentries(196) instead of guessing /dev node
-- names. Everything we know about device nodes came from name guessing; a real listing either
-- opens a much wider surface (/dev/mem, /dev/kmem, /dev/physmem, pci/nvme nodes) or proves the
-- namespace is closed to us. Dumps the first 96 raw bytes of each block so the dirent layout is
-- visible on the wire rather than assumed from the FreeBSD version.
print("=== PROBE 1070a: DEVFS ENUMERATION ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h, q.l end local n=to_num(q) return math.floor(n/4294967296), n%4294967296 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rqw(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end

local sc_sig=mk(416); local sc_open=mk(5); local sc_gde=mk(196); local sc_close=mk(6); local sc_pid=mk(20)
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local okS,vS=pcall(function() return sc_sig(uint64(12),uint64(aa),uint64(0)) end)
print(string.format("[S] sigsys-ignore ok=%s rv=%s pid=%s", tostring(okS), okS and tostring(to_num(vS)) or "-",
  tostring(to_num(select(2,pcall(function() return sc_pid() end))))))
print("")

local PB=0x100
local pa=as_addr(memory.alloc(PB))
local NB=0x2000
local ba=as_addr(memory.alloc(NB))
local bp=as_addr(memory.alloc(8))

local function setpath(p) for i=0,PB/4-1 do wd(pa+i*4,0) end for i=1,#p do wd(pa+i-1,p:byte(i)) end end
local function rdw(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return nil end
-- byte extraction MUST go through 32-bit reads: a qword holding ASCII exceeds 2^53 and
-- tonumber() rounds it, which silently corrupts every name byte (first run printed "xstem_tmp").
local function byteat(a,o) local d=rdw(a+o-o%4); if not d then return -1 end return math.floor(d/2^((o%4)*8))%256 end
local function str_at(a,o,len)
  local s=""
  for i=0,len-1 do
    if i>=48 then s=s..".."; break end
    local b=byteat(a,o+i); if b<32 or b>126 then break end
    s=s..string.char(b)
  end
  return s
end

local dirs={"/dev","/dev/fd"}
for _,dir in ipairs(dirs) do
  setpath(dir)
  local okf,fdv=pcall(function() return sc_open(uint64(pa),uint64(0),uint64(0)) end)
  local fd = okf and to_num(fdv) or -999
  print(string.format("[D] %-9s open=%s", dir, okf and tostring(fd) or "FAIL"))
  if fd>=0 then
    for round=1,64 do
      for i=0,NB/8-1 do wq(ba+i*8,0) end
      wq(bp,0)
      local okr,rv=pcall(function() return sc_gde(uint64(fd),uint64(ba),uint64(NB),uint64(bp)) end)
      local r = okr and to_num(rv) or -999
      print(string.format("  [G%02d] rv=%s base=%s", round, tostring(r), tostring(to_num(rqw(bp)))))
      if not okr or r<=0 then break end
      if round==1 then
        local line="    raw:"
        for i=0,191 do
          if i%16==0 then line=line..string.format("\n      +%03X:",i) end
          line=line..string.format(" %02X",byteat(ba,i))
        end
        print(line)
      end
      local off=0; local n=0; local names=""
      while off<r and n<400 do
        local d0=rdw(ba+off); local d1=rdw(ba+off+4)
        if not d0 or not d1 then break end
        local fileno=d0
        local reclen=d1%65536
        local dtype=math.floor(d1/65536)%256
        local namlen=math.floor(d1/16777216)%256
        if reclen<8 then print(string.format("      ! off=%X reclen=%d", off, reclen)) break end
        local nm=str_at(ba,off+8,namlen)
        names=names..string.format(" %s(%d,%d)", nm, fileno, dtype)
        off=off+reclen; n=n+1
      end
      print(string.format("    %d entries:%s", n, names))
      if n==0 then break end
    end
    pcall(function() return sc_close(uint64(fd)) end)
  end
  print("")
end
print("=== DONE 1070a ===")
