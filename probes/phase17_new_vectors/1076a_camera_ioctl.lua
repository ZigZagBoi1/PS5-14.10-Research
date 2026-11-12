-- CRASH_CLASS: MODERATE
-- PROBE 1076a: /dev/camera is the only node whose ioctl did not return the uniform -1.
-- 1075a got rv=22 for thirteen request codes and a changed first dword in the caller buffer.
-- Two things are ambiguous and this probe separates them:
--   (1) the return convention - a control call, TIOCGWINSZ on our own stdout tty, must return 0
--       and fill a winsize struct if 54 really is ioctl and errors really are normalised;
--   (2) whether the buffer change is a driver write or a stale sentinel, settled by filling each
--       dword with its own index so any written word is identifiable.
print("=== PROBE 1076a: CAMERA IOCTL MATRIX ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end

local sc_open=mk(5); local sc_ioctl=mk(54); local sc_close=mk(6)

-- ---- control: TIOCGWINSZ on the tty we already hold -------------------------------
local cb=memory.alloc(0x20); local ca=as_addr(cb)
for i=0,7 do wd(ca+i*4,0xA5A5A5A5) end
local okC,rvC=pcall(function() return sc_ioctl(uint64(1),uint64(0x40087468),uint64(ca)) end)
print(string.format("[CTL] ioctl(stdout, TIOCGWINSZ) ok=%s rv=%s dwords=%08X %08X %08X %08X",
  tostring(okC), okC and tostring(to_num(rvC)) or "-", rd(ca),rd(ca+4),rd(ca+8),rd(ca+12)))
print("")

-- ---- camera ----------------------------------------------------------------------
local path="/dev/camera"
local pb=memory.alloc(0x20); local pa=as_addr(pb)
for i=1,#path do wd(pa+i-1,path:byte(i)) end
wd(pa+#path,0)
local okF,fdv=pcall(function() return sc_open(uint64(pa),uint64(4),uint64(0)) end)
local fd = okF and to_num(fdv) or -1
print(string.format("[O] /dev/camera fd=%d", fd))
if fd < 0 then print("=== DONE 1076a (no camera) ===") return end

local NB=0x400
local buf=memory.alloc(NB); local ba=as_addr(buf)
local function paint() for i=0,NB/4-1 do wd(ba+i*4,0xA0000000+i) end end

local counts={}
local function run(dir,size,num)
  local cmd = dir + size*0x10000 + num*0x100
  paint()
  print(string.format("  > %08X", cmd))
  local ok,rv=pcall(function() return sc_ioctl(uint64(fd),uint64(cmd),uint64(ba)) end)
  local r = ok and to_num(rv) or -999
  local d0,d1,d2,d3 = rd(ba),rd(ba+4),rd(ba+8),rd(ba+12)
  local chg = (d0~=0xA0000000) or (d1~=0xA0000001) or (d2~=0xA0000002) or (d3~=0xA0000003)
  local key = string.format("%d/%s", r, tostring(chg))
  counts[key]=(counts[key] or 0)+1
  if chg or r ~= -1 then
    print(string.format("  C %08X rv=%d chg=%s %08X %08X %08X %08X", cmd, r, tostring(chg), d0,d1,d2,d3))
  end
end

for _,size in ipairs({0x08,0x20,0x100}) do
  for num=0,15 do
    run(0xC0000000,size,num)
  end
end
for num=0,7 do
  run(0x40000000,0x08,num)
  run(0x80000000,0x08,num)
end
print("")
for k,v in pairs(counts) do print(string.format("[H] rv/chg=%s n=%d", k, v)) end
print(string.format("[F] alive, camera fd still %d", fd))
print("=== DONE 1076a ===")
