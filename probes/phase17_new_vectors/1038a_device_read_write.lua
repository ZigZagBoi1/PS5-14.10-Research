-- CRASH_CLASS: MODERATE
-- PROBE 1038a: device read()/write() on the nodes the 32M-ioctl sweeps never touched
-- (repo gap D: rng, gic, bt, hid, camera, notification0, usbctl, ajm/ajmi), plus the
-- three 622 arg3 shapes DeviceRead proposed. Any kernel-range qword in a read() result
-- is a leak; a non-zero write() rv is a new write path. gc/dce are last because a
-- plain read on them is what killed 376a/380a.
print("=== PROBE 1038a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h, q.l end local n=to_num(q) return math.floor(n/4294967296), n%4294967296 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rqw(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end

local sc_sig=mk(416); local sc_open=mk(5); local sc_read=mk(3); local sc_write=mk(4); local sc_close=mk(6); local sc_pid=mk(20)
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local okS,vS=pcall(function() return sc_sig(uint64(12),uint64(aa),uint64(0)) end)
print(string.format("[S] shield ok=%s rv=%s pid=%d", tostring(okS), okS and tostring(to_num(vS)) or "-", to_num(select(2,pcall(function() return sc_pid() end)))))

local SENT=0xCDCDCDCD
local BUF=0x100
local buf=memory.alloc(BUF+0x100); local ba=as_addr(buf)
local pb=memory.alloc(0x80); local pa=as_addr(pb)
local function setpath(p) for i=0,#p do wd(pa+i,0) end for i=1,#p do wd(pa+i-1,p:byte(i)) end end
local function fill() for i=0,BUF/8-1 do wq(ba+i*8,SENT) end end
local function scan()
  local t=0; local kp=0; local first=""
  for i=0,BUF/8-1 do
    local vq=rqw(ba+i*8); local v=vq and to_num(vq) or -1
    if v~=SENT then
      t=t+1
      local h,l=hi_of(vq)
      if h>=0xFFFF8000 and not (h==0xFFFFFFFF and l==0xFFFFFFFF) then
        kp=kp+1
        if kp<=3 then first=first..string.format(" +%X=%X_%08X", i*8, h, l) end
      end
    end
  end
  return t,kp,first
end

local devs={"/dev/usbctl","/dev/ajm","/dev/ajmi","/dev/gic","/dev/notification0","/dev/notification1","/dev/gc","/dev/dce"}
for _,d in ipairs(devs) do
  setpath(d)
  local okf,fdv=pcall(function() return sc_open(uint64(pa),uint64(4),uint64(0)) end)  -- O_RDONLY|O_NONBLOCK
  local fd = okf and to_num(fdv) or -999
  if fd>=0 then
    fill()
    local okr,rv=pcall(function() return sc_read(uint64(fd),uint64(ba),uint64(BUF)) end)
    local r = okr and to_num(rv) or -999
    local t,kp,first=scan()
    print(string.format("[R] %s fd=%d rv=%s touched=%d kp=%d%s", d, fd, tostring(r), t, kp, first))
    local ok2,fd2=pcall(function() return sc_open(uint64(pa),uint64(5),uint64(0)) end)  -- O_WRONLY|O_NONBLOCK
    if ok2 and to_num(fd2)>=0 then
      for i=0,0x40/4-1 do wd(ba+i*4,0x41414141) end  -- double-exact pattern
      local okw,wv=pcall(function() return sc_write(uint64(to_num(fd2)),uint64(ba),uint64(0x40)) end)
      print(string.format("[W] %s rv=%s", d, okw and tostring(to_num(wv)) or "FAIL"))
      pcall(function() return sc_close(uint64(to_num(fd2))) end)
    else
      print(string.format("[W] %s rdonly", d))
    end
    pcall(function() return sc_close(uint64(fd)) end)
  else
    print(string.format("[R] %s open=%s", d, okf and tostring(fd) or "FAIL"))
  end
end

print("-- 622 mapped arg3 shapes")
local sc622=mk(622)
for _,c in ipairs({0x100,0x200,0x302,0x400,0x813}) do
  for _,shape in ipairs({"c,len,buf","c,buf,len","c,buf,0"}) do
    fill()
    local ok,v
    if shape=="c,len,buf" then
      ok,v=pcall(function() return sc622(uint64(c),uint64(BUF),uint64(ba),uint64(0),uint64(0),uint64(0)) end)
    elseif shape=="c,buf,len" then
      ok,v=pcall(function() return sc622(uint64(c),uint64(ba),uint64(BUF),uint64(0),uint64(0),uint64(0)) end)
    else
      ok,v=pcall(function() return sc622(uint64(c),uint64(ba),uint64(0),uint64(0),uint64(0),uint64(0)) end)
    end
    local t,kp,first=scan()
    print(string.format("[622] cmd=%X %s rv=%s q0=%X touched=%d kp=%d%s", c, shape, ok and tostring(to_num(v)) or "FAIL", to_num(rqw(ba) or 0), t, kp, first))
  end
end
print("[Z] done")
