-- CRASH_CLASS: LOW
-- PROBE 1151a: who are we, and does the devfs refusal depend on the open mode?
-- 1150a turned "twelve nodes refuse" into five different answers: EBUSY (a53mm), EPERM (a53mmsys,
-- dbggc, fttrm, duid, mp3), EACCES (sbl_srv, encdec, lvd3), ENODEV (acm) and a Sony code
-- 0x8A721003 (hmd2_image, hmd2_slam_trace). EACCES from a devfs node is a permission-bit
-- answer; EPERM is a privilege answer. Which one applies decides whether the gate is even
-- credential-based: a mode check on a node owned by another uid is not reachable by borrowing
-- anything, while priv_check is the shape the bit-62 hypothesis predicts.
-- This probe prints the credential we actually run with (uid/gid/groups) and re-opens every
-- node in four modes, always with O_NONBLOCK so a device cannot park the loader.
print("=== PROBE 1151a: DEVFS OPEN MODE MATRIX ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rqw(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end

-- 1151a run 1 died on syscall 48 (getegid) before the matrix: the loader kills the caller on an
-- absent slot unless SIGSYS is ignored first (see 353a/353b). Install the ignore, then probe.
local sc_sig=mk(416)
local act=as_addr(memory.alloc(0x28))
for o=0,0x20,8 do wd(act+o,0) end
wd(act,1)
local okS=pcall(function() sc_sig(uint64(12),uint64(act),uint64(0)) end)
print("[S] sigsys-ignore installed="..tostring(okS))
print("")

local sc_open=mk(5); local sc_close=mk(6)
local PB=0x100
local pa=as_addr(memory.alloc(PB))
local function setpath(p) for i=0,PB/4-1 do wd(pa+i*4,0) end for i=1,#p do wd(pa+i-1,p:byte(i)) end end

local function errstr()
  local ok,r=pcall(get_error_string)
  if ok then return tostring(r) end
  return "?"
end

print("[ID] uid="..tostring(to_num(select(2,pcall(function() return mk(24)() end)))))
print("[ID] euid="..tostring(to_num(select(2,pcall(function() return mk(25)() end)))))
print("[ID] gid="..tostring(to_num(select(2,pcall(function() return mk(47)() end)))))
print("")

local O_NONBLOCK=0x4
local modes={{"RDONLY",0x0},{"WRONLY",0x1},{"RDWR",0x2},{"RDWR|EXCL",0x2+0x2000}}
local names={"a53mm","a53mmsys","dbggc","sbl_srv","encdec","fttrm","duid","mp3","acm","lvd3","hmd2_image","hmd2_slam_trace"}
for _,n in ipairs(names) do
  local path="/dev/"..n
  local parts={}
  for _,m in ipairs(modes) do
    setpath(path)
    local ok,rv=pcall(function() return sc_open(uint64(pa),uint64(m[2]+O_NONBLOCK)) end)
    local r=ok and to_num(rv) or -999
    if ok and r>=0 and r<0x10000 then pcall(function() sc_close(uint64(r)) end) end
    local tag
    if r==-1 then
      local e=errstr()
      local num=e:match("^(%d+)")
      tag="E"..(num or "?")
    else
      tag=tostring(r)
    end
    parts[#parts+1]=m[1].."="..tag
  end
  print(string.format("[%s] %s", n, table.concat(parts," ")))
end
print("")
-- the two Sony-coded nodes again, with the full strerror text, and the flag that gives EBUSY
for _,n in ipairs({"hmd2_image","hmd2_slam_trace","a53mm","acm"}) do
  setpath("/dev/"..n)
  local ok,rv=pcall(function() return sc_open(uint64(pa),uint64(0x2+O_NONBLOCK)) end)
  local r=ok and to_num(rv) or -999
  if ok and r>=0 and r<0x10000 then pcall(function() sc_close(uint64(r)) end) end
  print(string.format("[TXT %s] rv=%s errno=%s", n, tostring(r), errstr()))
end
print("")
-- Last on purpose. Run 1 called 48 with the default SIGSYS disposition and lost the console before
-- any matrix line was printed; the matrix is the part that carries new information, so the
-- absent-slot test now runs after it with the ignore installed.
-- 48 (getegid) and 79 (getgroups) killed run 1 outright; with SIGSYS ignored they should
-- return -1 and leave the process alive. If they do, the absent-slot reading is confirmed.
local okE,ev=pcall(function() return mk(48)() end)
print("[LATE] getegid(48) ok="..tostring(okE).." rv="..tostring(okE and to_num(ev) or "?"))
local okg,gv=pcall(function() return mk(79)(uint64(0),uint64(0)) end)
print("[LATE] getgroups(79) ok="..tostring(okg).." rv="..tostring(okg and to_num(gv) or "?"))
print("")
print("=== DONE ===")