print("=== PROBE 1208c: Sony-range branch oracle sweep, part 3 (621+) (error-string channel) ===")
local function tn(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local g,r=pcall(get_error_string) if g then return tostring(r) end return "NOES" end
local Z=uint64(0)
local buf=memory.alloc(0x1000)
do local ok=pcall(function() for i=0,0xff0,8 do memory.write_qword(buf+i,uint64(0)) end end) end
local B=uint64(buf)
local ONE=uint64(1)
local HI=uint64("0x1000")
local shapes={
  {"Z",Z,Z,Z,Z,Z,Z},
  {"a0",B,Z,Z,Z,Z,Z},
  {"a1",Z,B,Z,Z,Z,Z},
  {"a2",Z,Z,B,Z,Z,Z},
  {"a3",Z,Z,Z,B,Z,Z},
  {"one",ONE,Z,Z,Z,Z,Z},
  {"0x1_2",Z,ONE,Z,HI,Z,Z},
}
local SKIP={[597]=1,[600]=1,[601]=1,[609]=1,[614]=1,[621]=1,[622]=1,[637]=1,[645]=1,[677]=1,[678]=1}
local interesting=0
for n=621,680 do
  if not SKIP[n] then
    local sc=mk(n)
    local line=string.format("S %-4d",n)
    local set={}
    for si=1,#shapes do
      local s=shapes[si]
      local ok,rv=pcall(function() return sc(s[2],s[3],s[4],s[5],s[6],s[7]) end)
      local e = ok and ES() or "TRAP"
      local r = ok and tn(rv) or -999
      line=line..string.format(" | %s=%s",s[1],e)
      if e~="TRAP" then set[e]=true end
      if ok and r~=0 and r~=-1 then line=line..string.format("(rv=%d)",r) end
    end
    local cnt=0 for _ in pairs(set) do cnt=cnt+1 end
    if cnt>1 then interesting=interesting+1 line=line.."  <<<" end
    print(line)
  end
end
print("differing syscalls: "..interesting)
print("=== DONE")
