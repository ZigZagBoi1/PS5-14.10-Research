-- CRASH_CLASS: MODERATE
-- PROBE 704a: /dev/gc mapped at offset 0 read all-ones last time. Sweep sizes,
-- protections and offsets, and dump the first qwords so we can tell "no
-- aperture" from "real MMIO that reads 0xFFFFFFFF".
print("=== PROBE 704a: /dev/gc MMIO ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function c6(n,a,b,c,d,e,f)
  local o,r=pcall(function() return mk(n)(U(a or 0),U(b or 0),U(c or 0),U(d or 0),U(e or 0),U(f or 0)) end)
  if o then return N(r) end return -999
end
local function openp(p)
  local b=memory.alloc(#p+2)
  for i=1,#p do pcall(function() memory.write_byte(N(b)+i-1,string.byte(p,i)) end) end
  return c6(5,N(b),2,0)
end
for _,dev in ipairs({"/dev/gc","/dev/dce","/dev/hid"}) do
  local fd=openp(dev)
  print(string.format("[A] %s fd=%d",dev,fd))
  if fd>=0 then
    for _,size in ipairs({0x1000,0x10000,0x400000}) do
      for _,off in ipairs({0,0x1000,0x10000,0x100000}) do
        local p=c6(477,0,size,3,1,fd,off)
        local ok=(p>0 and p<0x800000000000)
        if ok then
          local parts={}
          for i=0,0x40,8 do parts[#parts+1]=string.format("%016X",N(memory.read_qword(p+i))) end
          print(string.format("[B] %s size=0x%X off=0x%X p=0x%X q=[%s]",dev,size,off,p,table.concat(parts," ")))
          pcall(function() c6(73,p,size) end)
        else
          print(string.format("[B] %s size=0x%X off=0x%X mmap=%s",dev,size,off,tostring(p)))
        end
      end
    end
    pcall(function() c6(6,fd) end)
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
