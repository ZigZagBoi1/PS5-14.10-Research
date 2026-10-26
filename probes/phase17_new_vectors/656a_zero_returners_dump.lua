-- CRASH_CLASS: LOW
-- PROBE 656a: the sweep found ten numbers that return 0 for some shape with
-- zeroed pages. Dump what they write, looking for pointers.
print("=== PROBE 656a: WHAT THE ZERO-RETURNING SYSCALLS WRITE ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_qword(a) end) if o then return N(v) end return nil end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local pages={}
for i=1,3 do pages[i]=memory.alloc(0x1000) end
local function clean() for i=1,3 do for k=0,0xFFF,8 do wq(N(pages[i])+k,uint64(0)) end end end
local LIST={587,588,596,643,657,659,662,664,666,675}
local SHAPES={
  {"A",function(sc) return sc(U(N(pages[1])),U(0x1000),U(N(pages[2])),U(0x1000),U(N(pages[3])),U(0x1000)) end},
  {"B",function(sc) return sc(U(1),U(N(pages[1])),U(0x1000),U(N(pages[2])),U(0x1000),U(N(pages[3]))) end},
  {"C",function(sc) return sc(U(N(pages[1])),U(4),U(0),U(0),U(0),U(0)) end},
}
for _,num in ipairs(LIST) do
  for _,sh in ipairs(SHAPES) do
    clean()
    local ok,rv=pcall(function() return sh[2](mk(num)) end)
    if ok and N(rv)==0 then
      local out={}
      local kern=0
      for i=1,3 do
        local nz={}
        for k=0,0x38,8 do
          local v=rd(N(pages[i])+k) or 0
          if v~=0 then nz[#nz+1]=string.format("+%02X=%X",k,v)
            local hi=math.floor(v/4294967296)
            if hi>=0xFFFF8000 then kern=kern+1 end
          end
        end
        if #nz>0 then out[#out+1]=string.format("p%d[%s]",i,table.concat(nz," ")) end
      end
      print(string.format("[%d%s] ret=0 kern=%d %s",num,sh[1],kern,table.concat(out," ")))
    end
  end
end
print(string.format("[Z] alive=%d",N(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
