-- CRASH_CLASS: LOW (all pointers are mapped; the only copyout destination is our own buffer)
-- PROBE 1196a: sys 674 virtual_query_all - the command word nobody ever passed.
-- Static (13.60 body 0x8b47b980): uap = {+0x00 out_ptr, +0x08 stride, +0x10 max_entries,
-- +0x18 unused, +0x20 MAGIC dword which must equal 0x40000000 or the handler returns 0x16 EINVAL}.
-- It walks proc->vmspace's vm_map entry list and for each entry builds a 0x48-byte record on the stack
-- via 0x8b47a710(entry, start, end, rec, 1, 1), then copyout(rec, out_ptr + i*stride, min(stride,0x48)).
-- Every earlier sweep passed zeros, so the magic check failed every time and 674 looked dead.
-- This probe passes the magic and looks for ffff8... values in the record (a vm_object/vnode pointer
-- would be a KASLR recovery, and the record layout is worth knowing regardless).
print("=== PROBE 1196a: sys 674 virtual_query_all WITH THE MAGIC WORD ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hx(n) n = n % 4294967296 local hi = math.floor(n/65536) local lo = n - hi*65536 return string.format("%04X%04X", hi, lo) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function rq(a) local ok,v = pcall(function() return N(memory.read_qword(a)) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a, U(v)) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local BUF = N(memory.alloc(0x800))
local sc  = mk(674)
local function sent(n) for o=0,(n/4)-1 do wd(BUF+o*4,0xA5A5A5A5) end end
local function q(a) local v=rq(a) if v==nil then return "................" end return string.format("%08X%08X", math.floor(v/4294967296), v % 4294967296) end
local function hexdump(n)
  local lines={}
  for i=0,(n/8)-1 do
    local v=q(BUF+i*8)
    lines[#lines+1]=string.format("  +%02X %s", i*8, v)
  end
  return table.concat(lines,"\n")
end
local function call(outp, stride, count, a3, magic)
  sent(stride < 0x800 and 0x800 or stride)
  local ok, ret = pcall(function() return sc(U(outp), U(stride), U(count), U(a3), U(magic)) end)
  if not ok then return "PCALLFAIL", "-" end
  return tostring(N(ret)), es()
end
print("[0] negative control: magic = 0")
local rv, er = call(BUF, 0x48, 4, 0, 0)
print("    rv="..rv.." errno="..er)
print("[1] magic = 0x40000000, stride 0x48, count 4")
rv, er = call(BUF, 0x48, 4, 0, 0x40000000)
print("    rv="..rv.." errno="..er)
print(hexdump(0x120))
print("[2] magic = 0x40000000, stride 0x48, count 0x40")
rv, er = call(BUF, 0x48, 0x40, 0, 0x40000000)
print("    rv="..rv.." errno="..er)
local nz=0
for i=0,0x3f do
  local base=i*0x48
  local a=q(BUF+base) local b=q(BUF+base+8) local c=q(BUF+base+0x10)
  if a~="A5A5A5A5A5A5A5A5" then
    nz=nz+1
    print(string.format("  #%02d %s %s %s | +0x18 %s +0x20 %s +0x28 %s", i,a,b,c,q(BUF+base+0x18),q(BUF+base+0x20),q(BUF+base+0x28)))
  end
end
print("    non-empty records = "..nz)
print("[3] magic = 0x40000000, stride 0x18 (short stride), count 8")
rv, er = call(BUF, 0x18, 8, 0, 0x40000000)
print("    rv="..rv.." errno="..er)
print(hexdump(0xC0))
print("[Z] alive")
print("=== DONE ===")
