-- CRASH_CLASS: MODERATE (every call uses the 1170a shape: mapped 0x100 arg2, small numeric arg3)
-- PROBE 1195a: the attach hunt, with arg3 as a LENGTH.
-- The attach body (0xca12d5) copyout's min(arg3, 0x28) bytes of five ctx qwords to arg2, and sets
-- td+0x528 bit 8 on the way. With arg3 = 0 that copyout is zero-length and invisible (which is why the
-- whole sweep so far saw nothing). Here arg3 = 0x28, so an attach writes 0x28 bytes to arg2.
-- Phase A: find the writer. Phase B: re-run every EPERM(1) command, because the EPERM set is exactly
-- what the "flag clear" branch of the second-stage gate produces - one of them may now dispatch.
print("=== PROBE 1195a: 601 ATTACH HUNT (arg3 AS LENGTH) ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hx(n) n = n % 4294967296 local hi = math.floor(n/65536) local lo = n - hi*65536 return string.format("%04X%04X", hi, lo) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local B = N(memory.alloc(0x100))
local sc = mk(601)
local function sent() for o=0,0xFC,4 do wd(B+o,0xA5A5A5A5) end end
local function dump(n)
  local all, out = true, {}
  for i=0,(n/4)-1 do local v=rd(B+i*4) if v~=0xA5A5A5A5 then all=false end end
  if all then return nil end
  for i=0,(n/4)-1 do out[#out+1]=hx(rd(B+i*4)) end
  return table.concat(out," ")
end
local function call(cmd, len)
  sent()
  local ok, ret = pcall(function() return sc(U(cmd), U(B), U(len), U(0), U(0), U(0)) end)
  if not ok then return "PCALLFAIL","-",nil end
  local d = dump(0x28)
  return tostring(N(ret)), es(), d
end
local SKIP = {[0x03]=true,[0x04]=true,[0x08]=true,[0x0C]=true,[0x1B]=true,[0x27]=true}
local writers = {}
print("-- phase A: arg3 = 0x28, arg2 = 0xA5 buffer --")
for cmd=0,0x27 do
  if not SKIP[cmd] then
    print(string.format("[%02X] calling...", cmd))
    local rv, er, d = call(cmd, 0x28)
    if d then writers[#writers+1]=cmd end
    print(string.format("   rv=%-3s errno=%-28s %s", rv, er, d and ("WROTE "..d) or "no-write"))
  end
end
print("[SUMA] 0x28-byte writers = "..table.concat(writers, ","))
print("-- phase B: re-run the EPERM(1) set with arg3 = 0x28 --")
for _,cmd in ipairs({0x0A,0x0F,0x15,0x18,0x24,0x25,0x26}) do
  local rv, er, d = call(cmd, 0x28)
  print(string.format("[%02X] rv=%-3s errno=%-28s %s", cmd, rv, er, d and ("WROTE "..d) or "no-write"))
end
print("[Z] alive")
print("=== DONE ===")
