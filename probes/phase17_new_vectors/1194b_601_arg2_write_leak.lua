-- CRASH_CLASS: MODERATE (same skip list as 1193a; arg3 forced to 0)
-- PROBE 1194b: which 601 commands WRITE to arg2, and does anything leak a kernel pointer?
-- Every call: arg2 = 0xA5-filled 0x100 buffer, arg3 = 0. After each call the first 0x28 bytes are
-- compared to the sentinel and dumped when changed. A command that dumps 0xffff.... here is a kernel
-- pointer disclosure on 14.10; a command that dumps 8 bytes here is an out-parameter command.
print("=== PROBE 1194b: 601 ARG2 WRITE AND LEAK SWEEP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hx(n) n = n % 4294967296 local hi = math.floor(n/65536) local lo = n - hi*65536 return string.format("%04X%04X", hi, lo) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local B = N(memory.alloc(0x100))
local sc = mk(601)
local SKIP = {[0x00]=true,[0x03]=true,[0x04]=true,[0x08]=true,[0x0C]=true,[0x1B]=true,[0x27]=true}
local function dump()
  local seen, out, all = {}, {}, true
  for i=0,9 do local v = rd(B+i*4) if v ~= 0xA5A5A5A5 then all=false end end
  if all then return nil end
  for i=0,9 do out[#out+1] = hx(rd(B+i*4)) end
  return table.concat(out," ")
end
local writers = {}
for cmd=0,0x2F do
  if not SKIP[cmd] then
    for o=0,0xFC,4 do wd(B+o,0xA5A5A5A5) end
    local ok, ret = pcall(function() return sc(U(cmd), U(B), U(0), U(0), U(0), U(0)) end)
    if not ok then
      print(string.format("[%02X] PCALL-FAIL", cmd))
    else
      local rv = N(ret)
      local d = dump()
      if d then writers[#writers+1] = cmd end
      print(string.format("[%02X] rv=%-3s errno=%-28s %s", cmd, tostring(rv), es(), d and ("WROTE "..d) or "no-write"))
    end
  end
end
print("[SUM] writers = "..table.concat(writers, ","))
print("[Z] alive")
print("=== DONE ===")
