-- CRASH_CLASS: RISKY (arg3 is a mapped 8-byte sentinel for every command; 0x00 wedged the loader with a
-- non-zero arg3 in 1192a, so 0x00 is skipped here and stays skipped until the shape is understood)
-- PROBE 1194e: who writes the 8-byte stage-two result to arg3?
-- arg2 = a valid type-4 struct (unlink path: result 0), arg3 = 0x20 sentinel buffer. Stage two's only
-- copyout is "copyout(&stack_qword, arg3, 8)", so a command that changes the sentinel is a stage-two
-- entry. Each call is announced before it runs, so a hang names the command.
print("=== PROBE 1194e: 601 ARG3 OUT-POINTER SWEEP ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hx(n) n = n % 4294967296 local hi = math.floor(n/65536) local lo = n - hi*65536 return string.format("%04X%04X", hi, lo) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v % 4294967296 end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "?" end
local S = N(memory.alloc(0x100))
local O = N(memory.alloc(0x20))
local sc = mk(601)
local function struct4() for o=0,0xFC,4 do wd(S+o,0) end
  wd(S+0x08,0x10) wd(S+0x24,4) end
local function sent() for o=0,0x1C,4 do wd(O+o,0xC7C7C7C7) end end
local SKIP = {[0x00]=true,[0x01]=true,[0x03]=true,[0x04]=true,[0x08]=true,[0x0C]=true,[0x1B]=true,[0x27]=true}
local hits = {}
for cmd=0,0x27 do
  if not SKIP[cmd] then
    struct4() sent()
    print(string.format("[%02X] calling...", cmd))
    local ok, ret = pcall(function() return sc(U(cmd), U(S), U(O), U(0), U(0), U(0)) end)
    if not ok then print("   PCALL-FAIL")
    else
      local d = hx(rd(O)).." "..hx(rd(O+4))
      local changed = not (rd(O)==0xC7C7C7C7 and rd(O+4)==0xC7C7C7C7)
      if changed then hits[#hits+1] = cmd end
      print(string.format("   rv=%-3s errno=%-28s arg3=%s %s", tostring(N(ret)), es(), d, changed and "<<< WROTE" or ""))
    end
  end
end
print("[SUM] arg3 writers = "..table.concat(hits, ","))
print("[Z] alive")
print("=== DONE ===")
