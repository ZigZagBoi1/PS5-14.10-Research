-- CRASH_CLASS: MODERATE  (full 601 sweep; 0x08/0x0C parkers and the two killers are skipped)
-- PROBE 1193a: 601, errno-aware, with the attach-flag discrimination test.
--
-- Why: the whole existing 601 command map was built with rv only, and the loader's syscall wrapper
-- returns -1 for EVERY error (errno lives in libc's errno, read with get_error_string()). So "-1"
-- in docs/MDBG_601_COMMAND_MAP_14_10.md cannot separate EPERM from EINVAL from ENOSYS. This probe
-- prints errno per command, then calls 0x00 (the suspected attach: its case body at 0xca12d5 does
-- "or qword [td+0x528], 0x100"), then repeats the whole sweep. The command whose answer flips after
-- the attach is the second-stage dispatcher target (0xca0cda: test byte [td+0x529],1 -> jne 0xca180c).
print("=== PROBE 1193a: 601 ERRNO-AWARE SWEEP + ATTACH FLAG TEST ===")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%08X%08X", math.floor(N(v)/4294967296), N(v) % 4294967296)) end
local function hexn(v) v=N(v) return string.format("0x%08X%08X", math.floor(v/4294967296), v % 4294967296) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end

local STRUCT = N(memory.alloc(0x100))
local CAP    = N(memory.alloc(0x100))
local function zero(a,n) for o=0,n-4,4 do wd(a+o,0) end end
local sc = mk(601)

local function errnoword()
  local ok, s = pcall(function() return get_error_string() end)
  if ok and type(s)=="string" then return s end
  return "errno?"
end

local SKIP = {[0x00]=true,[0x03]=true,[0x04]=true,[0x08]=true,[0x0C]=true,[0x1B]=true,[0x27]=true}
local cmds = {}
for cmd=0,0x2F do if not SKIP[cmd] then cmds[#cmds+1]=cmd end end

-- one call: struct = all zeros, arg3 = 0 (len 0 -> no copyout, no wild pointer)
local function call1(cmd)
  zero(STRUCT,0x100)
  local ok, ret = pcall(function() return sc(U(cmd), U(STRUCT), U(0), U(0), U(0), U(0)) end)
  if not ok then return "PCALLFAIL", "-", "0x0" end
  local rv = N(ret)
  local raw = "?"
  pcall(function() raw = tostring(ret) end)
  return rv, errnoword(), raw
end

local pass1, pass2 = {}, {}
print("-- pass 1 (before any attach attempt) --")
for _,cmd in ipairs(cmds) do
  local rv, er, raw = call1(cmd)
  pass1[cmd] = {rv=rv, er=er, raw=raw}
  print(string.format("[%02X] rv=%-4s raw=%-20s errno=%s", cmd, tostring(rv), raw, er))
end

print("-- attach attempt: 601(0x00, mapped 0x100 buffer, 0) --")
zero(CAP,0x100)
local ok, ret = pcall(function() return sc(U(0x00), U(CAP), U(0), U(0), U(0), U(0)) end)
local rv0, raw0 = "PCALLFAIL", "?"
if ok then rv0 = N(ret) pcall(function() raw0 = tostring(ret) end) end
print(string.format("[00] rv=%s raw=%s errno=%s  cap=%s", tostring(rv0), raw0, errnoword(), hexn(rd(CAP))))

print("-- pass 2 (after the attach attempt) --")
local cand = {}
for _,cmd in ipairs(cmds) do
  local rv, er, raw = call1(cmd)
  pass2[cmd] = {rv=rv, er=er, raw=raw}
  local changed = (tostring(pass1[cmd].rv) ~= tostring(rv)) or (pass1[cmd].er ~= er)
  if changed then cand[#cand+1] = cmd end
  print(string.format("[%02X] rv=%-4s errno=%-28s %s", cmd, tostring(rv), er,
        changed and ("<<< CHANGED (was rv="..tostring(pass1[cmd].rv).." "..pass1[cmd].er..")") or ""))
end

if #cand == 0 then print("[SUM] no command changed after the 0x00 call: 0x00 is not the flag setter, or the flag is per-thread and already set") end
for _,cmd in ipairs(cand) do
  print(string.format("[CAND %02X] a third call with a real out pointer follows", cmd))
end
print("[Z] alive")
print("=== DONE ===")
