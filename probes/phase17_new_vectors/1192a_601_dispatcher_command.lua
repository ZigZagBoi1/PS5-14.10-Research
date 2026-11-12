-- CRASH_CLASS: MODERATE
-- PROBE 1192a: find the syscall-601 command that reaches the second-stage dispatcher.
--
-- Static context (13.60 dump, handler entry 0xca0630):
--   every command case that matters tail-jumps 0xca1819 -> jmp 0xca2320(td, arg2, arg3)
--   0xca2320 does copyin(0x3c) from arg2 into its stack frame, then:
--     type = struct[+0x24]
--     bit 0x100 of [td+0x528] clear -> type must pass mask 0xb8 (3,4,5,7);
--        types 4/5 -> unprivileged list-unlink path, returns 0
--        types 3/7 -> fall into the main body anyway
--     otherwise (bad type) -> return 1
--     arg3 != NULL -> copyout 8 bytes ([rbp-0x38]) to arg3
-- Earlier sweeps never crafted struct[+0x24] (0xA5A5A5A5 fill) and passed arg3 = 0,
-- so the dispatcher signature (rv 1 / rv 0+out write) was never seen.
print("=== PROBE 1192a: 601 DISPATCHER COMMAND HUNT ===")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function U(v) return uint64(string.format("0x%X", N(v))) end
local function hexn(v) v=N(v) return string.format("0x%08X%08X", math.floor(v/4294967296), v % 4294967296) end
local function rd(a) local ok,v = pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function make_syscall(num) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=num setmetatable(t,getmetatable(syscall.pipe)) return t end

local STRUCT = N(memory.alloc(0x100))
local OUT    = N(memory.alloc(0x1000))
local function zero(a,n) for o=0,n-4,4 do wd(a+o,0) end end
local function fill(a,n,v) for o=0,n-4,4 do wd(a+o,v) end end
local function out8() return string.format("%08X%08X", rd(OUT+4), rd(OUT)) end
local function nz(a,n) local s="" for o=0,n-4,4 do local v=rd(a+o) if v~=0 then s=s..string.format(" %02X=%08X",o,v) end end if s=="" then return "(zero)" end return s end

print("[A] struct=" .. hexn(STRUCT) .. " out=" .. hexn(OUT))
local sc = make_syscall(601)
local SKIP = {[0x03]=1,[0x04]=1,[0x08]=1,[0x0C]=1,[0x1B]=1,[0x27]=1}
local hit = {}

local function shape(cmd, ty, label)
  zero(STRUCT,0x100) fill(OUT,0x1000,0xC7C7C7C7)
  if ty then wd(STRUCT+0x24, ty) end
  local ok, ret = pcall(function() return sc(U(cmd), U(STRUCT), U(OUT), U(0), U(0), U(0)) end)
  local rv = ok and tostring(N(ret)) or "PCALL-FAIL"
  local o = out8()
  local interesting = (rv=="0" or rv=="1" or rv=="14") and o ~= "C7C7C7C7C7C7C7C7"
  print(string.format("[%02X] %-7s rv=%-12s out=%s %s struct:%s", cmd, label, rv, o, interesting and "<<< WRITE" or "", nz(STRUCT,0x40)))
  return rv
end

print("-- phase A: type 0 (invalid: bit0 of 0xb8 is clear) --")
for cmd=0,0x27 do if not SKIP[cmd] then local rv=shape(cmd,nil,"t=0") if rv=="1" then hit[cmd]=true end end end
print("-- phase B: type 4 (unprivileged dispatcher path, expect rv 0) --")
for cmd=0,0x27 do if not SKIP[cmd] then local rv=shape(cmd,4,"t=4") if rv=="0" then hit[cmd]=true end end end
print("-- phase C: type 0x5A5A5A5A (bad type, expect rv 1) --")
for cmd=0,0x27 do if not SKIP[cmd] then local rv=shape(cmd,0x5A5A5A5A,"t=bad") if rv=="1" then hit[cmd]=true end end end

local s="" for c=0,0x27 do if hit[c] then s=s..string.format(" %02X",c) end end
print("[HITS]" .. (s=="" and " none" or s))
print("[Z] alive")
print("=== DONE ===")
