-- CRASH_CLASS: SAFE (one 674 call, read-only; no execution, no 629, no writes)
-- PROBE 1252a: where is executable memory in this process, and is any of it writable?
--
-- Context: 1251a calibrated 674 and produced a result that changes the plan.
-- The kernel records an anon prot=7 mmap as prot=0x3 (rw-) and a file-backed
-- prot=7 MAP_PRIVATE mmap of /app0/eboot.bin as prot=0x3 as well, while eboot's
-- own .text is prot=0x5 (r-x).  So PROT_EXEC is stripped at mmap() time for BOTH
-- object types, and 674 reports the EFFECTIVE protection, not the request.
--
-- That kills the "write our own executable page" plan (1251b would be a wasted
-- crash), but it opens a better one: the process already contains executable
-- memory, and native.fcall_with_rax can call any userland address with six
-- controlled arguments (probe 129b).  If a suitable Spectre v1 gadget already
-- exists in an r-x region, we do not need to create one.
--
-- This probe answers:
--   [Q1] how much executable memory exists, and where?
--   [Q2] is any region both writable and executable (prot & 6 == 6) - instant win?
--   [Q3] which executable regions are file-backed, and what are they called?
--   [Q4] what is the exact byte range of eboot's .text, so a gadget scan can target it?

print("=== PROBE 1252a: EXECUTABLE SURFACE MAP ===")
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
local function u64(h, l) return h * 4294967296 + l end
local function bit(v, n)
  local d = 1
  for _ = 1, n do d = d * 2 end
  return math.floor(v / d) - math.floor(v / (d * 2)) * 2
end
local function bitname(p)
  local s = ""
  if bit(p, 0) == 1 then s = s .. "r" else s = s .. "-" end
  if bit(p, 1) == 1 then s = s .. "w" else s = s .. "-" end
  if bit(p, 2) == 1 then s = s .. "x" else s = s .. "-" end
  return s
end

local STRIDE, MAX = 72, 512
local sc674 = mk(674)
local buf = memory.alloc(STRIDE * MAX + 0x100)
local cnt = memory.alloc(16)
memory.write_dword(cnt, 0)
memory.write_dword(cnt + 4, 0)
local ok, rv = pcall(function()
  return sc674(uint64(N(buf)), uint64(STRIDE), uint64(MAX), uint64(N(cnt)), uint64(0x40000000))
end)
if not ok then
  print("674 pcall failed: " .. tostring(rv))
  print("=== DONE 1252a ===")
  return
end
local ret = N(rv)
local n = N(memory.read_dword(cnt))
if n < 0 then n = 0 end
if n > MAX then n = MAX end
print(string.format("[1] 674 rv=%d count=%d", ret, n))

local function name_of(base)
  local s = ""
  local len = N(memory.read_byte(base + 0x20))
  if len < 0 or len > 38 then len = 38 end
  for i = 1, len do
    local c = N(memory.read_byte(base + 0x20 + i))
    if c >= 32 and c < 127 then s = s .. string.char(c) else s = s .. "." end
  end
  return s
end

local recs = {}
local hist = {}
for i = 0, n - 1 do
  local b = N(buf) + i * STRIDE
  local r = {
    s = u64(N(memory.read_dword(b + 4)), N(memory.read_dword(b))),
    e = u64(N(memory.read_dword(b + 12)), N(memory.read_dword(b + 8))),
    p = N(memory.read_dword(b + 0x18)),
    nm = name_of(b),
  }
  r.len = r.e - r.s
  recs[#recs + 1] = r
  local k = r.p
  hist[k] = (hist[k] or 0) + 1
end

print("")
print("[2] protection histogram")
local keys = {}
for k, _ in pairs(hist) do keys[#keys + 1] = k end
table.sort(keys)
for i = 1, #keys do
  local k = keys[i]
  print(string.format("    prot=0x%X %s  %d regions", k, bitname(k), hist[k]))
end

print("")
print("[3] every executable region (prot & 4)")
local exec_total, exec_count, wx_count = 0, 0, 0
for i = 1, #recs do
  local r = recs[i]
  if bit(r.p, 2) == 1 then
    exec_count = exec_count + 1
    exec_total = exec_total + r.len
    local wx = (bit(r.p, 1) == 1)
    if wx then wx_count = wx_count + 1 end
    print(string.format("    %s - %s  len=%s  prot=0x%X %s%s  %s",
          hex(r.s), hex(r.e), hex(r.len), r.p, bitname(r.p),
          wx and "  *** W+X ***" or "", r.nm))
  end
end
print(string.format("    total: %d executable regions, %s bytes (%.1f MB), %d writable",
      exec_count, hex(exec_total), exec_total / 1048576, wx_count))

print("")
print("[4] W+X check")
if wx_count > 0 then
  print("    *** at least one writable+executable region exists - see [3] ***")
else
  print("    none: W^X holds for every mapped region in this process")
end

print("")
print("[5] named (non-anon) regions, i.e. file-backed mappings")
local named = 0
for i = 1, #recs do
  local r = recs[i]
  if not r.nm:find("^anon") and r.nm ~= "" then
    named = named + 1
    if named <= 40 then
      print(string.format("    %s - %s  prot=0x%X %s  %s", hex(r.s), hex(r.e), r.p, bitname(r.p), r.nm))
    end
  end
end
print(string.format("    %d named regions", named))

print("")
print("[6] eboot .text candidate (the largest r-x region named .executable)")
local best = nil
for i = 1, #recs do
  local r = recs[i]
  if bit(r.p, 2) == 1 and (r.nm:find("executable") or r.nm == "") then
    if best == nil or r.len > best.len then best = r end
  end
end
if best then
  print(string.format("    %s - %s  len=%s  prot=0x%X %s  name=%s",
        hex(best.s), hex(best.e), hex(best.len), best.p, bitname(best.p), best.nm))
  local okr, b0 = pcall(function() return N(memory.read_dword(best.s)) end)
  print(string.format("    first dword at start: %s (ELF magic would be 464C457F)", okr and string.format("%08X", b0) or "read failed"))
else
  print("    not found")
end

print("")
print("=== DONE 1252a ===")
