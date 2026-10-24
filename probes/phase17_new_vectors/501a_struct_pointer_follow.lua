-- CRASH_CLASS: MODERATE
-- PROBE 501a: struct-of-pointers sweep over the reachable Sony syscalls
-- The aio poll followed a pointer stored in a caller struct (descriptor +0x18) and
-- stored a status there. The same shape may exist in other reachable syscalls: fill a
-- struct with pointers to canary pages, call, then look for writes into the canaries
-- and for kernel-shaped values written back into the struct.
print("=== PROBE 501a: struct pointer follow ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hi_lo(v)
    if type(v) == "table" then return v.h, v.l end
    return 0, to_num(v)
end
local struct = memory.alloc(0x400)
local pages = {}
for i = 1, 4 do
  pages[i] = memory.alloc(0x1000)
end
local function fill(p, n, v)
  for o = 0, n - 1, 4 do pcall(function() memory.write_dword(p + o, v) end) end
end
local function page_addr(p) return memory.alloc(8) end
local function dword(p) return to_num(memory.read_dword(p)) end
local function canary_dirty()
  local n = 0
  for i = 1, 4 do
    for o = 0, 0xFFC, 0x40 do
      local v = to_num(memory.read_dword(pages[i] + o))
      if v ~= 0xAAAAAAAA then n = n + 1 end
    end
  end
  return n
end
local function kernelish_words(p, n)
  local out, count = {}, 0
  for o = 0, n - 8, 8 do
    local h, l = hi_lo(memory.read_qword(p + o))
    if h >= 0xFFFF8000 and not (h == 0xFFFFFFFF and (l == 0 or l == 0xFFFFFFFF)) then
      count = count + 1
      if count <= 4 then out[#out + 1] = string.format("%x=%08x%08x", o, h, l) end
    end
  end
  return count, table.concat(out, ",")
end
local nums = { 596, 585, 572, 624, 563, 564, 565, 566, 606, 643, 640, 649, 674, 557, 620, 454 }
local p0 = to_num(pages[1]) or 0
local p0s = string.format("0x%X", p0)
for _, n in ipairs(nums) do
  local sc = make_syscall(n)
  -- variant A: struct first, then a canary buffer
  fill(struct, 0x400, 0); fill(pages[1], 0x1000, 0xAAAAAAAA); fill(pages[2], 0x1000, 0xAAAAAAAA)
  for o = 0, 0x3F8, 8 do pcall(function() memory.write_qword(struct + o, uint64(p0s)) end) end
  local okA, retA = pcall(function() return sc(uint64(struct), uint64(0x400), uint64(string.format("0x%X", to_num(pages[2]))), uint64(0x100), uint64(0), uint64(0)) end)
  local ka, sa = kernelish_words(struct, 0x200)
  local da = canary_dirty()
  print(string.format("sys %d A ret=%s kern=%d %s dirty=%d", n, tostring(retA), ka, sa, da))
  -- variant B: buffer first, struct second
  fill(struct, 0x400, 0); fill(pages[1], 0x1000, 0xAAAAAAAA); fill(pages[2], 0x1000, 0xAAAAAAAA)
  for o = 0, 0x3F8, 8 do pcall(function() memory.write_qword(struct + o, uint64(p0s)) end) end
  local okB, retB = pcall(function() return sc(uint64(string.format("0x%X", to_num(pages[2]))), uint64(0x100), uint64(struct), uint64(0x400), uint64(0), uint64(0)) end)
  local kb, sb = kernelish_words(struct, 0x200)
  local db = canary_dirty()
  print(string.format("sys %d B ret=%s kern=%d %s dirty=%d", n, tostring(retB), kb, sb, db))
end
print("=== PROBE 501a COMPLETE ===")
