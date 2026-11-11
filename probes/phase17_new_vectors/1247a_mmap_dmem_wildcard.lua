-- CRASH_CLASS: LOW-MEDIUM (syscall sweep; idx=0xffffffff would index 0x138 bytes before the
-- container table and is deliberately NOT called)
-- PROBE 1247a: mmap_dmem (628) argument order and container reachability, plus
-- physhm (629) named-path error ordering.
--
-- Corrected argument map, decoded from the body at 0xabd540 (13.60):
--   uap[0x00] arg0 = physical offset / address   -> r12   (must be < 2^50: shl rax,0x32 ; jne EINVAL)
--   uap[0x08] arg1 = length                      -> [rbp-0x48] (= rsi)  (>= 0x4000 and 0x4000-aligned)
--   uap[0x10] arg2 = CONTAINER INDEX (dword)     -> rbx   (0xffffffff SKIPS the per-process lookup)
--   uap[0x18] arg3 = flags/prot (dword)          -> ebx   (bits must be a subset of 0x3f3)
--   uap[0x20] arg4 = extra bits (dword)          -> [rbp-0x60] (bits must be a subset of 0x6020d0)
--   uap[0x28] arg5 = extra address (qword)       -> [rbp-0x58] (must be < 2^50)
-- (An earlier reading had arg2 and arg3 swapped; that is why the first run would
--  have returned EINVAL for every row - flags 0xffffffff fails test ebx,0xfffffc0c.)
--
-- The capability stage is THREE helpers on cred = [proc+0x140]: 0x609560, 0x6095a0,
-- 0x6092d0 (abd5aa/abd5d7/abd5eb). Any refusal returns 1, and earlier probes got
-- 16/22 instead of 1, so a level-2 user passes all three.
--
-- The worker 0x3cb450 receives rcx = container index and computes
--   table = lea rip+0x3105979 ; imul rdx,r11,0x138 ; add r14,rdx
-- so idx = -1 lands 0x138 bytes BEFORE the global container table, and the code then
-- treats those bytes as a container (locks [r14+0x18], walks [r14+0x50], and WRITES
-- gs:[0] into [r14+0x50]). That is a kernel OOB write, so this probe does not call it.
-- The question here is only: does any in-range container index resolve for uid 1?
print("=== PROBE 1247a: mmap_dmem (628) container reachability + physhm (629) ordering ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function peek(addr, n)
  local s = ""
  for i=0,n-1 do
    local ok,v = pcall(function() return N(memory.read_byte(addr+i)) end)
    if ok then s = s .. string.format("%02X", v) else s = s .. "??" end
  end
  return s
end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function mmap(addr,len,prot,flags,fd,off) return N(mk(477)(addr,len,prot,flags,fd,off)) end

print(string.format("[0] pid=%d", N(mk(20)())))

local dmem   = mk(628)
local physhm = mk(629)
local SZ     = 0x4000

-- ------------------------------------------------------------------ part A
-- 0x3c33e0, the "container lookup" that gates arg2, is decoded as:
--   3c33e0 push rbp / mov rbp,rsp / xor eax,eax / cmp edi,0x15 / setb al / pop rbp / ret
-- i.e. just "return idx < 0x15" - there is NO per-process check. So 21 container
-- indices pass, and everything after that is decided by the worker's descriptor walk.
print("[A] 628(addr, len=0x4000, idx=0..0x14, flags=3, extra=0, extra_addr=0)")
for idx = 0, 0x14 do
  local rv = N(dmem(0, SZ, idx, 3, 0, 0))
  local e = ES()
  local note = ""
  if rv >= 0 and rv < 0x800000000000 then
    local h = peek(rv, 32)
    note = " bytes=" .. h
    if string.sub(h,1,8) == "7F454C46" then note = note .. "  *** ELF MAGIC ***" end
  end
  print(string.format("  idx=%-3d pa=00000000 -> rv=%d errno=\"%s\"%s", idx, rv, e, note))
end

print("[A2] same sweep at pa=0x100000 (kernel load address on a 2 MB boundary)")
for idx = 0, 0x14, 4 do
  local rv = N(dmem(0x100000, SZ, idx, 3, 0, 0))
  print(string.format("  idx=%-3d pa=00100000 -> rv=%d errno=\"%s\"", idx, rv, ES()))
end

print("[A3] flag and length controls at idx=0")
local ctl = {{0, SZ, 3}, {0, SZ, 0}, {0, SZ, 7}, {0, SZ, 0x40}, {0, 0x2000, 3}, {0, 0x4001, 3}, {0, 0x10000, 3}}
for _,c in ipairs(ctl) do
  local rv = N(dmem(c[1], c[2], 0, c[3], 0, 0))
  print(string.format("  pa=%X len=%X flags=%X -> rv=%d errno=\"%s\"", c[1], c[2], c[3], rv, ES()))
end

-- ------------------------------------------------------------------ part B
print("[B] 629 named path: which check refuses first")
local NAME = mmap(0, 0x1000, 3, 0x1002, -1, 0)
if NAME ~= nil and NAME ~= 0 and NAME < 0x800000000000 then
  local given = {"no_slash", "/a", "/phys", "/dev/physhm", "/sbl_srv", "/x", "/AAAAAAAAAA"}
  for _,n in ipairs(given) do
    for k=1,#n do wb(NAME+k-1, string.byte(n,k)) end
    wb(NAME+#n, 0)
    local rv = N(physhm(NAME, 2, 0, 0))
    print(string.format("  name=%-16s -> rv=%d errno=\"%s\"", "\""..n.."\"", rv, ES()))
  end
else
  print("  could not allocate the name buffer")
end

-- control: the anonymous form that already worked (arg0 == 1)
print("[B2] 629 anon form control")
for _,a0 in ipairs({1, 0}) do
  local rv = N(physhm(a0, 2, 0, 0))
  print(string.format("  arg0=%-3d -> rv=%d errno=\"%s\"", a0, rv, ES()))
end

print("=== DONE 1247a ===")