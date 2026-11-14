-- CRASH_CLASS: LOW (mmap + socketpair + write/recvfrom on our own VAs; no kernel deref,
-- no execution, no 628, no idx=-1)
-- PROBE 1250b: two corrections that do not need 629 to work.
--
-- [A] Does FreeBSD copyin fault a demand-zero page in?
--     Probe 1240a read a freshly mmap'ed page from the kernel (write(socket, va, n)) and
--     got EFAULT, and concluded "the mapping is not present".  That inference is only
--     valid if copyin does not fault.  FreeBSD's uiomove/vm_fault_quick_hold_pages does
--     fault user pages in, so a cold demand-zero page should still copy out zeros.  If
--     this kernel returns EFAULT for a cold page but success for a touched page, then
--     Sony hardened copyin and 1240a's conclusion was accidentally right; if the cold
--     page succeeds, 1240a's EFAULT was about something else entirely (a bad VA) and the
--     "PTE absent" claim in docs must be withdrawn.
--     Controls: an untouched anon page, the same page after one userland read, the second
--     page of the same mapping (still cold), and a plainly unmapped VA.
--
-- [B] 629 shm_open: is the second argument oflag rather than size?
--     Probe 1250a sent 629(1, 0x4000, fl, 0) for nine flag values and got EINVAL 22 every
--     time, including fl=0.  The decoded flags test is "test r15d,0xffdff1fc ; jne error",
--     and 0x4000 & 0xffdff1fc == 0x4000 - so if arg2 is oflag, EVERY one of those calls
--     died on the same check before any flag value mattered.  That single hypothesis
--     explains the uniform errno.  This section calls the 3-arg shape (name, oflag, mode)
--     and the 4-arg shape with the size in a different slot, and reports the errno for
--     each.  It also tests whether the anon form is "arg1 == 1" or "arg1 == NULL".
print("=== PROBE 1250b: copyin fault-in + 629 argument shape ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v = pcall(function() return N(memory.read_byte(a)) end) if ok then return v end return nil end
local function wr(a,v) local ok = pcall(function() memory.write_byte(a,v) end) return ok end
local function mmap(addr,len,prot,flags,fd,off) return N(mk(477)(addr,len,prot,flags,fd,off)) end
local function okva(a) return a ~= nil and a > 0 and a < 0x800000000000 end

print(string.format("[0] pid=%d", N(mk(20)())))

-- ---------------------------------------------------------------- A
print("[A] copyin fault-in test on an anonymous mapping")
local va = mmap(0, 0x8000, 3, 0x1002, -1, 0)
print(string.format("    mmap(0,0x8000,3,MAP_ANON|PRIVATE) -> 0x%X errno=\"%s\"", va, ES()))
if okva(va) then
  local fp = memory.alloc(8)
  memory.write_dword(fp, 0); memory.write_dword(fp + 4, 0)
  local rv = N(mk(135)(1, 1, 0, uint64(fp)))
  local s1, s2 = N(memory.read_dword(fp)), N(memory.read_dword(fp + 4))
  print(string.format("    socketpair -> rv=%d s1=%d s2=%d errno=\"%s\"", rv, s1, s2, ES()))
  if rv == 0 and s1 > 2 and s2 > 2 then
    local obuf = mmap(0, 0x1000, 3, 0x1002, -1, 0)
    local function drain(tag)
      local got, n = "", 0
      if okva(obuf) then
        n = N(mk(29)(s2, obuf, 64, 0x80, 0, 0))
        if n > 0 then for i = 0, n - 1 do got = got .. string.format("%02X", rd(obuf + i) or 0) end end
      end
      print(string.format("      %s recv=%d data=%s", tag, n, got))
    end
    local function kern_read(tag, addr, len)
      local n = N(mk(4)(s1, addr, len))
      print(string.format("    %-42s write=%d errno=\"%s\"", tag, n, ES()))
      if n > 0 then drain("->") end
      return n
    end

    -- A1: cold page, never touched by userland
    kern_read("[A1] cold page (never touched)", va, 8)
    -- A2: touch it from userland with one byte, then repeat
    local b0 = rd(va)
    print(string.format("    userland read of the cold page -> %s", b0 and string.format("%02X", b0) or "FAULT"))
    kern_read("[A2] same page after 1 userland read", va, 8)
    -- A3: second page of the mapping is still cold
    kern_read("[A3] second page, still cold", va + 0x4000, 8)
    -- A4: write a byte into the second page, then read it kernel-side
    wr(va + 0x4000, 0x5A)
    kern_read("[A4] second page after 1 user write", va + 0x4000, 8)
    -- A5: control - plainly unmapped VA
    kern_read("[A5] control: unmapped 0x10000000", 0x10000000, 8)
    -- A6: control - NULL
    kern_read("[A6] control: NULL", 0, 8)
    -- A7: length crossing from a mapped page into an unmapped one
    kern_read("[A7] 0x2000 bytes from the last mapped page", va + 0x6000, 0x2000)
    mk(6)(s1); mk(6)(s2)
  end
end

-- ---------------------------------------------------------------- B
print("[B] 629 shm_open argument shape")
local shm = mk(629)
local function t(tag, a, b, c, d)
  local ok, v = pcall(function() return shm(a, b, c, d) end)
  local rv = -999
  if ok then rv = N(v) end
  print(string.format("    %-34s -> rv=%d errno=\"%s\"", tag, rv, ES()))
  return rv
end
print("  [B1] 3-arg (name, oflag, mode); name=1 is the anon sentinel")
for _,fl in ipairs({0, 1, 2, 3, 0x200, 0x201, 0x203, 0x20000, 0x200000}) do
  t(string.format("629(1, %06X, 0)", fl), 1, fl, 0, 0)
end
print("  [B2] 4-arg with the size in slot 3")
t("629(1, 1, 0x4000, 0)", 1, 1, 0x4000, 0)
t("629(1, 0x200, 0x4000, 0)", 1, 0x200, 0x4000, 0)
print("  [B3] name pointer forms (arg1 = 0, not 1)")
local nbuf = mmap(0, 0x1000, 3, 0x1002, -1, 0)
if okva(nbuf) then
  local function setn(s) for k = 1, #s do wr(nbuf + k - 1, string.byte(s, k)) end wr(nbuf + #s, 0) end
  for _,n in ipairs({"shm", "/shm", "/SceShm", "/"}) do
    setn(n)
    t(string.format("629(\"%s\", 1, 0)", n), nbuf, 1, 0, 0)
  end
end
print("=== DONE 1250b ===")
