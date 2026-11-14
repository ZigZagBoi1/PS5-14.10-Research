-- CRASH_CLASS: LOW
-- PROBE 1240b: is the physhm mapping absent, or present-but-supervisor? mincore decides.
--
-- 1240a showed that the kernel's own copyin from a 629() mapping returns EFAULT
-- (write(sock, 0x310D3C000, 0x20) -> -1 errno 14). A PTE with U/S=0 cannot fault
-- inside the uaccess stac window, so the reading is "the page is not present".
-- That is an inference from the helper's code, not a measurement of page state.
--
-- mincore(2) (sys 78, three args) reports residency of user pages without touching
-- them: rv 0 and vec[i] bit 0 set means the page is in core. Run it on
--   (1) a touched anonymous page   -> must read 1, or the probe proves nothing
--   (2) an untouched anonymous page
--   (3) the physhm mapping
--   (4) a kernel address            -> the range gate's answer
-- and the control decides whether any verdict is admissible.
--
-- Everything stays inside pcall. Nothing here loads from the physhm mapping, and
-- nothing calls read(3) on an empty socket: recvfrom(29) with MSG_DONTWAIT=0x80.
print("=== PROBE 1240b: physhm residency via mincore ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end if type(v)=="table" and v.h then return v.h*4294967296+v.l end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rby(a) local ok,v=pcall(function() return N(memory.read_byte(uint64(a))) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wb(a,v) pcall(function() memory.write_byte(uint64(a),uint64(v)) end) end
local function addrof(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return N(t) end
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
for i=0,0x3F do wb(mark+i, 0xC0+i) end
local marka = addrof(mark)
local out = memory.alloc(0x40); local outa = addrof(out)
local w = mk(4); local rcv = mk(29)
print("[A] control: write then recvfrom on the socketpair")
local ok1, rv1 = pcall(function() return w(uint64(s1),uint64(marka),uint64(0x20),uint64(0),uint64(0),uint64(0)) end)
local ok2, rv2 = pcall(function() return rcv(uint64(s2),uint64(outa),uint64(0x20),uint64(0x80),uint64(0),uint64(0)) end)
print(string.format("    write rv=%d | recvfrom rv=%d | %s", N(rv1), N(rv2), hex(outa,0x20)))
if N(rv2) <= 0 then print("[!] socketpair control failed - stopping") print("=== DONE 1240b ===") return end
print("[B] the mincore call shape")
local vec = memory.alloc(0x10)
local veca = addrof(vec)
local mc = mk(78)
local function mincore(addr, len)
  for k=0,0x0F do wd(veca+k,0xA5) end
  local ok, rv = pcall(function() return mc(uint64(addr),uint64(len),uint64(veca)) end)
  local v = -1; if ok then v = N(rv) end
  return v, ES(), rby(veca), rby(veca+1)
end
print("[C] control mappings")
local anon1 = N(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
local anon2 = N(mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)))
print(string.format("    anon1=0x%X anon2=0x%X", anon1, anon2))
wb(anon1, 0x5A)
local r1,e1,b0,b1 = mincore(anon1, 0x1000)
print(string.format("    mincore(touched anon 0x%X) rv=%d err=%s vec0=0x%02X vec1=0x%02X", anon1, r1, e1, b0, b1))
local r2,e2,c0,c1 = mincore(anon2, 0x1000)
print(string.format("    mincore(untouched anon 0x%X) rv=%d err=%s vec0=0x%02X vec1=0x%02X", anon2, r2, e2, c0, c1))
print(string.format("    control verdict: sys78 = %s", (r1==0 and b0%2==1) and "USABLE (touched page reads resident)" or "NOT USABLE - no verdict below is admissible"))
print("[D] the physhm mapping")
local pfd = -1
local okp, rvp = pcall(function() return mk(629)(uint64(1),uint64(2),uint64(0),uint64(0),uint64(0),uint64(0)) end)
if okp then pfd = N(rvp) end
print(string.format("    629(1,2,0,0) -> %d err=%s", pfd, ES()))
if pfd > 0 then
  local okm, base = pcall(function() return mk(477)(uint64(0),uint64(0x4000),uint64(3),uint64(1),uint64(pfd),uint64(0)) end)
  local b = -1; if okm then b = N(base) end
  print(string.format("    mmap -> 0x%X err=%s", b, ES()))
  if b > 0 then
    local r3,e3,d0,d1 = mincore(b, 0x1000)
    print(string.format("    mincore(physhm 0x%X) rv=%d err=%s vec0=0x%02X vec1=0x%02X", b, r3, e3, d0, d1))
    print(string.format("    => %s", (r3==0 and d0%2==0) and "rv 0 and NOT resident: the PTE is absent, not supervisor" or (r3==0 and "rv 0 and RESIDENT: the page is present, so the EFAULT is a different gate" or "mincore refused the address")))
    local okw, rvw = pcall(function() return w(uint64(s1),uint64(b),uint64(0x20),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("    copyin re-check write(s1, 0x%X, 0x20) rv=%d err=%s", b, N(rvw), ES()))
    local okq, rvq = pcall(function() return rcv(uint64(s2),uint64(outa),uint64(0x20),uint64(0x80),uint64(0),uint64(0)) end)
    print(string.format("    recvfrom rv=%d err=%s", N(rvq), ES()))
    local out547 = memory.alloc(0x40)
    for k=0,0x3F,4 do wd(addrof(out547)+k,0) end
    local ok547, rv547 = pcall(function() return mk(547)(uint64(b),uint64(addrof(out547)),uint64(0x40),uint64(0),uint64(0),uint64(0)) end)
    print(string.format("    547(0x%X) rv=%d err=%s | %s", b, N(rv547), ES(), hex(addrof(out547),0x20)))
  end
end
print("[E] mincore on a kernel address (the range gate)")
local r4,e4,f0,f1 = mincore(0xFFFFFFFF85000000, 0x1000)
print(string.format("    mincore(0xFFFFFFFF85000000) rv=%d err=%s vec0=0x%02X", r4, e4, f0))
print("=== DONE 1240b ===")
