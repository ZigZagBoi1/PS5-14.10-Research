-- CRASH_CLASS: HIGH
-- PROBE 1072a: the one discriminator 1040a could not run. 622 cmd 0x302 kills the process
-- whenever uap slot 3 is our own mapped user page, which is the signature either of a CPL0
-- dereference under SMAP or of a death unrelated to arg3. The kernel image is mapped
-- supervisor-only at 0xFFFFFFFF9C800000 this boot (1004a/1005a, 0x6200000 bytes), so passing
-- that address separates the two: a raw kernel dereference of a SUPERVISOR page succeeds where
-- the same dereference of a user page faults. Case order is by information value, because the
-- probe dies at the first case that kills the process - print-before-call names the killer.
print("=== PROBE 1072a: 622 / 0x302 ARG3 AS KERNEL POINTER ===")
print("")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function hi_of(q) if type(q)=="table" and q.h then return q.h, q.l end local n=to_num(q) return math.floor(n/4294967296), n%4294967296 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rqw(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end

local sc_sig=mk(416); local sc622=mk(622); local sc_pid=mk(20)
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local okS,vS=pcall(function() return sc_sig(uint64(12),uint64(aa),uint64(0)) end)
local function alive() local o,v=pcall(function() return sc_pid() end) if o then return tostring(to_num(v)) end return "dead" end
print(string.format("[S] sigsys-ignore ok=%s rv=%s pid=%s", tostring(okS), okS and tostring(to_num(vS)) or "-", alive()))
print("")

local K   = 0xFFFFFFFF9C800000        -- measured image base this boot
local KA  = 0xFFFFFFFF9C800000 + 0x1000
local NB  = 0x100
local buf = memory.alloc(NB); local ba = as_addr(buf)
-- 0x4141414141414141 is above 2^53, so uint64.lua's number path stores 0x4141414141414100
-- rather than the literal. That is harmless for a "did any byte change" reading, but it is why
-- nothing here compares the buffer against an exact all-ones value.
local function fill() for i=0,NB/8-1 do wd(ba+i*8,0x41414141); wd(ba+i*8+4,0x41414141) end end
local function dump(tag)
  local s=""
  for i=0,3 do
    local vq=rqw(ba+i*8); local h,l=hi_of(vq)
    s=s..string.format(" q%d=%X_%08X", i, h, l)
  end
  print(string.format("    %s rv-returned%s", tag, s))
end

-- The user-page baseline runs first so the run has a control even if a later case dies.
-- The unmapped kernel half (0xFFFFFFFF00000000) and a NULL pointer are deliberately absent:
-- both are most likely to fault in kernel mode, and a kernel-mode fault with pcb_onfault==NULL
-- goes through trap_fatal to a console panic, not a process kill. Neither case could separate
-- the hypotheses anyway, so they are not worth the console.
local cases = {
  { "user-page", 0x302, 0,    ba, ba,  0, 0 },
  { "K-base",    0x302, 0,    ba, K,   0, 0 },
  { "K+0x1000",  0x302, 0,    ba, KA,  0, 0 },
  { "len=0x10",  0x302, 0x10, ba, K,   0, 0 },
  { "arg2=K",    0x302, K,    ba, 0,   0, 0 },
}
for _,c in ipairs(cases) do
  fill()
  print(string.format("[%s] 622(0x302, a2=%X, a3=buf, a4=%X, 0, 0)", c[1], to_num(c[3]), to_num(c[5])))
  local ok,rv = pcall(function()
    return sc622(uint64(to_num(c[2])),uint64(to_num(c[3])),uint64(to_num(c[4])),
                 uint64(to_num(c[5])),uint64(to_num(c[6])),uint64(to_num(c[7])))
  end)
  local r = ok and to_num(rv) or -999
  print(string.format("    rv=%s pid=%s", tostring(r), alive()))
  dump("buf")
end
print("")
print("=== DONE 1072a ===")
