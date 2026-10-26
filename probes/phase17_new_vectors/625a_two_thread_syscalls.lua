-- CRASH_CLASS: MODERATE
-- PROBE 625a: helper Lua thread and parent issuing syscalls at the same time
print("=== PROBE 625a: TWO THREAD SYSCALLS ===")
local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local fn=syscall.pipe.fn_addr
local CTX=memory.alloc(0x100)
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end) if o then return N(v) end return nil end
for i=0,0xFC,4 do wd(N(CTX)+i,0) end
local function gpid() return N(native.fcall_with_rax(fn,20)) end
local me=gpid()
print(string.format("[A] pid=%d",me))

local body=[==[
local CTX=]==] .. tostring(N(CTX)) .. [==[
local fn=syscall.pipe.fn_addr
local function N2(v)
  if type(v)=="table" and v.tonumber then return v:tonumber() end
  if type(v)=="table" and v.h then return v.h*4294967296+v.l end
  return tonumber(v) or 0
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
wd(CTX+8,1)
for i=1,200 do
  local ok,p=pcall(function() return native.fcall_with_rax(fn,20) end)
  if ok and N2(p)>0 then wd(CTX+4,i) end
end
wd(CTX+12,1)
]==]
run_lua_code_in_new_thread(body,{async=true})
local mine,n=0,0
for i=1,200 do
  local ok,p=pcall(function() return native.fcall_with_rax(fn,20) end)
  n=n+1
  if ok and N(p)==me then mine=mine+1 end
end
print(string.format("[B] parent calls=%d ok=%d",n,mine))
for k=1,200000 do if rd(N(CTX)+12)==1 then break end end
print(string.format("[C] helper started=%s calls=%s done=%s",tostring(rd(N(CTX)+8)),tostring(rd(N(CTX)+4)),tostring(rd(N(CTX)+12))))
print(string.format("[D] alive pid=%d",gpid()))
print("[Z] alive")
