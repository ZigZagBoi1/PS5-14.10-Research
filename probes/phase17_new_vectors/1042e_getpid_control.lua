-- CRASH_CLASS: MODERATE
-- PROBE 1042e: CONTROL for 1042d. Two Lua callers, but each only calls getpid(20) in a loop.
-- 1042d died immediately after both loops started. Before reading that as a race hit, this
-- separates the two causes: a race hit in the aio table (needs the aio calls) versus the
-- loader's own call stub being unsafe from two Lua states at once (happens with any syscall).
-- If this dies, 1042d proves nothing about aio and the whole Lua-thread direction stops here.
print("=== PROBE 1042e ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end); if o then return to_num(v) end return -1 end
local function ad(x) return tonumber(tostring(x):match("0x(%x+)"),16) end

local N = 200000
local base=memory.alloc(0x100); local ba=ad(base)
for o=0,0xF8,8 do wq(ba+o,0) end
wq(ba+0x18,1)

local SRC = [[
local BASE=%d
local N=%d
local GO=%d
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local sc=mk(20)
local ok0,rv0=pcall(function() return sc(uint64(0)) end)
wd(BASE+0x70, ok0 and 1 or 0)
wd(BASE+0x74, ok0 and (rv0.tonumber and rv0:tonumber() or 0) or 0)
while BASE and false do end
local n=0
for i=1,N do
  local ok=pcall(function() return sc(uint64(0)) end)
  if ok then n=n+1 end
  if i %% 10000 == 0 then wd(BASE+0x08,i) end
end
wd(BASE+0x08,N); wd(BASE+0x10,n); wd(BASE+0x18,1)
]]

local src=string.format(SRC, ba, N, ba+0x18)
local ok=pcall(function() run_lua_code_in_new_thread(src,{async=true}) end)
print("[S] child spawn ok="..tostring(ok))

local ts=memory.alloc(16)
local function sleep_ms(ms) wq(ts,0); wq(ts+8,ms*1000000); pcall(function() mk(240)(uint64(ts),uint64(0)) end) end
sleep_ms(300)

local sc=mk(20)
local pn=0
for i=1,N do
  local okc=pcall(function() return sc(uint64(0)) end)
  if okc then pn=pn+1 end
  if i%50000==0 then
    print(string.format("[P] i=%d child=%d done=%d", i, rd(ba+0x08), rd(ba+0x10)))
  end
end
print(string.format("[Q] parent calls=%d child_last=%d child_ok=%d child_done=%d", pn, rd(ba+0x08), rd(ba+0x10), rd(ba+0x18)))
print("[Z] alive pid="..tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr,20))))
