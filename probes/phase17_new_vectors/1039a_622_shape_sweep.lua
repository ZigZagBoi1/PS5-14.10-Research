-- CRASH_CLASS: HIGH
-- PROBE 1039a: sys 622 dispatch with the CORRECT uap layout.
-- 1038a proved the command is uap slot 0 (`622(cmd, len, buf)`) and that cmd 0x100
-- returns 0 with 0x8002004E in the buffer while 0x302 with a 0x100-byte buffer kills
-- the game. The old 55b/55c sweep put the command in slot 1, so its uniform
-- 0x800E0001 answers described commands 0 and 1 only. This pass walks 0x300..0x520
-- with len=0 (no copyout) and a mapped arg3, so a command that only *reads* arg3
-- cannot fault. A marker precedes every call: if the game dies, the last marker names
-- the command and we restart from the next one.
print("=== PROBE 1039a ===")
local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(uint64(a)) end) if o then return to_num(v) end return -1 end

local sc_sig=mk(416); local sc622=mk(622); local sc_pid=mk(20)
local act=memory.alloc(0x28); local aa=as_addr(act)
for o=0,0x20,8 do wd(aa+o,0) end
wd(aa,1)
local okS,vS=pcall(function() return sc_sig(uint64(12),uint64(aa),uint64(0)) end)
print(string.format("[S] shield=%s pid=%d", tostring(to_num(vS)), to_num(select(2,pcall(function() return sc_pid() end)))))

local buf=memory.alloc(0x200); local ba=as_addr(buf)
for o=0,0x1F8,4 do wd(ba+o,0xCDCDCDCD) end

local from=0x300; local to=0x520
for c=from,to do
  wd(ba,0xCDCDCDCD)
  print(string.format(">%X", c))
  local ok,v=pcall(function() return sc622(uint64(c),uint64(0),uint64(ba),uint64(0),uint64(0),uint64(0)) end)
  local rv = ok and to_num(v) or -999
  local q0 = rd(ba)
  if rv~=0 or q0~=0xCDCDCDCD then
    print(string.format("[622] cmd=%X rv=%s q0=%X", c, tostring(rv), q0))
  end
end
print("[Z] sweep reached "..string.format("%X",to))
