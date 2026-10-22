-- CRASH_CLASS: LOW
-- PROBE 102d: scan ifindex 0-20 for a non-wedged netcontrol queue
--
-- Both ifindex=-1 (0xFFFFFFFF) and ifindex=1 are wedged from prior runs.
-- netcontrol state is per-interface in kernel, persists across process death.
-- Need to find a clean interface index for further UAF testing.

print("=== PROBE 102d: NETCONTROL IFINDEX SCAN ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local sc_socket=mk(97)
local sc_close=mk(6)
local sc_nc=mk(99)
local BUF=memory.alloc(0x20)

local function sock()
    local ok,rv=pcall(function() return sc_socket(uint64(1),uint64(2),uint64(0)) end)
    return ok and N(rv) or -1
end

local function nc_op(ifidx, cmd, fd)
    z(BUF,0x10); wd(BUF, fd)
    local ok,rv=pcall(function()
        return sc_nc(uint64(ifidx),uint64(cmd),uint64(BUF),uint64(8))
    end)
    return ok and N(rv) or -999
end

-- Test register+unregister on each ifindex
-- If register=0 and unregister=0 → clean queue
-- If register=-1 → wedged or invalid interface
for idx=0,20 do
    local fd=sock()
    if fd<0 then
        print(string.format("  ifindex=%2d: SOCKET FAIL", idx))
    else
        local reg=nc_op(idx, 0x20000003, fd)
        local unreg=-999
        if reg==0 then
            unreg=nc_op(idx, 0x20000007, fd)
        end
        pcall(function() sc_close(uint64(fd)) end)

        local status="UNKNOWN"
        if reg==0 and unreg==0 then status="CLEAN"
        elseif reg==0 and unreg~=0 then status="REG OK, UNREG FAIL"
        elseif reg==-1 then status="WEDGED/INVALID"
        else status="reg="..reg end

        print(string.format("  ifindex=%2d: reg=%d unreg=%d → %s",
            idx, reg, unreg, status))
    end
end

-- Also test some higher values
for _,idx in ipairs({100, 200, 255, 1000, 65535}) do
    local fd=sock()
    if fd>=0 then
        local reg=nc_op(idx, 0x20000003, fd)
        local unreg=-999
        if reg==0 then unreg=nc_op(idx, 0x20000007, fd) end
        pcall(function() sc_close(uint64(fd)) end)
        local status=(reg==0 and unreg==0) and "CLEAN" or
            (reg==-1 and "WEDGED/INVALID" or "reg="..reg)
        print(string.format("  ifindex=%5d: reg=%d unreg=%d → %s",
            idx, reg, unreg, status))
    end
end

print("")
print("=== 102d COMPLETE ===")
