-- CRASH_CLASS: LOW
-- PROBE: Kernel Pointer Harvester
--
-- On 13.60 jailbroken: systematically collect kernel pointer values
-- from every available source. This builds the offset database that
-- lets us translate 13.60 addresses to 14.10.
--
-- Sources we check:
-- 1. Thread control block (TCB)
-- 2. Process credential structure
-- 3. File descriptor table
-- 4. VM map entries
-- 5. Sysctl output buffers with detailed inspection
-- 6. Socket structures
-- 7. Module info extended (sys 608)

print("=== KERNEL POINTER HARVEST v1 ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local function is_kptr(val)
    if not val then return false end
    local h, l = get_hi_lo(val)
    -- Kernel pointers: 0xFFFF8000_00000000 to 0xFFFFFFFF_FFFFFFFF
    -- Excluding sentinels like 0xFFFFFFFF_00000000, 0xFFFFFFFF_FFFFFFFF
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    if h == 0xFFFFFFFF and l ~= 0 and l ~= 0xFFFFFFFF and l > 0x1000 then return true end
    return false
end

local sc_getpid = make_syscall(20)
local pid = to_num(sc_getpid())
print("PID: " .. pid)

local kptrs_found = {}
local function record_kptr(source, offset, val)
    local h, l = get_hi_lo(val)
    local addr_str = string.format("0x%08X%08X", h, l)
    print(string.format("KPTR[%s+0x%X] = %s", source, offset, addr_str))
    table.insert(kptrs_found, {source=source, offset=offset, addr=addr_str})
end

-- === Source 1: kinfo_proc deep scan ===
print("")
print("=== SOURCE 1: kinfo_proc deep scan ===")
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 1)   -- KERN_PROC_PID
safe_wd(mib + 12, pid)
local kinfo = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0x800)
safe_wd(oldlenp + 4, 0)
local ret = sc_sysctl(uint64(mib), uint64(4), uint64(kinfo), uint64(oldlenp), uint64(0), uint64(0))

if to_num(ret) == 0 then
    local kinfo_len = safe_rd(oldlenp) or 0
    print("KINFO_SIZE: " .. kinfo_len)
    -- Scan every qword for kernel pointers
    for off = 0, kinfo_len - 8, 8 do
        local val = safe_rq(kinfo + off)
        if is_kptr(val) then
            record_kptr("kinfo_proc", off, val)
        end
    end
else
    print("kinfo_proc FAILED: " .. to_num(ret))
end

-- === Source 2: Module info extended (sys 608) ===
print("")
print("=== SOURCE 2: dynlib_get_info_ex (sys 608) ===")
local sc_608 = make_syscall(608)
for handle = 0, 5 do
    local info_ex = memory.alloc(0x400)
    safe_wd(info_ex, 0x400)  -- size field
    local ok = pcall(function() sc_608(uint64(handle), uint64(1), info_ex) end)
    if ok then
        -- Scan for kernel pointers
        for off = 0, 0x3F8, 8 do
            local val = safe_rq(info_ex + off)
            if is_kptr(val) then
                record_kptr("info_ex_h" .. handle, off, val)
            end
        end
    end
end

-- === Source 3: Credential structure (sys 587) ===
print("")
print("=== SOURCE 3: Credential (sys 587) ===")
local sc_587 = make_syscall(587)
local cred_buf = memory.alloc(0x200)
safe_wd(cred_buf, 0x200)
local cret = sc_587(uint64(0), uint64(cred_buf))
if to_num(cret) == 0 then
    print("CRED_OK")
    for off = 0, 0x1F8, 8 do
        local val = safe_rq(cred_buf + off)
        if is_kptr(val) then
            record_kptr("cred", off, val)
        end
    end
    -- Also report the capability bits
    local cap = safe_rd(cred_buf + 0x0C)
    print("CRED_CAP: " .. string.format("0x%08X", cap or 0))
else
    print("CRED_FAILED: " .. to_num(cret))
end

-- === Source 4: AF_ROUTE messages ===
print("")
print("=== SOURCE 4: AF_ROUTE messages ===")
local sc_socket = make_syscall(97)
local route_fd = sc_socket(uint64(17), uint64(3), uint64(0))  -- AF_ROUTE, SOCK_RAW
local rfd = to_num(route_fd)
print("ROUTE_FD: " .. rfd)

if rfd >= 0 then
    -- RTM_GET for default route
    local rtm = memory.alloc(256)
    -- RTM_GET header
    safe_wd(rtm + 0, 152)    -- rtm_msglen
    safe_wd(rtm + 2, 4)      -- RTM_GET (version=5, type=4)
    -- actually: +0=msglen(2), +2=version(1), +3=type(1)
    -- Safe approach: build the header byte by byte
    -- But for now, just send and see what comes back

    local sc_write = make_syscall(4)
    local sc_read = make_syscall(3)

    -- Read any pending route messages
    local route_buf = memory.alloc(0x2000)
    local rret = sc_read(uint64(rfd), uint64(route_buf), uint64(0x2000))
    local rbytes = to_num(rret)
    print("ROUTE_READ: " .. rbytes .. " bytes")

    if rbytes > 0 then
        for off = 0, rbytes - 8, 8 do
            local val = safe_rq(route_buf + off)
            if is_kptr(val) then
                record_kptr("route", off, val)
            end
        end
    end

    local sc_close = make_syscall(6)
    sc_close(uint64(rfd))
end

-- === Source 5: TCP_INFO deep scan ===
print("")
print("=== SOURCE 5: TCP_INFO ===")
local tcp_fd = sc_socket(uint64(2), uint64(1), uint64(6))  -- AF_INET, SOCK_STREAM, TCP
local tfd = to_num(tcp_fd)
if tfd >= 0 then
    local sc_getsockopt = make_syscall(118)
    local tcp_info = memory.alloc(512)
    local tcp_len = memory.alloc(8)
    safe_wd(tcp_len, 512)

    -- SOL_TCP=6, TCP_INFO=0x20
    local sret = sc_getsockopt(uint64(tfd), uint64(6), uint64(0x20), uint64(tcp_info), uint64(tcp_len))
    if to_num(sret) == 0 then
        local actual = safe_rd(tcp_len) or 0
        print("TCP_INFO_SIZE: " .. actual)
        for off = 0, actual - 8, 8 do
            local val = safe_rq(tcp_info + off)
            if is_kptr(val) then
                record_kptr("tcp_info", off, val)
            end
        end
    end

    local sc_close = make_syscall(6)
    sc_close(uint64(tfd))
end

-- === Summary ===
print("")
print("=== HARVEST SUMMARY ===")
print("TOTAL_KPTRS: " .. #kptrs_found)
for _, kp in ipairs(kptrs_found) do
    print(string.format("  %s+0x%X = %s", kp.source, kp.offset, kp.addr))
end
print("")
print("=== KERNEL POINTER HARVEST v1 COMPLETE ===")
