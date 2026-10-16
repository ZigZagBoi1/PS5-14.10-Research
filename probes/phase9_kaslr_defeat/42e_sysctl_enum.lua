-- CRASH_CLASS: SAFE (read-only sysctl enumeration)
-- PROBE 42e: Enumerate ALL available sysctls via meta-interface
--
-- FreeBSD sysctl meta-interface:
--   {0, 1, <oid...>} = get next OID in tree
--   {0, 2, <oid...>} = get name of OID
--   {0, 4, <oid...>} = get format string of OID
--
-- Strategy: walk the entire sysctl tree, try to read each one,
-- and check for kernel addresses in any that return data.

print("=== PROBE 42e: SYSCTL ENUMERATION ===")
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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

local sc_sysctl = make_syscall(202)
local sc_getpid = make_syscall(20)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

-- Buffers
local mib_buf = memory.alloc(64)
local next_buf = memory.alloc(64)
local name_buf = memory.alloc(256)
local val_buf = memory.alloc(0x200)
local len_buf = memory.alloc(8)

local kptrs = {}
local readable_count = 0
local total_found = 0

-- Get next OID: sysctl({0, 1, <current_oid>}, len+2, next_oid, &next_len, NULL, 0)
local function get_next_oid(current_oid, current_len)
    -- Build query MIB: {0, 1, current_oid[0], current_oid[1], ...}
    safe_wd(mib_buf, 0)
    safe_wd(mib_buf + 4, 1)
    for i = 0, current_len - 1 do
        safe_wd(mib_buf + 8 + i * 4, current_oid[i + 1])
    end

    -- Output: next OID
    safe_wd(len_buf, 64)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib_buf), uint64(current_len + 2),
            uint64(next_buf), uint64(len_buf), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    if rv ~= 0 then return nil end

    local out_len = safe_rd(len_buf) or 0
    local oid_count = math.floor(out_len / 4)
    if oid_count <= 0 then return nil end

    local result = {}
    for i = 0, oid_count - 1 do
        result[i + 1] = safe_rd(next_buf + i * 4) or 0
    end
    return result
end

-- Get name of OID: sysctl({0, 2, oid...}, len+2, name_out, &name_len, NULL, 0)
local function get_oid_name(oid)
    safe_wd(mib_buf, 0)
    safe_wd(mib_buf + 4, 2)
    for i = 1, #oid do
        safe_wd(mib_buf + 4 + i * 4, oid[i])
    end

    safe_wd(len_buf, 256)
    local ok, ret = pcall(function()
        return sc_sysctl(uint64(mib_buf), uint64(#oid + 2),
            uint64(name_buf), uint64(len_buf), uint64(0), uint64(0))
    end)
    if not ok or to_num(ret) ~= 0 then return nil end

    local nlen = safe_rd(len_buf) or 0
    if nlen <= 0 then return nil end

    local name = ""
    for i = 0, math.min(nlen - 1, 127) do
        local b = safe_rd(name_buf + i)
        if b then
            b = b % 256
            if b == 0 then break end
            if b >= 0x20 and b < 0x7F then name = name .. string.char(b) end
        end
    end
    return name
end

-- Try to read the value of an OID and check for kernel pointers
local function try_read_oid(oid, name)
    for i = 0, 0x1F, 4 do safe_wd(val_buf + i, 0) end
    safe_wd(len_buf, 0x200)

    -- Build the MIB
    local qmib = memory.alloc(#oid * 4)
    for i = 1, #oid do safe_wd(qmib + (i-1) * 4, oid[i]) end

    local ok, ret = pcall(function()
        return sc_sysctl(uint64(qmib), uint64(#oid),
            uint64(val_buf), uint64(len_buf), uint64(0), uint64(0))
    end)
    local rv = ok and to_num(ret) or -999
    if rv ~= 0 then return false end

    local vlen = safe_rd(len_buf) or 0
    if vlen <= 0 then return false end

    readable_count = readable_count + 1

    -- Scan for kernel pointers
    local found = false
    for off = 0, math.min(vlen - 8, 0x1F8), 8 do
        local q = safe_rq(val_buf + off)
        if q then
            local h, l = get_hi_lo(q)
            if h >= 0xFFFF8000 then
                print(string.format("  *** %s +%03X: %08X_%08X KPTR!", name, off, h, l))
                kptrs[#kptrs + 1] = {src = name, off = off, h = h, l = l}
                found = true
            end
        end
    end

    return found
end

--------------------------------------------------------------------
-- Walk the sysctl tree
--------------------------------------------------------------------
print("Walking sysctl tree...")
print("")

local current = {1}  -- start from CTL_KERN (1)
local max_iter = 500
local iter = 0

-- Keep track to print interesting readable ones
local readable_names = {}

while iter < max_iter do
    iter = iter + 1

    local name = get_oid_name(current)
    if name then
        total_found = total_found + 1
        local had_kptr = try_read_oid(current, name)
        if had_kptr then
            -- already printed
        end
        -- Track readable names (just record, print summary at end)
        if readable_count > #readable_names then
            readable_names[#readable_names + 1] = name
        end
    end

    -- Get next OID
    local next_oid = get_next_oid(current, #current)
    if not next_oid then break end

    -- Safety: don't go past top-level 20
    if next_oid[1] and next_oid[1] > 20 then break end

    current = next_oid
end

print("")
print("=== ENUMERATION RESULTS ===")
print(string.format("OIDs found: %d", total_found))
print(string.format("Readable: %d", readable_count))
print(string.format("Kernel pointers: %d", #kptrs))

if #kptrs > 0 then
    print("")
    print("*** KERNEL POINTERS FOUND ***")
    for _, kp in ipairs(kptrs) do
        print(string.format("  [%s +%03X] %08X_%08X", kp.src, kp.off, kp.h, kp.l))
    end
end

-- Print all readable sysctl names
print("")
print("Readable sysctls:")
for _, n in ipairs(readable_names) do
    print("  " .. n)
end

print("")
print("=== PROBE 42e COMPLETE ===")
