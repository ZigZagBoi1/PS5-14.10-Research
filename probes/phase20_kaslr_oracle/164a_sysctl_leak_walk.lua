-- CRASH_CLASS: LOW
-- PROBE 164a: Walk sysctl tree hunting kernel pointer leaks
-- Targets: debug.*, machdep.*, kern.msgbuf, kern.proc info

print("=== PROBE 164a: SYSCTL KERNEL LEAK WALK ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    if h == 0 and l == 0 then return "0" end
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc202 = make_syscall(202)  -- __sysctl
local sc20 = make_syscall(20)

local ok, pid_raw = pcall(function() return sc20() end)
local pid = ok and to_num(pid_raw) or 0
print("PID: " .. pid)
print("")

local mib = memory.alloc(32)
local oldlen_buf = memory.alloc(8)
local data_buf = memory.alloc(0x4000)  -- 16KB

local function try_sysctl(name, mib_vals, mib_len, buf_size)
    buf_size = buf_size or 0x1000
    for i, v in ipairs(mib_vals) do
        memory.write_dword(mib + (i-1)*4, v)
    end
    memory.write_qword(oldlen_buf, uint64(buf_size))
    for i = 0, math.min(buf_size-1, 127), 8 do
        memory.write_qword(data_buf + i, uint64(0))
    end

    local ok1, rv = pcall(function()
        return sc202(uint64(mib), uint64(mib_len), uint64(data_buf), uint64(oldlen_buf), uint64(0), uint64(0))
    end)
    if not ok1 then return nil, "PCALL-FAIL" end

    local h, l = get_hi_lo(rv)
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return nil, "EPERM/ENOENT" end

    local dlen = to_num(memory.read_qword(oldlen_buf))
    return dlen, "OK"
end

local function scan_for_kernel_ptrs(dlen, label)
    local found = {}
    local limit = math.min(dlen, 0x4000)
    for off = 0, limit - 8, 8 do
        local val = memory.read_qword(data_buf + off)
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h <= 0xFFFFFFFF then
            found[#found+1] = string.format("    off=0x%04X: 0x%X%08X", off, h, l)
        end
    end
    if #found > 0 then
        print("  " .. label .. ": KERNEL POINTERS FOUND!")
        for _, f in ipairs(found) do print(f) end
        return true
    end
    return false
end

local function read_string(max_len)
    max_len = max_len or 256
    local parts = {}
    for i = 0, max_len - 4, 4 do
        local ok_b, raw = pcall(function() return memory.read_dword(data_buf + i) end)
        if not ok_b then break end
        local dw = to_num(raw)
        for shift = 0, 24, 8 do
            local byte = math.floor(dw / (2^shift)) % 256
            if byte == 0 then return table.concat(parts) end
            if byte >= 32 and byte < 127 then
                parts[#parts+1] = string.char(byte)
            else
                parts[#parts+1] = "."
            end
        end
    end
    return table.concat(parts)
end

-- ============================================================
-- 1. Walk top-level sysctl OIDs (0-12) to find accessible trees
-- sysctl MIB {0, 1} = get next OID after a given OID
-- ============================================================
print("=== 1. Top-level sysctl trees ===")
-- CTL_KERN=1, CTL_VM=2, CTL_VFS=3, CTL_NET=4, CTL_DEBUG=5,
-- CTL_HW=6, CTL_MACHDEP=7, CTL_USER=8, CTL_P1003_1B=9
local trees = {
    {1, "kern"}, {2, "vm"}, {3, "vfs"}, {4, "net"},
    {5, "debug"}, {6, "hw"}, {7, "machdep"}, {8, "user"}, {9, "p1003_1b"},
}
for _, tree in ipairs(trees) do
    -- Try to get size of first child
    memory.write_dword(mib, tree[1])
    memory.write_qword(oldlen_buf, uint64(0))
    local ok2, rv2 = pcall(function()
        return sc202(uint64(mib), uint64(1), uint64(0), uint64(oldlen_buf), uint64(0), uint64(0))
    end)
    local h, l = 0, 0
    if ok2 then h, l = get_hi_lo(rv2) end
    local accessible = ok2 and not (h == 0xFFFFFFFF and l == 0xFFFFFFFF)
    print(string.format("  %s(%d): %s", tree[2], tree[1], accessible and "accessible" or "blocked"))
end
print("")

-- ============================================================
-- 2. kern.msgbuf — kernel message buffer (dmesg)
-- MIB: {1, 8} on some, or name2oid lookup
-- Actually: kern.msgbuf = {1, 28}
-- ============================================================
print("=== 2. kern.msgbuf (dmesg) ===")
local dlen, status = try_sysctl("kern.msgbuf", {1, 28}, 2, 0x4000)
print("  status=" .. status .. " len=" .. (dlen or 0))
if dlen and dlen > 0 then
    local found = scan_for_kernel_ptrs(dlen, "kern.msgbuf")
    -- Print first 512 chars as text (after scan so we get ptrs even if text crashes)
    local tok, text = pcall(function() return read_string(math.min(dlen, 512)) end)
    if tok and text and #text > 0 then
        print("  text: " .. text:sub(1, 200))
    end
end
print("")

-- ============================================================
-- 3. debug tree — try first 20 children
-- ============================================================
print("=== 3. debug.* tree ===")
for child = 0, 20 do
    local dlen2, status2 = try_sysctl("debug." .. child, {5, child}, 2, 0x100)
    if status2 == "OK" and dlen2 and dlen2 > 0 then
        local val = memory.read_qword(data_buf)
        local h, l = get_hi_lo(val)
        local tag = ""
        if h >= 0xFFFF8000 then tag = " <<< KERNEL PTR!" end
        print(string.format("  debug.%d: len=%d val=%s%s", child, dlen2, fmt(val), tag))
    end
end
print("")

-- ============================================================
-- 4. machdep tree
-- ============================================================
print("=== 4. machdep.* tree ===")
for child = 0, 30 do
    local dlen3, status3 = try_sysctl("machdep." .. child, {7, child}, 2, 0x100)
    if status3 == "OK" and dlen3 and dlen3 > 0 then
        local val = memory.read_qword(data_buf)
        local h, l = get_hi_lo(val)
        local tag = ""
        if h >= 0xFFFF8000 then tag = " <<< KERNEL PTR!" end
        print(string.format("  machdep.%d: len=%d val=%s%s", child, dlen3, fmt(val), tag))
    end
end
print("")

-- ============================================================
-- 5. kern.proc subtree — various info
-- kern.proc = {1, 14}
-- ============================================================
print("=== 5. kern.proc.* for PID " .. pid .. " ===")
local proc_nodes = {
    {7,  "args"},
    {12, "pathname"},
    {14, "sv_name"},
    {32, "vmmap_size_only"},
    {33, "groups"},
    {35, "kstack"},
    {38, "cwd"},
    {39, "nfds"},
    {40, "sigfastblk"},
    {41, "vm_layout"},
}
for _, pn in ipairs(proc_nodes) do
    local dlen4, status4 = try_sysctl("kern.proc." .. pn[2], {1, 14, pn[1], pid}, 4, 0x1000)
    if status4 == "OK" and dlen4 and dlen4 > 0 then
        local found = scan_for_kernel_ptrs(dlen4, pn[2])
        -- Print raw first bytes
        local first_val = memory.read_qword(data_buf)
        local tok2, text = pcall(function() return read_string(math.min(dlen4, 128)) end)
        if tok2 and text and #text > 0 then
            print(string.format("  %-14s len=%d text=%s", pn[2], dlen4, text:sub(1,80)))
        else
            print(string.format("  %-14s len=%d val=%s", pn[2], dlen4, fmt(first_val)))
        end
    elseif status4 ~= "PCALL-FAIL" then
        -- Only print blocked, not crashes
        if status4 == "EPERM/ENOENT" then
            print(string.format("  %-14s blocked", pn[2]))
        end
    end
end
print("")

-- ============================================================
-- 6. hw subtree (hardware info might leak)
-- ============================================================
print("=== 6. hw.* tree ===")
for child = 0, 20 do
    local dlen5, status5 = try_sysctl("hw." .. child, {6, child}, 2, 0x100)
    if status5 == "OK" and dlen5 and dlen5 > 0 then
        local val = memory.read_qword(data_buf)
        local h, l = get_hi_lo(val)
        local tag = ""
        if h >= 0xFFFF8000 then tag = " <<< KERNEL PTR!" end
        local tok3, text = pcall(function() return read_string(math.min(dlen5, 64)) end)
        if tok3 and text and #text > 3 and dlen5 < 256 then
            print(string.format("  hw.%d: len=%d text=%s%s", child, dlen5, text:sub(1,60), tag))
        else
            print(string.format("  hw.%d: len=%d val=%s%s", child, dlen5, fmt(val), tag))
        end
    end
end
print("")

-- ============================================================
-- 7. Full vmmap scan — check ALL 45K bytes for kernel ptrs
-- ============================================================
print("=== 7. vmmap full scan (first 16KB) ===")
local vlen, vstatus = try_sysctl("vmmap", {1, 14, 32, pid}, 4, 0x4000)
print("  status=" .. vstatus .. " len=" .. (vlen or 0))
if vlen and vlen > 0 then
    -- Scan ALL qwords
    local kptrs = 0
    local highest_user = 0
    for off = 0, math.min(vlen, 0x4000) - 8, 8 do
        local val = memory.read_qword(data_buf + off)
        local h, l = get_hi_lo(val)
        if h >= 0xFFFF8000 and h <= 0xFFFFFFFF then
            kptrs = kptrs + 1
            if kptrs <= 5 then
                print(string.format("    off=0x%04X: 0x%X%08X", off, h, l))
            end
        end
        if h < 0x800 and l > highest_user then
            highest_user = l
        end
    end
    if kptrs > 0 then
        print("  Total kernel pointers: " .. kptrs)
    else
        print("  No kernel pointers. Highest user addr: " .. string.format("0x%X", highest_user))
    end
end

print("")
print("=== PROBE 164a COMPLETE ===")
