-- CRASH_CLASS: MODERATE
-- PROBE 51a: Sony custom syscall survey (532-676)
--
-- Context: Kernel dump analysis of FW 13.60 revealed 116 Sony-custom syscalls
-- in the 532-676 range. Only 557, 593, and 620 have been tested on FW 14.10.
-- This probe systematically calls each one with safe args (zeros or small buffers)
-- to determine which are accessible from our sandbox and what they return.
-- Grouped by kernel code proximity to identify subsystems.

print("=== PROBE 51a: SONY SYSCALL SURVEY (532-676) ===")
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

-- Allocate shared buffers for syscall arguments
local buf1 = memory.alloc(0x1000)
local buf2 = memory.alloc(0x1000)
local buf3 = memory.alloc(0x1000)

-- Zero the buffers
for i = 0, 0xFF0, 4 do
    safe_wd(buf1 + i, 0)
    safe_wd(buf2 + i, 0)
    safe_wd(buf3 + i, 0)
end

-- Get PID for reference
local sc_getpid = make_syscall(20)
local pid = to_num(pcall(function() return sc_getpid() end) and sc_getpid() or 0)
print("PID: " .. pid)
print("")

-- Sony syscalls from 13.60 kernel dump analysis, grouped by subsystem
-- Format: {syscall_num, narg, group_name}
local sony_syscalls = {
    -- Dynamic linker group (TEXT+0x340000)
    {591, 3, "dynlib"}, {592, 3, "dynlib"}, {594, 4, "dynlib"},
    {595, 3, "dynlib"}, {596, 0, "dynlib"}, {598, 2, "dynlib"},
    {599, 0, "dynlib"}, {608, 3, "dynlib"}, {612, 1, "dynlib"},
    {649, 3, "dynlib"}, {656, 2, "dynlib"}, {659, 3, "dynlib"},
    {660, 2, "dynlib"}, {672, 3, "dynlib"},

    -- VM/memory group (TEXT+0xab0000)
    {547, 2, "vm"}, {548, 5, "vm"}, {559, 1, "vm"},
    {572, 4, "vm"}, {588, 3, "vm"}, {607, 2, "vm"},
    {613, 3, "vm"}, {615, 3, "vm"}, {618, 3, "vm"},
    {624, 0, "vm"}, {628, 6, "vm"}, {637, 2, "vm"},
    {642, 4, "vm"}, {646, 1, "vm"}, {647, 1, "vm"},
    {671, 4, "vm"}, {674, 5, "vm"},

    -- Sony subsystem C (TEXT+0xc10000, 549-556)
    {549, 4, "sysC"}, {550, 1, "sysC"}, {551, 1, "sysC"},
    {552, 1, "sysC"}, {553, 3, "sysC"}, {554, 2, "sysC"},
    {555, 2, "sysC"}, {556, 3, "sysC"},

    -- Sony subsystem D (TEXT+0xba0000-bb0000, 538-546)
    {538, 3, "sysD"}, {539, 1, "sysD"}, {540, 1, "sysD"},
    {541, 1, "sysD"}, {542, 5, "sysD"}, {543, 4, "sysD"},
    {544, 2, "sysD"}, {545, 2, "sysD"}, {546, 3, "sysD"},

    -- Process/thread group (TEXT+0x600000, 563-567 + 625-626)
    {563, 1, "proc"}, {564, 1, "proc"}, {565, 3, "proc"},
    {566, 3, "proc"}, {567, 3, "proc"}, {625, 4, "proc"},
    {626, 5, "proc"},

    -- Device/IPC group (TEXT+0x3b0000, 661-670)
    {661, 4, "dev"}, {662, 3, "dev"}, {663, 5, "dev"},
    {664, 3, "dev"}, {665, 2, "dev"}, {666, 3, "dev"},
    {668, 2, "dev"}, {669, 5, "dev"}, {670, 4, "dev"},

    -- Misc groups
    {532, 5, "misc"}, {533, 3, "misc"}, {534, 2, "misc"},
    {535, 4, "io"}, {536, 3, "io"}, {558, 2, "misc"},
    {560, 1, "io"}, {585, 0, "fs"}, {586, 1, "misc"},
    {587, 2, "io"}, {600, 1, "evt"}, {601, 3, "evt"},
    {602, 3, "evt"}, {603, 2, "fd"}, {604, 5, "io"},
    {605, 1, "evt"}, {606, 0, "evt"}, {610, 1, "misc"},
    {611, 3, "evt"}, {616, 2, "thr"}, {617, 1, "misc"},
    {622, 6, "vm"}, {623, 1, "misc"}, {627, 2, "io"},
    {629, 4, "misc"}, {630, 1, "misc"}, {632, 1, "thr"},
    {633, 1, "thr"}, {634, 2, "thr"}, {636, 2, "misc"},
    {638, 4, "misc"}, {639, 5, "misc"}, {640, 8, "misc"},
    {641, 2, "io"}, {643, 1, "evt"}, {648, 1, "misc"},
    {652, 2, "proc"}, {653, 1, "misc"}, {654, 5, "misc"},
    {655, 3, "misc"}, {657, 4, "misc"}, {658, 1, "fs"},
    {667, 2, "io"}, {673, 4, "misc"}, {675, 2, "misc"},
    {676, 0, "misc"},
}

print("Testing " .. #sony_syscalls .. " Sony syscalls via make_syscall...")
print("")

local accessible = {}
local killed = {}
local errors = {}

for idx, entry in ipairs(sony_syscalls) do
    local num = entry[1]
    local narg = entry[2]
    local group = entry[3]

    local sc = make_syscall(num)
    local ok, ret

    if narg == 0 then
        ok, ret = pcall(function() return sc() end)
    elseif narg == 1 then
        ok, ret = pcall(function() return sc(uint64(0)) end)
    elseif narg == 2 then
        ok, ret = pcall(function() return sc(uint64(0), uint64(0)) end)
    elseif narg == 3 then
        ok, ret = pcall(function() return sc(uint64(0), uint64(0), uint64(0)) end)
    elseif narg == 4 then
        ok, ret = pcall(function() return sc(uint64(buf1), uint64(buf2), uint64(0), uint64(0)) end)
    elseif narg == 5 then
        ok, ret = pcall(function() return sc(uint64(buf1), uint64(buf2), uint64(buf3), uint64(0), uint64(0)) end)
    elseif narg == 6 then
        ok, ret = pcall(function() return sc(uint64(buf1), uint64(buf2), uint64(buf3), uint64(0), uint64(0), uint64(0)) end)
    elseif narg == 8 then
        ok, ret = pcall(function() return sc(uint64(buf1), uint64(buf2), uint64(buf3), uint64(0), uint64(0), uint64(0)) end)
    end

    if ok then
        local rv = to_num(ret)
        local rh, rl = get_hi_lo(ret)
        local tag = ""
        if rv == 0 then tag = " [SUCCESS]"
        elseif rv == -1 or rv == 4294967295 then tag = " [EPERM/ENOSYS?]"
        elseif rh >= 0xFFFF8000 then tag = " [KERNEL PTR!!!]"
        end

        -- Check if buffer was modified (for narg >= 4)
        local buf_mod = ""
        if narg >= 4 then
            local v1 = safe_rd(buf1)
            local v2 = safe_rd(buf2)
            if v1 ~= 0 or v2 ~= 0 then
                buf_mod = string.format(" buf1[0]=%08X buf2[0]=%08X", v1 or 0, v2 or 0)
                -- Re-zero for next test
                safe_wd(buf1, 0)
                safe_wd(buf2, 0)
            end
        end

        if rv ~= -1 and rv ~= 4294967295 then
            table.insert(accessible, {num, rv, rh, rl, group, buf_mod})
        end

        print(string.format("  [%s] %d: ret=%d (0x%08X_%08X)%s%s",
            group, num, rv, rh, rl, tag, buf_mod))
    else
        local err = tostring(ret)
        if err:find("killed") or err:find("signal") then
            table.insert(killed, {num, err, group})
            print(string.format("  [%s] %d: KILLED - %s", group, num, err))
        else
            table.insert(errors, {num, err, group})
            print(string.format("  [%s] %d: ERROR - %s", group, num, err))
        end
    end
end

print("")
print("=== SUMMARY ===")
print(string.format("Total tested: %d", #sony_syscalls))
print(string.format("Accessible (ret != -1): %d", #accessible))
print(string.format("Killed: %d", #killed))
print(string.format("Errors: %d", #errors))

if #accessible > 0 then
    print("")
    print("=== ACCESSIBLE SYSCALLS (non-error returns) ===")
    for _, entry in ipairs(accessible) do
        local num, rv, rh, rl, group, buf_mod = entry[1], entry[2], entry[3], entry[4], entry[5], entry[6]
        local tag = ""
        if rh >= 0xFFFF8000 then tag = " <<< KERNEL POINTER <<<" end
        print(string.format("  [%s] %d: ret=0x%08X_%08X%s%s", group, num, rh, rl, buf_mod, tag))
    end
end

if #killed > 0 then
    print("")
    print("=== SANDBOX-KILLED SYSCALLS ===")
    for _, entry in ipairs(killed) do
        print(string.format("  [%s] %d: %s", entry[3], entry[1], entry[2]))
    end
end

print("")
print("=== PROBE 51a COMPLETE ===")
