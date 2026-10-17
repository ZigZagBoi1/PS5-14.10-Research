-- CRASH_CLASS: MODERATE
-- PROBE 51c: Sony syscall survey part 2 (untested remainder from 51a)
--
-- Context: 51a was cut short after ~55 syscalls (through the proc group).
-- This probe covers the remaining untested Sony syscalls: the device/IPC
-- group (661-670) and all misc/io/evt/thr/fs syscalls that 51a didn't reach.
-- Also re-tests a few from the end of the proc group that may not have run.

print("=== PROBE 51c: SONY SYSCALL SURVEY PART 2 ===")
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

local buf1 = memory.alloc(0x1000)
local buf2 = memory.alloc(0x1000)
local buf3 = memory.alloc(0x1000)

for i = 0, 0xFF0, 4 do
    safe_wd(buf1 + i, 0)
    safe_wd(buf2 + i, 0)
    safe_wd(buf3 + i, 0)
end

local sc_getpid = make_syscall(20)
local pid = to_num(pcall(function() return sc_getpid() end) and sc_getpid() or 0)
print("PID: " .. pid)
print("")

-- Syscalls that 51a didn't reach (dev group + misc/io/evt/thr/fs)
-- Also re-test 625, 626 from the end of proc group in case they were missed
local remaining = {
    -- Re-test end of proc group
    {625, 4, "proc"}, {626, 5, "proc"},

    -- Device/IPC group (TEXT+0x3b0000, 661-670)
    {661, 4, "dev"}, {662, 3, "dev"}, {663, 5, "dev"},
    {664, 3, "dev"}, {665, 2, "dev"}, {666, 3, "dev"},
    {668, 2, "dev"}, {669, 5, "dev"}, {670, 4, "dev"},

    -- Misc groups (everything 51a listed after dev)
    {532, 5, "misc"}, {533, 3, "misc"}, {534, 2, "misc"},
    {535, 4, "io"}, {536, 3, "io"}, {558, 2, "misc"},
    {560, 1, "io"}, {586, 1, "misc"},
    {587, 2, "io"}, {600, 1, "evt"}, {601, 3, "evt"},
    {602, 3, "evt"}, {603, 2, "fd"}, {604, 5, "io"},
    {605, 1, "evt"}, {610, 1, "misc"},
    {611, 3, "evt"}, {616, 2, "thr"}, {617, 1, "misc"},
    {622, 6, "vm"}, {623, 1, "misc"}, {627, 2, "io"},
    {629, 4, "misc"}, {630, 1, "misc"}, {632, 1, "thr"},
    {633, 1, "thr"}, {634, 2, "thr"}, {636, 2, "misc"},
    {638, 4, "misc"}, {639, 5, "misc"}, {640, 8, "misc"},
    {641, 2, "io"}, {648, 1, "misc"},
    {652, 2, "proc"}, {653, 1, "misc"}, {654, 5, "misc"},
    {655, 3, "misc"}, {657, 4, "misc"}, {658, 1, "fs"},
    {667, 2, "io"}, {673, 4, "misc"}, {675, 2, "misc"},
    {676, 0, "misc"},
}

print("Testing " .. #remaining .. " Sony syscalls...")
print("")

local accessible = {}
local killed = {}
local errors = {}

for idx, entry in ipairs(remaining) do
    local num = entry[1]
    local narg = entry[2]
    local group = entry[3]

    local sc = make_syscall(num)
    local ok, ret

    -- Zero buffers between tests
    if narg >= 4 then
        for i = 0, 0x100, 4 do
            safe_wd(buf1 + i, 0)
            safe_wd(buf2 + i, 0)
        end
    end

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
        elseif rv == -1 or rv == 4294967295 then tag = " [DENIED]"
        elseif rh >= 0xFFFF8000 then tag = " [KERNEL PTR!!!]"
        end

        local buf_mod = ""
        if narg >= 4 then
            local v1 = safe_rd(buf1)
            local v2 = safe_rd(buf2)
            if (v1 and v1 ~= 0) or (v2 and v2 ~= 0) then
                buf_mod = string.format(" buf1[0]=%08X buf2[0]=%08X", v1 or 0, v2 or 0)
            end
            -- Scan first 256 bytes of buf1 for kernel pointers
            for i = 0, 248, 8 do
                local val = safe_rq(buf1 + i)
                if val then
                    local kh, kl = get_hi_lo(val)
                    if kh >= 0xFFFF8000 and kh < 0xFFFFFFFF then
                        buf_mod = buf_mod .. string.format(" KPTR@+%02X=%08X_%08X", i, kh, kl)
                    end
                end
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
print(string.format("Total tested: %d", #remaining))
print(string.format("Accessible (ret != -1): %d", #accessible))
print(string.format("Killed: %d", #killed))
print(string.format("Errors: %d", #errors))

if #accessible > 0 then
    print("")
    print("=== ACCESSIBLE SYSCALLS ===")
    for _, entry in ipairs(accessible) do
        local num, rv, rh, rl, group, buf_mod = entry[1], entry[2], entry[3], entry[4], entry[5], entry[6]
        local tag = ""
        if rh >= 0xFFFF8000 then tag = " <<< KERNEL POINTER <<<" end
        print(string.format("  [%s] %d: ret=0x%08X_%08X%s%s", group, num, rh, rl, buf_mod, tag))
    end
end

if #killed > 0 then
    print("")
    print("=== SANDBOX-KILLED ===")
    for _, entry in ipairs(killed) do
        print(string.format("  [%s] %d: %s", entry[3], entry[1], entry[2]))
    end
end

print("")
print("=== PROBE 51c COMPLETE ===")
