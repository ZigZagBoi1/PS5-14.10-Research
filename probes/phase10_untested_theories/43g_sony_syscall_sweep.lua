-- CRASH_CLASS: MODERATE (probing unknown syscalls with safe args)
-- PROBE 43g: Systematic Sony syscall sweep 540–650
--
-- Calls each syscall number with arg=0 to find which ones are live.
-- Any that return 0 or positive are alive and need deeper probing.
-- Focus on syscalls that return data (potential kernel leaks).

print("=== PROBE 43g: SONY SYSCALL SWEEP ===")
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

local sc_getpid = make_syscall(20)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

-- Already known syscalls (skip them)
local known = {
    [538]=true, [539]=true, -- evf_create/delete
    [547]=true, [548]=true, [549]=true, [550]=true, [551]=true, [552]=true, -- dmem
    [585]=true, -- mtypeprotect (tested in 42f)
    [588]=true, -- munmap
    [592]=true, [593]=true, -- dynlib
    [594]=true, -- dlsym
    [617]=true, -- getCpuUsage (tested in 42f)
}

--------------------------------------------------------------------
-- SWEEP: call each unknown syscall with (0) and (out_buf)
--------------------------------------------------------------------
print("")
print("=== SWEEP 540-650 ===")

local out_buf = memory.alloc(0x200)
local live = {}

for num = 540, 650 do
    if not known[num] then
        -- Zero output buffer
        for off = 0, 0x1FC, 4 do safe_wd(out_buf + off, 0) end

        local sc = make_syscall(num)

        -- Try with output buffer as first arg
        local ok, ret = pcall(function()
            return sc(uint64(out_buf))
        end)
        local rv = ok and to_num(ret) or -999

        -- Check for interesting returns
        if rv ~= -999 and rv ~= -1 and rv ~= 0xFFFFFFFF then
            live[#live + 1] = {num = num, rv = rv}
            -- Check output buffer
            local q = safe_rq(out_buf)
            local qh, ql = 0, 0
            if q then qh, ql = get_hi_lo(q) end
            local tag = ""
            if qh >= 0xFFFF8000 then tag = " KPTR!" end
            print(string.format("  %3d: ret=%-6d buf=%08X_%08X%s", num, rv, qh, ql, tag))
        end

        -- Also try with just 0 as arg (some take an int, not a pointer)
        for off = 0, 0x1FC, 4 do safe_wd(out_buf + off, 0) end
        local ok2, ret2 = pcall(function()
            return sc(uint64(0))
        end)
        local rv2 = ok2 and to_num(ret2) or -999

        if rv2 ~= rv and rv2 ~= -999 and rv2 ~= -1 and rv2 ~= 0xFFFFFFFF then
            live[#live + 1] = {num = num, rv = rv2, note = "(arg=0)"}
            print(string.format("  %3d: ret=%-6d (arg=0)", num, rv2))
        end
    end
end

--------------------------------------------------------------------
-- Also sweep 650-700 (possible newer PS5 additions)
--------------------------------------------------------------------
print("")
print("=== SWEEP 650-700 ===")
for num = 650, 700 do
    for off = 0, 0x1FC, 4 do safe_wd(out_buf + off, 0) end
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(out_buf))
    end)
    local rv = ok and to_num(ret) or -999
    if rv ~= -999 and rv ~= -1 and rv ~= 0xFFFFFFFF then
        live[#live + 1] = {num = num, rv = rv}
        local q = safe_rq(out_buf)
        local qh, ql = 0, 0
        if q then qh, ql = get_hi_lo(q) end
        print(string.format("  %3d: ret=%-6d buf=%08X_%08X", num, rv, qh, ql))
    end
end

--------------------------------------------------------------------
-- SUMMARY
--------------------------------------------------------------------
print("")
print("=== LIVE SYSCALLS ===")
for _, s in ipairs(live) do
    print(string.format("  syscall %d: ret=%d %s", s.num, s.rv, s.note or ""))
end
print("total live: " .. #live)

print("")
print("=== PROBE 43g COMPLETE ===")
