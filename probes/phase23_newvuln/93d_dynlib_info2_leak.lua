-- CRASH_CLASS: LOW
-- PROBE 93d: sys 660 dynlib_get_info2 — ungated module info with kptr scan
--
-- 13.60 dossier: sys 660 is dynlib_get_info2, NO authid gate (unlike 656).
-- Takes (module_handle, info_buffer) and copies out 0x160 bytes.
-- If 660 returns a different/extended struct than 593, it may include
-- kernel-side pointers (module kernel object address, TLS base, etc.)
--
-- Also tests: sys 659 (dynlib_get_list2), sys 667 (get_bio_usage_all),
-- sys 642 (get_map_statistics), sys 604 (dl_get_metadata)

print("=== PROBE 93d: dynlib_get_info2 + ungated Sony syscall survey ===")
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

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

-- Get module handles via 592
print("[0] Getting module handles via sys 592")
local handles_buf = memory.alloc(0x400)
local count_buf = memory.alloc(8)
wd(N(count_buf), 0)
pcall(function() mk(592)(handles_buf, uint64(256), count_buf) end)
local mod_count = rd(N(count_buf)) or 0
print(string.format("  module count: %d", mod_count))

local handles = {}
for i = 0, math.min(mod_count - 1, 39) do
    local h = rd(N(handles_buf) + i * 4) or 0
    if h ~= 0 then table.insert(handles, h) end
end
print(string.format("  handles collected: %d", #handles))

-- [A] sys 660 — dynlib_get_info2
print("")
print("[A] SYS 660 — dynlib_get_info2 (ungated)")
local sc_660 = mk(660)

local kptr_count = 0
local kptr_locations = {}

for idx, handle in ipairs(handles) do
    local buf = memory.alloc(0x200)
    -- Fill with sentinel
    for i = 0, 0x1FC, 4 do wd(N(buf) + i, 0xDEADDEAD) end
    -- Set size field at +0 (like 593 expects)
    wd(N(buf), 0x160)

    local ok, ret = pcall(function() return sc_660(uint64(handle), buf) end)
    local rv = ok and sgn(ret) or -999

    if rv == 0 then
        -- Scan for kernel pointers
        local found = false
        for off = 0, 0x158, 8 do
            local val = rq(N(buf) + off)
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                if not found then
                    print(string.format("  handle %d (ret=%d):", handle, rv))
                    found = true
                end
                print(string.format("    +0x%03X: %s *** KERNEL PTR ***", off, fmt(val)))
                kptr_count = kptr_count + 1
                table.insert(kptr_locations, string.format("h=%d+0x%03X", handle, off))
            end
        end
        if not found and idx <= 3 then
            print(string.format("  handle %d: ret=%d (no kptrs in 0x160 bytes)", handle, rv))
        end
    elseif idx <= 5 then
        print(string.format("  handle %d: ret=%d", handle, rv))
    end

    if not alive() then print("  *** DEAD ***"); break end
end

if kptr_count == 0 then
    print(string.format("  scanned %d handles — zero kernel pointers", #handles))
end

-- Also try 660 with a larger output buffer size field
print("")
print("[A2] SYS 660 — larger size field (0x200, 0x400)")
for _, sz in ipairs({0x200, 0x400}) do
    if #handles > 0 and alive() then
        local buf = memory.alloc(0x400)
        for i = 0, 0x3FC, 4 do wd(N(buf) + i, 0xDEADDEAD) end
        wd(N(buf), sz)
        local ok, ret = pcall(function() return sc_660(uint64(handles[1]), buf) end)
        local rv = ok and sgn(ret) or -999
        -- Find how far the write went
        local last_written = 0
        for off = 0, sz - 4, 4 do
            if rd(N(buf) + off) ~= 0xDEADDEAD then last_written = off end
        end
        print(string.format("  size=0x%X: ret=%d last_written=+0x%X", sz, rv, last_written))
    end
end

-- [B] sys 659 — dynlib_get_list2
print("")
print("[B] SYS 659 — dynlib_get_list2")
if alive() then
    local lbuf = memory.alloc(0x400)
    local lcnt = memory.alloc(8)
    for i = 0, 0x3FC, 4 do wd(N(lbuf) + i, 0) end
    wd(N(lcnt), 0)

    local ok, ret = pcall(function() return mk(659)(lbuf, uint64(256), lcnt) end)
    local rv = ok and sgn(ret) or -999
    local cnt = rd(N(lcnt)) or 0
    print(string.format("  659(buf, 256, &cnt): ret=%d count=%d", rv, cnt))

    if rv == 0 and cnt > 0 then
        -- Scan for kernel pointers in output
        for off = 0, math.min(cnt * 4, 0x3FC), 8 do
            local val = rq(N(lbuf) + off)
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("    +0x%03X: %s *** KERNEL PTR ***", off, fmt(val)))
                kptr_count = kptr_count + 1
            end
        end
    end
end

-- [C] sys 667 — get_bio_usage_all
print("")
print("[C] SYS 667 — get_bio_usage_all")
if alive() then
    for _, shape in ipairs({
        {0, 0, 0, 0},
        {0, 0x100, 0, 0},
    }) do
        local obuf = memory.alloc(0x400)
        for i = 0, 0x3FC, 4 do wd(N(obuf) + i, 0xDEADDEAD) end
        local ok, ret = pcall(function()
            return mk(667)(uint64(N(obuf)), uint64(shape[2]), uint64(shape[3]), uint64(shape[4]))
        end)
        local rv = ok and sgn(ret) or -999
        local last_w = 0
        for off = 0, 0x3FC, 4 do
            if rd(N(obuf) + off) ~= 0xDEADDEAD then last_w = off end
        end
        print(string.format("  667(buf, 0x%X, %d, %d): ret=%d last_written=+0x%X",
            shape[2], shape[3], shape[4], rv, last_w))

        if rv == 0 and last_w > 0 then
            for off = 0, last_w, 8 do
                local val = rq(N(obuf) + off)
                local h, l = get_hi_lo(val)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("    +0x%03X: %s *** KERNEL PTR ***", off, fmt(val)))
                    kptr_count = kptr_count + 1
                end
            end
        end
    end
end

-- [D] sys 642 — get_map_statistics
print("")
print("[D] SYS 642 — get_map_statistics")
if alive() then
    for _, shape in ipairs({
        {0x100, 0, 0},
        {0x200, 1, 0},
        {0x400, 0, 1},
    }) do
        local obuf = memory.alloc(0x400)
        for i = 0, 0x3FC, 4 do wd(N(obuf) + i, 0xDEADDEAD) end
        local ok, ret = pcall(function()
            return mk(642)(uint64(N(obuf)), uint64(shape[1]), uint64(shape[2]), uint64(shape[3]))
        end)
        local rv = ok and sgn(ret) or -999
        local last_w = 0
        for off = 0, 0x3FC, 4 do
            if rd(N(obuf) + off) ~= 0xDEADDEAD then last_w = off end
        end
        print(string.format("  642(buf, 0x%X, %d, %d): ret=%d last_written=+0x%X",
            shape[1], shape[2], shape[3], rv, last_w))

        if rv == 0 and last_w > 0 then
            for off = 0, last_w, 8 do
                local val = rq(N(obuf) + off)
                local h, l = get_hi_lo(val)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("    +0x%03X: %s *** KERNEL PTR ***", off, fmt(val)))
                    kptr_count = kptr_count + 1
                end
            end
        end
    end
end

-- [E] sys 648 — app_state_change (pointer arg)
print("")
print("[E] SYS 648 — app_state_change")
if alive() then
    local sbuf = memory.alloc(0x40)
    for _, state in ipairs({0, 1, 2, 3, 4, 5}) do
        for i = 0, 0x3C, 4 do wd(N(sbuf) + i, 0) end
        wd(N(sbuf), state)
        local ok, ret = pcall(function() return mk(648)(uint64(N(sbuf))) end)
        local rv = ok and sgn(ret) or -999
        if rv ~= -1 or state <= 2 then
            print(string.format("  648({state=%d}): ret=%d", state, rv))
        end
        if not alive() then print("  *** DEAD ***"); break end
    end
end

-- [F] sys 641 — get_cpu_usage_proc
print("")
print("[F] SYS 641 — get_cpu_usage_proc")
if alive() then
    local obuf = memory.alloc(0x200)
    for i = 0, 0x1FC, 4 do wd(N(obuf) + i, 0xDEADDEAD) end
    local ok, ret = pcall(function() return mk(641)(uint64(pid_val), uint64(N(obuf))) end)
    local rv = ok and sgn(ret) or -999
    local last_w = 0
    for off = 0, 0x1FC, 4 do
        if rd(N(obuf) + off) ~= 0xDEADDEAD then last_w = off end
    end
    print(string.format("  641(pid=%d, buf): ret=%d last_written=+0x%X", pid_val, rv, last_w))

    if rv == 0 and last_w > 0 then
        for off = 0, last_w, 8 do
            local val = rq(N(obuf) + off)
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("    +0x%03X: %s *** KERNEL PTR ***", off, fmt(val)))
                kptr_count = kptr_count + 1
            end
        end
    end
end

-- [G] sys 611 — get_paging_stats_of_all_threads
print("")
print("[G] SYS 611 — get_paging_stats_of_all_threads")
if alive() then
    local obuf = memory.alloc(0x400)
    for i = 0, 0x3FC, 4 do wd(N(obuf) + i, 0xDEADDEAD) end
    local ok, ret = pcall(function() return mk(611)(uint64(N(obuf)), uint64(0x400)) end)
    local rv = ok and sgn(ret) or -999
    local last_w = 0
    for off = 0, 0x3FC, 4 do
        if rd(N(obuf) + off) ~= 0xDEADDEAD then last_w = off end
    end
    print(string.format("  611(buf, 0x400): ret=%d last_written=+0x%X", rv, last_w))

    if rv == 0 and last_w > 0 then
        for off = 0, last_w, 8 do
            local val = rq(N(obuf) + off)
            local h, l = get_hi_lo(val)
            if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                print(string.format("    +0x%03X: %s *** KERNEL PTR ***", off, fmt(val)))
                kptr_count = kptr_count + 1
            end
        end
    end
end

print("")
print("[SUMMARY]")
print(string.format("  total kernel pointers found: %d", kptr_count))
if kptr_count > 0 then
    print("  locations:")
    for _, loc in ipairs(kptr_locations) do print("    " .. loc) end
    print("  *** KASLR DEFEAT CANDIDATE ***")
end
print(string.format("  process: %s", alive() and "ALIVE" or "DEAD"))

print("")
print("=== 93d COMPLETE ===")
