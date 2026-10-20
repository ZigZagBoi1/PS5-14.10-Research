-- CRASH_CLASS: LOW
-- Standard syscall copyout survey, without GPU mapping or ptrace.
print("=== PROBE 110b: STANDARD COPYOUT ===")
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
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then return true end
    return false
end

local SYS_getpid    = 20
local SYS_ptrace    = 26
local SYS_profil    = 44
local SYS_getlogin  = 49
local SYS_madvise   = 75
local SYS_mincore   = 78
local SYS_getgroups = 79
local SYS_fcntl     = 92
local SYS_getrusage = 117
local SYS_mlock     = 203
local SYS_munlock   = 204
local SYS_mmap      = 477
local SYS_getcwd    = 326

local pid = to_num(make_syscall(SYS_getpid)())
print("pid: " .. pid)

-- SECTION D: Standard info leak syscalls
-- ============================================================
print("--- SECTION D: STANDARD INFO LEAKS ---")
print("")

-- D1: getrusage(117) — full struct dump
print("[D] D1: getrusage")
repeat
    local buf = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end

    -- RUSAGE_SELF = 0
    local ok, rv = pcall(function()
        return to_num(make_syscall(SYS_getrusage)(uint64(0), uint64(buf)))
    end)
    print("[D] getrusage(SELF): ok=" .. tostring(ok) .. " ret=" .. tostring(rv))

    if ok and to_num(rv) == 0 then
        -- struct rusage is ~144 bytes on FreeBSD amd64
        local kptrs = 0
        for i = 0, 0x8F, 8 do
            local qv = safe_rq(buf + i)
            local h, l = get_hi_lo(qv)
            local m = ""
            if is_kptr(qv) then m = " *** KPTR ***"; kptrs = kptrs + 1 end
            if h == 0xDEADBEEF then m = " [sentinel]" end
            if m ~= "" or i < 0x20 then
                print("[D]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
            end
        end
        print("[D] kernel ptrs in rusage: " .. kptrs)

        -- Timing values (for side channel calibration)
        local utime_sec = safe_rd(buf)
        local utime_usec = safe_rd(buf + 8)
        local stime_sec = safe_rd(buf + 0x10)
        local stime_usec = safe_rd(buf + 0x18)
        print("[D] user time: " .. tostring(utime_sec) .. "s " ..
              tostring(utime_usec) .. "us")
        print("[D] sys time: " .. tostring(stime_sec) .. "s " ..
              tostring(stime_usec) .. "us")
    end

    -- RUSAGE_CHILDREN = -1
    for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end
    local ok2, rv2 = pcall(function()
        return to_num(make_syscall(SYS_getrusage)(uint64(0xFFFFFFFF), uint64(buf)))
    end)
    print("[D] getrusage(CHILDREN): ret=" .. tostring(rv2))

    -- RUSAGE_THREAD = 1
    for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end
    local ok3, rv3 = pcall(function()
        return to_num(make_syscall(SYS_getrusage)(uint64(1), uint64(buf)))
    end)
    print("[D] getrusage(THREAD): ret=" .. tostring(rv3))
until true
print("")

-- D2: getlogin(49)
print("[D] D2: getlogin")
repeat
    local buf = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end

    local ok, rv = pcall(function()
        return to_num(make_syscall(SYS_getlogin)(uint64(buf), uint64(0x100)))
    end)
    print("[D] getlogin: ok=" .. tostring(ok) .. " ret=" .. tostring(rv))

    if ok and to_num(rv) == 0 then
        -- Read string
        local name = ""
        for i = 0, 63 do
            local dw = safe_rd(buf + (i - i % 4))
            if dw then
                local byte = math.floor(dw / (256 ^ (i % 4))) % 256
                if byte == 0 then break end
                name = name .. string.char(byte)
            end
        end
        print("[D] login name: '" .. name .. "'")

        -- Scan PAST the null terminator for kernel heap leaks
        local name_end = #name + 1
        local kptrs = 0
        for i = name_end, 0xFF, 8 do
            local aligned = i - (i % 8)
            local qv = safe_rq(buf + aligned)
            if qv and not is_kptr(qv) then
                -- skip
            elseif is_kptr(qv) then
                print("[D]   post-null +" .. string.format("%02X", aligned) ..
                      ": " .. fmt_addr(qv) .. " *** KPTR ***")
                kptrs = kptrs + 1
            end
        end
        print("[D] post-null kernel ptrs: " .. kptrs)
    end
until true
print("")

-- D3: __getcwd(326)
print("[D] D3: getcwd")
repeat
    local buf = memory.alloc(0x200)
    for i = 0, 0x1FF, 4 do safe_wd(buf + i, 0xDEADBEEF) end

    local ok, rv = pcall(function()
        return to_num(make_syscall(SYS_getcwd)(uint64(buf), uint64(0x200)))
    end)
    print("[D] __getcwd: ok=" .. tostring(ok) .. " ret=" .. tostring(rv))

    if ok and to_num(rv) == 0 then
        -- Read path string
        local path = ""
        for i = 0, 255 do
            local dw = safe_rd(buf + (i - i % 4))
            if dw then
                local byte = math.floor(dw / (256 ^ (i % 4))) % 256
                if byte == 0 then break end
                path = path .. string.char(byte)
            end
        end
        print("[D] cwd: '" .. path .. "'")
    end
until true
print("")

-- D4: getgroups(79)
print("[D] D4: getgroups")
repeat
    local buf = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(buf + i, 0xDEADBEEF) end

    local ok, rv = pcall(function()
        return to_num(make_syscall(SYS_getgroups)(uint64(32), uint64(buf)))
    end)
    print("[D] getgroups(32): ok=" .. tostring(ok) .. " ret=" .. tostring(rv))

    if ok and to_num(rv) >= 0 then
        local ngroups = to_num(rv)
        print("[D] ngroups: " .. ngroups)
        local groups = {}
        for i = 0, math.min(ngroups, 32) - 1 do
            local gid = safe_rd(buf + i * 4)
            table.insert(groups, tostring(gid))
        end
        if #groups > 0 then print("[D] groups: " .. table.concat(groups, ",")) end

        -- Scan past returned groups for kernel heap leak
        for i = ngroups * 4, 0xFF, 8 do
            local qv = safe_rq(buf + i)
            if is_kptr(qv) then
                print("[D]   post-groups +" .. string.format("%02X", i) ..
                      ": " .. fmt_addr(qv) .. " *** KPTR ***")
            end
        end
    end
until true
print("")

-- ============================================================
print("=== PROBE 110b COMPLETE ===")
