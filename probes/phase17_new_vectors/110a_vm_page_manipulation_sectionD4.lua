-- Isolated continuation after original 110a stopped at getcwd on 2026-10-19.
-- CRASH_CLASS: MODERATE
-- PROBE 110a: VM page manipulation on GPU mmap + standard info leaks
--
-- Context: madvise, mlock, munlock, mincore have NEVER been tested on
-- GPU-mapped pages. These FreeBSD VM syscalls manipulate per-page metadata
-- in the kernel. On device-backed (GPU) pages, the kernel's handling is
-- different from anonymous memory — potential for confused deputy attacks,
-- page fault handler bugs, and physical address leaks.
--
-- Also tests: getrusage (timing side channel), getlogin/getcwd (padding leaks),
-- profil (kernel PC sampling), and ptrace PT_TRACE_ME (via pcall).
--
-- Section A: madvise ops on GPU mmap (MADV_FREE/DONTNEED/etc.) (LOW risk)
-- Section B: mlock/munlock on GPU mmap (MODERATE risk)
-- Section C: mincore on GPU mmap — physical residency leak (LOW risk)
-- Section D: getrusage + getlogin + getcwd + fcntl (LOW risk)
-- Section E: profil kernel PC sampling + ptrace self-trace (MODERATE risk)

print("=== PROBE 110a: VM PAGE MANIPULATION + STANDARD INFO LEAKS ===")
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

print("=== PROBE 110a sectionD4 COMPLETE ===")
