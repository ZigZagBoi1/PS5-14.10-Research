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

-- E1: profil(44) — kernel PC sampling
print("[E] E1: profil setup")
repeat
    -- profil(samples, size, offset, scale)
    -- samples: buffer for PC samples (uint16_t array)
    -- size: buffer size
    -- offset: lowest PC address to sample
    -- scale: sampling frequency (0x10000 = 1:1, 0x8000 = 1:2)
    local samples = memory.alloc(0x1000)
    for i = 0, 0xFFF, 4 do safe_wd(samples + i, 0) end

    -- Get eboot base for offset
    local info_buf = memory.alloc(0x200)
    safe_wd(info_buf, 0x160)
    pcall(function() make_syscall(593)(uint64(0), uint64(info_buf)) end)
    local eboot_lo = safe_rd(info_buf + 0x108)
    local eboot_hi = safe_rd(info_buf + 0x10C)
    local eboot_base = uint64(string.format("0x%X%08X", eboot_hi or 0, eboot_lo or 0))
    print("[E] eboot base: " .. fmt_addr(eboot_base))

    local ok, rv = pcall(function()
        return to_num(make_syscall(SYS_profil)(uint64(samples), uint64(0x1000),
            uint64(eboot_base), uint64(0x10000)))
    end)
    print("[E] profil: ok=" .. tostring(ok) .. " ret=" .. tostring(rv))

    if ok and to_num(rv) == 0 then
        print("[E] *** PROFIL ACCEPTED ***")

        -- Do some work to generate samples
        local dummy = 0
        for i = 1, 10000 do dummy = dummy + i end

        -- Read samples
        local nonzero = 0
        for i = 0, 0xFFF, 4 do
            local val = safe_rd(samples + i)
            if val ~= nil and val ~= 0 then
                nonzero = nonzero + 1
                if nonzero <= 10 then
                    print("[E]   sample[" .. string.format("%03X", i) .. "]: " .. val)
                end
            end
        end
        print("[E] nonzero samples: " .. nonzero)

        -- Disable profil
        pcall(function()
            make_syscall(SYS_profil)(uint64(0), uint64(0), uint64(0), uint64(0))
        end)
    end
until true
print("")

print("=== PROBE 110a sectionE1 COMPLETE ===")
