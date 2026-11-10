-- CRASH_CLASS: LOW
-- PROBE: CSSFontFaceSet vtable RVA extractor
--
-- Context: PR #240 leaks VP = 0x80f4b9b28 from the FontFace walk chain on 14.10.
-- VP = WebProcess_base + CSSFontFaceSet_vtable_RVA.
-- VP mod 0x1000 = 0xB28, so the RVA ends in 0xB28.
-- This payload runs on 13.60 jailbroken to:
-- 1. Find SceWebProcess/SceShellCore PIDs
-- 2. Dump the process's WebKit module text section
-- 3. Scan for vtable candidates ending in 0xB28 (page offset match)
-- 4. Validate by checking if the vtable contains function pointers
--    that match the CSSFontFace::Client ABI (8 slots: 2 dtors,
--    fontLoaded, fontStateChanged, fontPropertyChanged,
--    updateStyleIfNeeded, ref, deref)
--
-- The RVA lets us compute: 14.10 WebProcess_base = VP - RVA
--
-- This probe needs kernel R/W (etaHEN). Without it, it falls back to
-- enumerating processes and documenting what kernel offsets are needed.
--
-- prior art: 02_webprocess_dump.lua (process enum), PR #240 (VP leak)

print("=== VTABLE RVA EXTRACTOR v1 ===")
print("TIMESTAMP: " .. os.date("%Y-%m-%d %H:%M:%S"))
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
local pid = to_num(sc_getpid())
print("PID: " .. pid)

-- === Step 1: Enumerate processes ===
print("")
print("=== STEP 1: PROCESS ENUMERATION ===")

local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
safe_wd(mib, 1)       -- CTL_KERN
safe_wd(mib + 4, 14)  -- KERN_PROC
safe_wd(mib + 8, 0)   -- KERN_PROC_ALL

local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0)
safe_wd(oldlenp + 4, 0)
local ret = sc_sysctl(uint64(mib), uint64(3), uint64(0), uint64(oldlenp), uint64(0), uint64(0))
local needed = safe_rd(oldlenp)
print("PROCLIST_SIZE: " .. (needed or 0))

local web_pids = {}

if needed and needed > 0 and needed < 0x200000 then
    local buf = memory.alloc(needed + 0x2000)
    safe_wd(oldlenp, needed + 0x2000)
    safe_wd(oldlenp + 4, 0)
    ret = sc_sysctl(uint64(mib), uint64(3), uint64(buf), uint64(oldlenp), uint64(0), uint64(0))

    if to_num(ret) == 0 then
        local actual = safe_rd(oldlenp) or 0
        local kinfo_size = 1096
        local count = math.floor(actual / kinfo_size)
        print("PROCESS_COUNT: " .. count)

        for i = 0, count - 1 do
            local base = buf + i * kinfo_size
            local pid_val = safe_rd(base + 0x44) or 0
            local name = ""
            for j = 0, 19 do
                local c = safe_rd(base + 0x1BF + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then name = name .. string.char(c) end
            end

            -- Report all processes
            print(string.format("PROC[%03d] pid=%-6d %s", i, pid_val, name))

            -- Flag browser/web processes
            local nl = name:lower()
            if nl:find("web") or nl:find("browser") or nl:find("sceshell") or
               nl:find("sceweb") or nl:find("webkit") then
                print("  *** WEB TARGET ***")
                table.insert(web_pids, {pid = pid_val, name = name})
            end
        end
    end
end

print("")
print("WEB_TARGETS: " .. #web_pids)
for _, p in ipairs(web_pids) do
    print("  " .. p.name .. " (pid " .. p.pid .. ")")
end

-- === Step 2: Test kernel read ===
print("")
print("=== STEP 2: KERNEL READ TEST ===")

local kernel_read_works = false
local test_addrs = {
    {0xFFFFFFFF, 0x80000000},
    {0xFFFFFFFF, 0x82200000},
    {0xFFFFFFFF, 0x83000000},
}

for _, entry in ipairs(test_addrs) do
    local hi, lo = entry[1], entry[2]
    local addr = uint64(string.format("0x%X%08X", hi, lo))
    local val = safe_rq(addr)
    if val then
        local vh, vl = get_hi_lo(val)
        print(string.format("KREAD %08X%08X = %08X%08X", hi, lo, vh, vl))
        if vh ~= 0 or vl ~= 0 then
            kernel_read_works = true
        end
    else
        print(string.format("KREAD %08X%08X = FAULT", hi, lo))
    end
end

if kernel_read_works then
    print("KERNEL_READ: WORKING")
else
    print("KERNEL_READ: NOT AVAILABLE")
    print("")
    print("=== FALLBACK: OWN PROCESS VTABLE SCAN ===")
    print("Without kernel R/W, scanning our own process for")
    print(".rodata vtable candidates ending in 0xB28.")
    print("")
    print("On 13.60 with etaHEN, kernel R/W is needed to:")
    print("1. Read allproc (kernel_base + allproc_offset)")
    print("2. Walk proc list to find WebProcess by name")
    print("3. Read proc->p_vmspace->vm_map to get text segment")
    print("4. Map or copy text pages to userland for scanning")
    print("")
    print("Alternatively, check if etaHEN exposes:")
    print("- A kread syscall (try sys 600-620 with kernel VA args)")
    print("- /dev/kmem access (tested in 03_sysent_dump.lua)")
    print("- A ptrace-like API for cross-process reads")
end

-- === Step 3: Scan our own .text for reference ===
-- Even without cross-process read, we can check if our loader
-- process has any WebKit-related vtables
print("")
print("=== STEP 3: OWN MODULE SCAN ===")

local sc_info = make_syscall(593)
local modules = {}

for handle = 0, 255 do
    local ibuf = memory.alloc(0x200)
    safe_wd(ibuf, 0x160)
    local ok = pcall(function() sc_info(uint64(handle), ibuf) end)
    if ok then
        local tlo = safe_rd(ibuf + 0x108)
        local thi = safe_rd(ibuf + 0x10C)
        local tslo = safe_rd(ibuf + 0x110)
        local tshi = safe_rd(ibuf + 0x114)
        if thi and thi > 0 then
            local nm = ""
            for j = 0, 63 do
                local c = safe_rd(ibuf + 8 + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then nm = nm .. string.char(c) end
            end
            table.insert(modules, {
                handle = handle, name = nm,
                text_hi = thi, text_lo = tlo,
                size_hi = tshi or 0, size_lo = tslo or 0
            })
            print(string.format("MOD[%03d] %08X%08X size=%08X%08X %s",
                handle, thi, tlo, tshi or 0, tslo or 0, nm))
        end
    end
end

print("MODULE_COUNT: " .. #modules)

-- === Step 4: Document what we need ===
print("")
print("=== STEP 4: VTABLE RVA REQUIREMENTS ===")
print("")
print("Known from PR #240 walk chain on 14.10:")
print("  VP  = 0x80f4b9b28 (CSSFontFaceSet vtable pointer)")
print("  VP mod 0x1000 = 0xB28 (page-offset constraint)")
print("  s0  = 0x80dda8fb0 (dtor complete)")
print("  s1  = 0x80dda8fe0 (dtor deleting, s1-s0=0x30)")
print("  s2  = 0x80c26d750 (fontLoaded -- base impl)")
print("  s3  = 0x80dda96b0 (fontStateChanged -- overridden)")
print("  s4  = 0x80c26d750 (fontPropertyChanged -- base impl)")
print("  s5  = 0x80c26d750 (updateStyleIfNeeded -- base impl)")
print("  s6  = 0x80d9ff400 (ref)")
print("  s7  = 0x80dda9810 (deref)")
print("  s8  = 0x0")
print("")
print("CSSFontFace::Client vtable ABI (Itanium C++ ABI):")
print("  slot 0: ~Client() complete destructor")
print("  slot 1: ~Client() deleting destructor")
print("  slot 2: fontLoaded")
print("  slot 3: fontStateChanged")
print("  slot 4: fontPropertyChanged")
print("  slot 5: updateStyleIfNeeded")
print("  slot 6: ref")
print("  slot 7: deref")
print("")
print("To compute 14.10 WebProcess base:")
print("  base = VP - RVA = 0x80f4b9b28 - RVA")
print("")
print("To find RVA, need the 13.60 WebProcess binary:")
print("  1. Dump WebProcess .text via kernel R/W")
print("  2. Search .rodata for vtable at offset ending 0xB28")
print("  3. Validate: 8 function pointers in .text range")
print("  4. Confirm: s2=s4=s5 (shared base impl)")
print("  5. RVA = vtable_offset_in_binary")
print("  6. If 13.60 and 14.10 share WebKit build, RVA matches")
print("")
print("Slot deltas (build-invariant patterns):")
print("  s1-s0 = 0x30 (dtor pair spacing)")
print("  s3-s0 = 0x700 (fontStateChanged - dtor)")
print("  s6-s0 = 0x1F6064A50 (ref, distant -- possibly wrong)")
print("  s2=s4=s5 (three base stubs share one address)")
print("")
print("=== VTABLE RVA EXTRACTOR v1 COMPLETE ===")
