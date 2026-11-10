-- CRASH_CLASS: LOW
-- PROBE: WebProcess Binary Finder and Dumper
--
-- On 13.60 jailbroken: enumerate all processes, find WebProcess/WebKit,
-- read its memory map, dump the .text section to get the WebProcess binary.
-- This is the KEY missing piece for 14.10 WebKit exploitation --
-- knowing the WebProcess text base and binary contents lets us build
-- a code-reuse chain for the FontFace UAF.

print("=== WEBPROCESS DUMPER v1 ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end

-- Step 1: Enumerate all processes via sysctl
print("=== PROCESS ENUMERATION ===")

local sc_sysctl = make_syscall(202)
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("OUR_PID: " .. our_pid)

-- CTL_KERN=1, KERN_PROC=14, KERN_PROC_ALL=0
local mib = memory.alloc(16)
safe_wd(mib, 1)
safe_wd(mib + 4, 14)
safe_wd(mib + 8, 0)

-- First call: get required buffer size
local oldlenp = memory.alloc(8)
safe_wd(oldlenp, 0)
safe_wd(oldlenp + 4, 0)
local ret = sc_sysctl(uint64(mib), uint64(3), uint64(0), uint64(oldlenp), uint64(0), uint64(0))
local needed = safe_rd(oldlenp)
print("PROCLIST_BYTES: " .. (needed or 0))

local target_pids = {}

if needed and needed > 0 and needed < 0x200000 then
    local buf = memory.alloc(needed + 0x2000)
    safe_wd(oldlenp, needed + 0x2000)
    safe_wd(oldlenp + 4, 0)
    ret = sc_sysctl(uint64(mib), uint64(3), uint64(buf), uint64(oldlenp), uint64(0), uint64(0))

    if to_num(ret) == 0 then
        local actual = safe_rd(oldlenp) or 0
        -- kinfo_proc is 1096 bytes on PS5/FreeBSD
        local kinfo_size = 1096
        local count = math.floor(actual / kinfo_size)
        print("PROCESS_COUNT: " .. count)
        print("")

        for i = 0, count - 1 do
            local base = buf + i * kinfo_size
            -- ki_pid at +0x44 (dword)
            local pid_val = safe_rd(base + 0x44) or 0
            -- ki_comm at +0x1BF (20 bytes, NUL-terminated)
            local name = ""
            for j = 0, 19 do
                local c = safe_rd(base + 0x1BF + j)
                if not c or c == 0 then break end
                if c >= 32 and c < 127 then
                    name = name .. string.char(c)
                end
            end
            -- ki_uid at +0x2C
            local uid = safe_rd(base + 0x2C) or 0

            print(string.format("PROC[%03d] pid=%-6d uid=%-4d comm=%s", i, pid_val, uid, name))

            -- Flag WebKit/browser processes
            if name:lower():find("web") or name:lower():find("webkit") or
               name:lower():find("browser") or name:lower():find("sceshell") or
               name:lower():find("sceweb") then
                print("  *** TARGET PROCESS ***")
                table.insert(target_pids, {pid = pid_val, name = name})
            end
        end
    else
        print("SYSCTL_FAILED: " .. to_num(ret))
    end
else
    print("PROCLIST_FAILED: needed=" .. tostring(needed))
end

print("")
print("TARGET_PROCESSES: " .. #target_pids)
for _, p in ipairs(target_pids) do
    print("  TARGET: pid=" .. p.pid .. " name=" .. p.name)
end

-- Step 2: For each target, get its VM map
-- On a jailbroken system, we can use sys 674 with the target PID
-- or read /proc/<pid>/map if procfs is mounted

print("")
print("=== TARGET VM MAPS ===")

-- Try reading the target process's modules via dynlib_get_info
-- This requires being in the same address space, so we may need
-- kernel R/W to read another process's memory

-- Alternative: use the kernel read primitive to read the process
-- structure and extract the VM map from there

-- For now, report what we know about our own process (the loader)
-- and document the path to reading WebProcess

print("=== OUR OWN MODULE MAP (loader process) ===")
local sc_info = make_syscall(593)
-- Scan module handles 0-255
for handle = 0, 39 do
    local info_buf = memory.alloc(0x200)
    safe_wd(info_buf, 0x160)
    local ok = pcall(function() sc_info(uint64(handle), info_buf) end)
    if ok then
        local text_lo = safe_rd(info_buf + 0x108)
        local text_hi = safe_rd(info_buf + 0x10C)
        local text_size_lo = safe_rd(info_buf + 0x110)
        local text_size_hi = safe_rd(info_buf + 0x114)

        -- Read module name at +0x08
        local mod_name = ""
        for j = 0, 63 do
            local c = safe_rd(info_buf + 8 + j)
            if not c or c == 0 then break end
            if c >= 32 and c < 127 then
                mod_name = mod_name .. string.char(c)
            end
        end

        if text_hi and text_hi > 0 then
            print(string.format("MOD[%02d] %08X%08X size=%08X%08X %s",
                handle,
                text_hi or 0, text_lo or 0,
                text_size_hi or 0, text_size_lo or 0,
                mod_name))
        end
    end
end

-- Step 3: Document the kernel-assisted cross-process read
print("")
print("=== CROSS-PROCESS READ STRATEGY ===")
print("To dump WebProcess on 13.60 jailbroken:")
print("1. Find WebProcess PID (done above)")
print("2. Use kernel R/W to read proc->p_vmspace")
print("3. Walk vm_map entries to find .text segment")
print("4. Use copyin/copyout or direct physical mapping to read pages")
print("5. Send bytes back over TCP")
print("")
print("On 13.60 with etaHEN kernel patches:")
print("- kread/kwrite primitives are available")
print("- allproc list is at a known kernel offset")
print("- proc structure layout is documented in FreeBSD source")
print("")
print("=== WEBPROCESS DUMPER v1 COMPLETE ===")
