-- 14.10 Recon Probe 01: Identity & Environment
-- Baseline info: firmware, PID, module bases, available globals
-- Run this FIRST to confirm the loader is working on 14.10

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: IDENTITY ===")
log("timestamp: " .. os.date("%Y-%m-%d %H:%M:%S"))

-- Platform & firmware
log("")
log("--- platform ---")
log("PLATFORM: " .. tostring(PLATFORM))
log("FW_VERSION: " .. tostring(FW_VERSION))

-- PID
local pid = syscall.getpid():tonumber()
log("PID: " .. pid)

syscall.resolve({ getppid = 39, getuid = 24, geteuid = 25, getgid = 47, getegid = 43 })
log("PPID: " .. syscall.getppid():tonumber())
log("UID: " .. syscall.getuid():tonumber())
log("EUID: " .. syscall.geteuid():tonumber())
log("GID: " .. syscall.getgid():tonumber())
log("EGID: " .. syscall.getegid():tonumber())

-- Module bases
log("")
log("--- module bases ---")
if eboot_base then log("eboot_base: " .. hex(eboot_base)) end
if libc_base then log("libc_base: " .. hex(libc_base)) end
if libkernel_base then log("libkernel_base: " .. hex(libkernel_base)) end

-- Enumerate all globals the loader provides
log("")
log("--- loader globals ---")
local globals = {}
for k, v in pairs(_G) do
    globals[#globals+1] = k .. " = " .. type(v)
end
table.sort(globals)
for _, g in ipairs(globals) do log("  " .. g) end

-- Check what's in syscall table
log("")
log("--- registered syscalls ---")
local sc = {}
for k, v in pairs(syscall) do
    sc[#sc+1] = k
end
table.sort(sc)
for _, s in ipairs(sc) do log("  " .. s) end

-- Check kernel module availability
log("")
log("--- kernel r/w status ---")
if type(kernel) == "table" then
    log("kernel table exists")
    if kernel.read_dword then
        log("  kernel.read_dword: available")
    else
        log("  kernel.read_dword: NOT available")
    end
    if kernel.addr then
        log("  kernel.addr entries:")
        for k, v in pairs(kernel.addr) do
            log("    " .. tostring(k) .. " = " .. tostring(v))
        end
    else
        log("  kernel.addr: NOT set (no kernel exploit ran)")
    end
else
    log("kernel table: NOT available (userland only)")
end

-- Check memory API
log("")
log("--- memory API ---")
if type(memory) == "table" then
    local mem_funcs = {}
    for k, v in pairs(memory) do
        mem_funcs[#mem_funcs+1] = k .. " = " .. type(v)
    end
    table.sort(mem_funcs)
    for _, f in ipairs(mem_funcs) do log("  " .. f) end
else
    log("memory table: NOT available")
end

-- PAGE_SIZE
log("")
log("PAGE_SIZE: " .. tostring(PAGE_SIZE))

log("")
log("=== IDENTITY PROBE DONE ===")
return table.concat(out, "\n")
