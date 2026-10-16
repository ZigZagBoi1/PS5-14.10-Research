-- 14.10 Recon Probe 05: Filesystem & Module Recon
-- Uses syscall.resolve() properly

local out = {}
local function log(s) out[#out+1] = s; print(s) end

log("=== 14.10 RECON: FILE RECON ===")
log("fw: " .. tostring(FW_VERSION))

syscall.resolve({
    sc_open = 5, sc_close = 6, sc_read = 3,
    sc_getdents = 272, sc_fstat = 189,
})

local function list_dir(path)
    local entries = {}
    local ok, err = pcall(function()
        local fd = syscall.sc_open(path, 0x00020000):tonumber()
        if fd < 0 then
            fd = syscall.sc_open(path, 0):tonumber()
        end
        if fd < 0 then return end

        local buf = memory.alloc(4096)
        while true do
            local n = syscall.sc_getdents(fd, buf, 4096):tonumber()
            if n <= 0 then break end

            local pos = 0
            while pos < n do
                local reclen = memory.read_word(buf + pos + 4):tonumber()
                if reclen == 0 then break end
                local d_type = memory.read_byte(buf + pos + 6):tonumber()

                local name_chars = {}
                for i = 0, math.min(reclen - 9, 255) do
                    local b = memory.read_byte(buf + pos + 8 + i):tonumber()
                    if b == 0 then break end
                    name_chars[#name_chars+1] = string.char(b)
                end
                local name = table.concat(name_chars)

                local type_str = "?"
                if d_type == 4 then type_str = "dir"
                elseif d_type == 8 then type_str = "file"
                elseif d_type == 10 then type_str = "link"
                elseif d_type == 2 then type_str = "chr"
                elseif d_type == 6 then type_str = "blk"
                end

                entries[#entries+1] = { name=name, dtype=type_str }
                pos = pos + reclen
            end
        end

        syscall.sc_close(fd)
    end)

    return entries, ok, err
end

local function read_file_head(path, max_bytes)
    max_bytes = max_bytes or 256
    local ok, result = pcall(function()
        local fd = syscall.sc_open(path, 0):tonumber()
        if fd < 0 then return nil end
        local buf = memory.alloc(max_bytes + 1)
        local n = syscall.sc_read(fd, buf, max_bytes):tonumber()
        syscall.sc_close(fd)
        if n <= 0 then return nil end
        local chars = {}
        for i = 0, n-1 do
            local b = memory.read_byte(buf + i):tonumber()
            if b == 0 then break end
            if b >= 32 and b < 127 then
                chars[#chars+1] = string.char(b)
            else
                chars[#chars+1] = "."
            end
        end
        return table.concat(chars)
    end)
    return ok and result or nil
end

local dirs_to_scan = {
    "/", "/dev", "/system", "/system/common",
    "/system/common/lib", "/system/priv/lib",
    "/system/sys", "/system/vsh",
    "/savedata0",
    "/app0", "/app0/sce_module",
    "/data",
    "/mnt", "/mnt/usb0", "/mnt/usb1",
    "/mnt/sandbox",
    "/proc",
    "/system_ex", "/system_ex/app",
}

for _, dir in ipairs(dirs_to_scan) do
    local entries, ok, err = list_dir(dir)
    if #entries > 0 then
        log("")
        log("--- " .. dir .. " (" .. #entries .. " entries) ---")
        for _, e in ipairs(entries) do
            log("  [" .. e.dtype .. "] " .. e.name)
        end
    else
        log("")
        log("--- " .. dir .. ": " .. (ok and "empty/inaccessible" or tostring(err):sub(1,40)))
    end
end

log("")
log("--- version files ---")

local version_files = {
    "/system/common/lib/build_tag.txt",
    "/system/common/lib/version.txt",
    "/system/build_tag",
    "/system/version",
    "/system/sys/version",
    "/savedata0/version.txt",
}

for _, path in ipairs(version_files) do
    local content = read_file_head(path, 512)
    if content then
        log("  " .. path .. ": " .. content)
    end
end

log("")
log("--- loaded modules ---")
local mod_entries = list_dir("/app0/sce_module")
if #mod_entries > 0 then
    for _, e in ipairs(mod_entries) do
        if e.name:find("%.prx$") or e.name:find("%.sprx$") then
            log("  " .. e.name)
        end
    end
end

local sys_mod_entries = list_dir("/system/common/lib")
if #sys_mod_entries > 0 then
    log("")
    log("--- /system/common/lib ---")
    local count = 0
    for _, e in ipairs(sys_mod_entries) do
        if e.name:find("%.prx$") or e.name:find("%.sprx$") then
            log("  " .. e.name)
            count = count + 1
            if count > 50 then
                log("  ... (truncated, " .. #sys_mod_entries .. " total)")
                break
            end
        end
    end
end

log("")
log("--- sandbox check ---")
local sandbox_tests = {
    "/", "/..",
    "/system/vsh/app/NPXS20001",
    "/user/home",
    "/mnt/sandbox/pfsmnt",
}
for _, path in ipairs(sandbox_tests) do
    local entries = list_dir(path)
    log("  " .. path .. ": " .. #entries .. " entries")
end

log("")
log("=== FILE RECON DONE ===")
return table.concat(out, "\n")
