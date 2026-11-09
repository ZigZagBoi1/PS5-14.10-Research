-- CRASH_CLASS: LOW
-- PROBE p571: Find browser-launch imports in eboot GOT + try loading browser module
--
-- Context: dlsym fails (NID hashing). Scan eboot GOT for function pointers
-- into libSceSystemService text range. Also try dynlib_load_prx to load
-- browser dialog module.

print("=== PROBE p571: Browser Imports + Module Load ===")
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

-- Get eboot info
local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local eb_text_lo = safe_rd(info + 0x108)
local eb_text_hi = safe_rd(info + 0x10C)
local eb_text_sz_lo = safe_rd(info + 0x110)
local eb_text_sz_hi = safe_rd(info + 0x114)
local eb_data_lo = safe_rd(info + 0x120)
local eb_data_hi = safe_rd(info + 0x124)
local eb_data_sz_lo = safe_rd(info + 0x128)
local eb_data_sz_hi = safe_rd(info + 0x12C)
print(string.format("[A] eboot text: 0x%X%08X sz: 0x%X%08X", eb_text_hi or 0, eb_text_lo or 0, eb_text_sz_hi or 0, eb_text_sz_lo or 0))
print(string.format("    eboot data: 0x%X%08X sz: 0x%X%08X", eb_data_hi or 0, eb_data_lo or 0, eb_data_sz_hi or 0, eb_data_sz_lo or 0))

-- Get libSceSystemService text range
safe_wd(info, 0x160)
pcall(function() sc_info(uint64(142), info) end)
local ss_text_lo = safe_rd(info + 0x108)
local ss_text_hi = safe_rd(info + 0x10C)
local ss_text_sz_lo = safe_rd(info + 0x110)
local ss_text_sz_hi = safe_rd(info + 0x114)
print(string.format("[A] SysService text: 0x%X%08X sz: 0x%X%08X", ss_text_hi or 0, ss_text_lo or 0, ss_text_sz_hi or 0, ss_text_sz_lo or 0))

local ss_base = uint64(string.format("0x%X%08X", ss_text_hi, ss_text_lo))
local ss_end = uint64(string.format("0x%X%08X", ss_text_hi, ss_text_lo + ss_text_sz_lo))

-- Scan eboot data segment for pointers into libSceSystemService
print("")
print("[B] Scanning eboot data for SysService function pointers...")
local eb_data_base = uint64(string.format("0x%X%08X", eb_data_hi, eb_data_lo))
local found_ptrs = {}
local scan_count = 0
local max_scan = math.min(to_num(eb_data_sz_lo), 0x100000) -- max 1MB

for off = 0, max_scan - 8, 8 do
    local val = safe_rq(eb_data_base + off)
    if val then
        local vh, vl = get_hi_lo(val)
        -- Check if pointer falls in SysService text range
        if vh == ss_text_hi and vl >= ss_text_lo and vl < (ss_text_lo + ss_text_sz_lo) then
            local offset_in_lib = vl - ss_text_lo
            table.insert(found_ptrs, {off = off, val_h = vh, val_l = vl, lib_off = offset_in_lib})
            if #found_ptrs <= 50 then
                print(string.format("  data+0x%X -> SysService+0x%X (0x%X%08X)", off, offset_in_lib, vh, vl))
            end
        end
    end
    scan_count = scan_count + 1
    if scan_count % 0x10000 == 0 then
        -- progress
    end
end
print(string.format("  Scanned %d qwords, found %d SysService pointers", scan_count, #found_ptrs))

-- [C] Try loading browser-related modules via dynlib_load_prx (sys 594)
print("")
print("[C] Trying to load browser modules via sys 594...")
local sc_load = make_syscall(594)
local handle_out = memory.alloc(8)

local modules_to_try = {
    "libSceWebBrowserDialog.sprx",
    "libSceBrowser.sprx",
    "libSceWebView.sprx",
    "libSceCommonDialog.sprx",
    "libSceImeDialog.sprx",
    "libSceSystemService.sprx",
}

for _, mod in ipairs(modules_to_try) do
    safe_wq(handle_out, uint64(0))
    local name_buf = memory.alloc(256)
    for i = 1, #mod do
        safe_wd(name_buf + i - 1, string.byte(mod, i))
    end
    safe_wd(name_buf + #mod, 0)

    local ok, r = pcall(function()
        return sc_load(uint64(name_buf), uint64(0), uint64(handle_out), uint64(0))
    end)
    local h = safe_rq(handle_out)
    local hh, hl = get_hi_lo(h)
    local rh, rl = 0, 0
    if r then rh, rl = get_hi_lo(r) end
    print(string.format("  load('%s'): ok=%s ret=0x%X%08X handle=0x%X%08X", mod, tostring(ok), rh, rl, hh, hl))
end

-- [D] Try NID-based dlsym
-- PS4/PS5 NID format: first 11 chars of base64(sha1(name#lib:libname#suffix))
-- Known NIDs from PS4 scene for sceSystemServiceLaunchWebBrowser
print("")
print("[D] Trying NID-based dlsym (sys 591)...")
local sc_dlsym = make_syscall(591)
local result_addr = memory.alloc(8)

-- Known PS4 NIDs for browser functions (may differ on PS5)
local nids_to_try = {
    -- sceSystemServiceLaunchWebBrowser NID from PS4
    {"sceSystemServiceLaunchWebBrowser", "A08050A1"},
    -- Try common Sony NID encoding patterns
    {"sceSystemServiceLoadExec", "4AEA1E04"},
    {"sceSystemServiceLaunchApp", "689A4A9D"},
}

-- Also try calling sys 591 with the NID as an integer instead of string
for _, entry in ipairs(nids_to_try) do
    local fname, nid_hex = entry[1], entry[2]
    safe_wq(result_addr, uint64(0))

    -- Try NID as string
    local nid_buf = memory.alloc(256)
    for i = 1, #nid_hex do
        safe_wd(nid_buf + i - 1, string.byte(nid_hex, i))
    end
    safe_wd(nid_buf + #nid_hex, 0)

    local ok, r = pcall(function()
        return sc_dlsym(uint64(142), uint64(nid_buf), uint64(result_addr))
    end)
    local resolved = safe_rq(result_addr)
    local rsh, rsl = get_hi_lo(resolved)
    print(string.format("  dlsym(142, '%s'): ok=%s resolved=0x%X%08X", nid_hex, tostring(ok), rsh, rsl))
end

-- [E] If we found SysService pointers, try calling each as a browser launch
print("")
print("[E] Testing found SysService function pointers...")

if native and native.fcall_with_rax and #found_ptrs > 0 then
    local url_str = "http://10.0.0.231/"
    local url_buf = memory.alloc(256)
    for i = 1, #url_str do
        safe_wd(url_buf + i - 1, string.byte(url_str, i))
    end
    safe_wd(url_buf + #url_str, 0)

    -- Only try first 20 to avoid killing the process
    local try_count = math.min(#found_ptrs, 20)
    for i = 1, try_count do
        local p = found_ptrs[i]
        local func = uint64(string.format("0x%X%08X", p.val_h, p.val_l))
        local call_ok, call_ret = pcall(function()
            return native.fcall_with_rax(func, url_buf)
        end)
        local crh, crl = 0, 0
        if call_ret then crh, crl = get_hi_lo(call_ret) end
        print(string.format("  SysService+0x%X: ok=%s ret=0x%X%08X", p.lib_off, tostring(call_ok), crh, crl))
        if not call_ok then
            print("    CRASHED - stopping function calls")
            break
        end
    end
else
    if #found_ptrs == 0 then
        print("  No SysService pointers found in eboot data")
    else
        print("  native.fcall_with_rax not available")
    end
end

print("")
print("=== PROBE p571 COMPLETE ===")
