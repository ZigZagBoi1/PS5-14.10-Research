-- CRASH_CLASS: ZERO
-- PROBE 594a: dynlib_load_prx — handle generation for 591
--
-- Context: We need real module handles for 591 (dynlib_dlsym).
-- sys 593 (dynlib_get_info) gives us existing handles.
-- sys 594 (dynlib_load_prx) may give us NEW handles by loading a PRX module.
--
-- 594 signature: 594(path: char*, flags: u64, out_handle: u64*)
-- or possibly: 594(path: char*, out_handle: u64*, flags: u64)
--
-- If 594 works, the returned handle is a fresh module handle for 591.

print("=== PROBE 594a: DYNLIB_LOAD_PRX HANDLE GENERATION ===")
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
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc594 = make_syscall(594)
local sc593 = make_syscall(593)

local path_buf = memory.alloc(0x1000)
local out_handle_buf = memory.alloc(0x200)
local info_buf = memory.alloc(0x200)

-- Common PRX paths on PS5
local PRX_PATHS = {
    "/hostapp/sys/lib/scePad.sprx",
    "/hostapp/sys/lib/sceControllerManager.sprx",
    "/system/sys/lib/libSceIosSdk.sprx",
    "/system/sys/lib/libSceSysUtil.sprx",
    "/system/sys/lib/libSceSysCred.sprx",
    "/system/sys/lib/libSceNpManager.sprx",
    "/system/sys/lib/libSceNpService.sprx",
    "/system/sys/lib/libSceAudioOutput.sprx",
    "/system/sys/lib/libSceGpuRes.sprx",
    "/system/sys/lib/libSceDisplaySrv.sprx",
    "libkernel_srv.sprx",
    "libSceFios2.sprx",
    "libSceJit.sprx",
    "libSceMdbgEngine.sprx",
    "libScePdfEmulator.sprx",
}

print("[A] Test sys 594 (dynlib_load_prx) with common PRX paths:")
print("")
print("  Signature: 594(path: char*, flags: u64, out_handle: u64*)")
print("  Or possibly: 594(path: char*, out_handle: u64*, flags: u64)")
print("")

for path_idx, prx_path in ipairs(PRX_PATHS) do
    -- Write the PRX path to the buffer
    for i = 0, 0x9FF do wd(path_buf + i, 0) end
    for i = 1, #prx_path do
        wd(path_buf + i - 1, string.byte(prx_path, i))
    end
    
    -- Zero the out handle buffer
    for i = 0, 0x57 do wd(out_handle_buf + i * 4, 0) end
    
    -- Try with flags=0 as arg2
    local ok1, rv1 = pcall(function()
        return sc594(uint64(path_buf), uint64(0), uint64(out_handle_buf))
    end)
    local ret1 = ok1 and to_num(rv1) or -999
    
    -- Try with flags=0 as arg3 (swapped args)
    local ok2, rv2 = pcall(function()
        return sc594(uint64(path_buf), uint64(out_handle_buf), uint64(0))
    end)
    local ret2 = ok2 and to_num(rv2) or -999
    
    -- Read the output handle
    local out_handle = "N/A"
    if ok1 then
        local oh = rq(out_handle_buf)
        if oh then
            local oh_h, oh_l = 0, to_num(oh)
            if type(oh) == "table" and oh.h then oh_h, oh_l = oh.h, oh.l end
            out_handle = string.format("0x%08X_%08X", oh_h, oh_l)
        end
    end
    
    print(string.format("  path=\"%s\":", prx_path))
    print(string.format("    arg2=flags(0), arg3=out: ret=%d", ret1))
    print(string.format("    arg2=out, arg3=flags(0): ret=%d", ret2))
    if out_handle ~= "N/A" then
        print(string.format("    out_handle=%s", out_handle))
    end
end

print("")
print("[B] Test sys 594 with empty/NULL path:")
for i = 0, 0x9FF do wd(path_buf + i, 0) end
for i = 0, 0x57 do wd(out_handle_buf + i * 4, 0) end

local ok1, rv1 = pcall(function()
    return sc594(uint64(path_buf), uint64(0), uint64(out_handle_buf))
end)
local ret1 = ok1 and to_num(rv1) or -999
print(string.format("  594(NULL, 0, out): ret=%d", ret1))

local ok2, rv2 = pcall(function()
    return sc594(uint64(0), uint64(out_handle_buf), uint64(0))
end)
local ret2 = ok2 and to_num(rv2) or -999
print(string.format("  594(0, out, 0): ret=%d", ret2))

print("")
print("[C] Test sys 594 with various flag values:")
for i = 0, 0x9FF do wd(path_buf + i, 0) end
for i = 1, 12 do wd(path_buf + i - 1, string.byte("/hostapp/sys/lib/libSceSysUtil.sprx", i)) end
for i = 0, 0x57 do wd(out_handle_buf + i * 4, 0) end

local flags = {0, 1, 2, 0x100, 0x1000, 0x10000, 0xFFFFFFFF}
for fi, flag in ipairs(flags) do
    local ok, rv = pcall(function()
        return sc594(uint64(path_buf), uint64(flag), uint64(out_handle_buf))
    end)
    local ret = ok and to_num(rv) or -999
    print(string.format("  594(path, flag=0x%X, out): ret=%d", flag, ret))
end

print("")
print("[D] Stability check:")
local ok, rv = pcall(function() return sc593(uint64(0), uint64(info_buf)) end)
print("  593(0, ...): ret=" .. (ok and to_num(rv) or "FAIL"))

print("")
print("=== PROBE 594a COMPLETE ===")
