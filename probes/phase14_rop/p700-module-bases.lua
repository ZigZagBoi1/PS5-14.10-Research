-- CRASH_CLASS: LOW
-- PROBE P700: Enumerate all loaded modules and find base addresses
-- Context: We need libkernel_web and libSceLibcInternal bases for ROP chain
-- Uses syscall 592 (dynlib_get_list) and 593 (dynlib_get_info)

print("=== PROBE P700: MODULE BASE DISCOVERY ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end

-- Allocate buffers
local handle_buf = memory.alloc(0x400)   -- space for up to 128 handles (4 bytes each)
local count_buf = memory.alloc(0x10)     -- for count output
local info_buf = memory.alloc(0x200)     -- dynlib_get_info output struct

-- Zero buffers
for i = 0, 0x3FF, 4 do safe_wd(handle_buf + i, 0) end
for i = 0, 0xF, 4 do safe_wd(count_buf + i, 0) end
for i = 0, 0x1FF, 4 do safe_wd(info_buf + i, 0) end

-- Step 1: dynlib_get_list (syscall 592)
-- int dynlib_get_list(int *handles, int max_count, int *actual_count)
print("[*] Calling dynlib_get_list (syscall 592)...")
local sc_getlist = make_syscall(592)
local ret = -999
pcall(function()
    ret = to_num(sc_getlist(handle_buf, uint64(128), count_buf))
end)
print("    ret = " .. ret)

local count = safe_rd(count_buf)
print("    module count = " .. tostring(count))

if not count or count == 0 then
    print("[!] No modules returned. Trying alternative approach...")
    -- Try with different arg order or check if blocked
    count = 0
end

-- Step 2: For each handle, get info
print("")
print("[*] Enumerating module info (syscall 593)...")
local sc_getinfo = make_syscall(593)

local modules = {}

for idx = 0, math.min((count or 0) - 1, 127) do
    local handle = safe_rd(handle_buf + idx * 4)
    if not handle or handle == 0 then break end

    -- Zero info buffer
    for i = 0, 0x1FF, 4 do safe_wd(info_buf + i, 0) end
    -- Set buffer size (first field)
    safe_wd(info_buf, 0x160)

    local info_ret = -999
    pcall(function()
        info_ret = to_num(sc_getinfo(uint64(handle), info_buf))
    end)

    if info_ret == 0 then
        -- Parse info struct
        -- Offset 0x00: size (uint32)
        -- Offset 0x08: name (char[256]) - at offset 8
        -- Offset 0x108: ... varies by FW
        -- Offset 0x??: mapbase, mapsize, text_base, text_size
        -- The exact layout needs to be determined empirically

        -- Read name (try offset 0x08, up to 64 chars)
        local name_bytes = {}
        for i = 0, 63 do
            local b = safe_rd(info_buf + 8 + i)
            if b then
                local c1 = b % 256
                local c2 = math.floor(b / 256) % 256
                local c3 = math.floor(b / 65536) % 256
                local c4 = math.floor(b / 16777216) % 256
                if c1 == 0 then break end
                name_bytes[#name_bytes + 1] = string.char(c1)
                if c2 == 0 then break end
                name_bytes[#name_bytes + 1] = string.char(c2)
                if c3 == 0 then break end
                name_bytes[#name_bytes + 1] = string.char(c3)
                if c4 == 0 then break end
                name_bytes[#name_bytes + 1] = string.char(c4)
            end
        end
        local name = table.concat(name_bytes)

        -- Read potential base addresses at various offsets
        -- Try common offsets for mapbase: 0x108, 0x110, 0x118, 0x120
        local mapbase = safe_rq(info_buf + 0x108)
        local mapsize = safe_rq(info_buf + 0x110)
        local textbase = safe_rq(info_buf + 0x118)
        local textsize = safe_rq(info_buf + 0x120)

        local mb_h, mb_l = get_hi_lo(mapbase)
        local ms_h, ms_l = get_hi_lo(mapsize)
        local tb_h, tb_l = get_hi_lo(textbase)
        local ts_h, ts_l = get_hi_lo(textsize)

        print(string.format("  [%d] handle=%d name='%s'", idx, handle, name))
        print(string.format("       mapbase=0x%X%08X mapsize=0x%X%08X", mb_h, mb_l, ms_h, ms_l))
        print(string.format("       textbase=0x%X%08X textsize=0x%X%08X", tb_h, tb_l, ts_h, ts_l))

        -- Also dump raw bytes at key offsets for analysis
        print("       raw@0x100: " .. string.format("%08X", safe_rd(info_buf + 0x100) or 0) .. " " ..
              string.format("%08X", safe_rd(info_buf + 0x104) or 0))
        print("       raw@0x108: " .. string.format("%08X", safe_rd(info_buf + 0x108) or 0) .. " " ..
              string.format("%08X", safe_rd(info_buf + 0x10C) or 0))
        print("       raw@0x110: " .. string.format("%08X", safe_rd(info_buf + 0x110) or 0) .. " " ..
              string.format("%08X", safe_rd(info_buf + 0x114) or 0))
        print("       raw@0x118: " .. string.format("%08X", safe_rd(info_buf + 0x118) or 0) .. " " ..
              string.format("%08X", safe_rd(info_buf + 0x11C) or 0))

        modules[#modules + 1] = {
            handle = handle,
            name = name,
            mapbase_h = mb_h, mapbase_l = mb_l,
        }

        -- Flag if this is a target module
        if name:find("libkernel") then
            print("  >>> FOUND libkernel! <<<")
        end
        if name:find("LibcInternal") then
            print("  >>> FOUND libSceLibcInternal! <<<")
        end
    else
        print(string.format("  [%d] handle=%d info_ret=%d (failed)", idx, handle, info_ret))
    end
end

print("")
print("=== SUMMARY ===")
print("Total modules: " .. #modules)
for _, m in ipairs(modules) do
    print(string.format("  %-40s base=0x%X%08X", m.name, m.mapbase_h, m.mapbase_l))
end
print("")
print("=== P700 COMPLETE ===")
