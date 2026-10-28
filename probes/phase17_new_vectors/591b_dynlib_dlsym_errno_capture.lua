-- CRASH_CLASS: ZERO
-- PROBE 591b: dynlib_dlsym — errno capture for error code discrimination
--
-- Context: The 13.60 handler returns positive SCE error codes (1, 3, 0x16, 0x2d, 0x4e).
-- The dispatch wrapper turns nonzero returns into userland -1/errno shape.
-- A -1 verdict hides the actual code; errno capture is the discriminator.
--
-- This probe tests 591 with every plausible handle value and captures errno.
-- Error 1 = process dynlib object missing (handle namespace not initialized)
-- Error 3 = handle not found / caller module mismatch
-- Error 0x16 = device or state issue
-- Error 0x2d = too many / resource limit
-- Error 0x4e = not found

print("=== PROBE 591b: DYNLIB_DLSYM ERRNO CAPTURE ===")
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

local sc591 = make_syscall(591)

local out_buf = memory.alloc(0x200)
local name_buf = memory.alloc(0x1000)

-- First, try to get a valid handle from 593
print("[A] Get a valid handle from sys 593:")
print("")

local sc593 = make_syscall(593)
local info_buf = memory.alloc(0x200)

local valid_handles = {}

for handle = 0, 20 do
    for i = 0, 0x57 do wd(info_buf + i * 4, 0) end
    wd(info_buf, 0x160)
    
    local ok, rv = pcall(function()
        return sc593(uint64(handle), uint64(info_buf))
    end)
    local ret = ok and to_num(rv) or -999
    
    if ok and ret == 0 then
        local name_bytes = {}
        for j = 0, 31 do
            local b = rd(info_buf + 8 + j) or 0
            local c = b % 256
            if c >= 32 and c <= 126 then
                table.insert(name_bytes, string.char(c))
            else
                break
            end
        end
        local name = table.concat(name_bytes)
        print(string.format("  handle=%d: 593 OK, name=%s", handle, name))
        table.insert(valid_handles, handle)
    end
end

print("")
print("[B] Test 591 with valid handles (errno capture):")
print("")

for hi, handle in ipairs(valid_handles) do
    for nid_idx, nid_str in ipairs({"printf", "malloc", "strlen", "open", "sceKernelExitProcess"}) do
        for i = 0, 0x9FF do wd(name_buf + i, 0) end
        for i = 1, #nid_str do
            wd(name_buf + i - 1, string.byte(nid_str, i))
        end
        for i = 0, 0x57 do wd(out_buf + i * 4, 0) end
        
        local ok, rv = pcall(function()
            return sc591(uint64(handle), uint64(name_buf), uint64(out_buf))
        end)
        local ret = ok and to_num(rv) or -999
        
        -- Try to read errno via sys 594 (or a known errno-reading mechanism)
        local errno_val = "N/A"
        if ok and ret == -1 then
            -- Try reading errno from common locations
            -- FreeBSD errno is typically in the TCB or a thread-local area
            -- We'll try reading from the output buffer area and nearby
            local test_addrs = {
                out_buf, out_buf + 8, out_buf + 16, out_buf + 32,
                out_buf + 64, out_buf + 128, out_buf + 256,
                name_buf, name_buf + 8, name_buf + 16,
            }
            for ta_idx, ta in ipairs(test_addrs) do
                local ev = rd(ta) or 0
                if ev > 0 and ev < 200 then
                    errno_val = string.format("0x%X (at +0x%X from out_buf)", ev, ta - out_buf)
                    break
                end
            end
        end
        
        local out_val = "N/A"
        if ok then
            local ov = rq(out_buf)
            if ov then
                local oh, ol = 0, to_num(ov)
                if type(ov) == "table" and ov.h then oh, ol = ov.h, ov.l end
                out_val = string.format("0x%08X_%08X", oh, ol)
            end
        end
        
        print(string.format("  591(h=%d, \"%s\"): ret=%-4s out=%s errno=%s",
            handle, nid_str, ret, out_val, errno_val))
    end
end

print("")
print("[C] Test 591 with handle range sweep (errno capture):")
print("")

local test_handles = {}
for h = 0, 255 do table.insert(test_handles, h) end
for h = 0xFFFF, 0xFFFF + 255 do table.insert(test_handles, h) end

for ni, nid_str in ipairs({"printf", "strlen"}) do
    for hi, handle in ipairs(test_handles) do
        if hi > 100 then break end  -- limit output
        
        for i = 0, 0x9FF do wd(name_buf + i, 0) end
        for i = 1, #nid_str do
            wd(name_buf + i - 1, string.byte(nid_str, i))
        end
        for i = 0, 0x57 do wd(out_buf + i * 4, 0) end
        
        local ok, rv = pcall(function()
            return sc591(uint64(handle), uint64(name_buf), uint64(out_buf))
        end)
        local ret = ok and to_num(rv) or -999
        
        if ret ~= -1 and ret ~= 0 then
            print(string.format("  591(h=%d, \"%s\"): ret=%d (non-standard)", handle, nid_str, ret))
        elseif ret == 0 then
            print(string.format("  591(h=%d, \"%s\"): ret=0 *** SUCCESS ***", handle, nid_str))
        end
    end
end

print("")
print("[D] Stability check:")
local ok, rv = pcall(function() return sc593(uint64(0), uint64(info_buf)) end)
print("  593(0, ...): ret=" .. (ok and to_num(rv) or "FAIL"))

print("")
print("=== PROBE 591b COMPLETE ===")
