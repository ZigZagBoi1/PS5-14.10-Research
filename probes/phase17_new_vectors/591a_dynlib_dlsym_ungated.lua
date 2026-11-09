-- CRASH_CLASS: ZERO
-- PROBE 591a: dynlib_dlsym — UNGATED kernel-side symbol resolution
--
-- Context: Handler 0x34ae90, narg 3: 591(handle: u32, name: char*, out_addr: u64*)
-- No authid gate, no bit-62 gate.
-- 14.10: six-zeros probe returns -1 (handle=0 failure, error 3).
--
-- Strategy:
--   A) Get a real handle from sys 593 (dynlib_get_info) — known to work
--   B) Call 591(handle, "common_nid", &out) for well-known NID strings
--   C) Capture errno to discriminate error codes (1 vs 3 vs 0x16)
--
-- Success = kernel dlsym for every loaded module.

print("=== PROBE 591a: DYNLIB_DLSYM UNGATED SYMBOL RESOLUTION ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
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

local NID_STRINGS = {
    "printf", "malloc", "free", "memcpy", "memset",
    "strlen", "strcmp", "open", "close", "read", "write",
    "_printf", "__printf", "sceKernelExitProcess",
    "sceKernelGetProcessTime", "sceKernelGetThreadTime",
    "dlsym", "load_prx", "start", "stop",
}

print("[A] Get a real handle from sys 593 (dynlib_get_info):")
print("")

local sc593 = make_syscall(593)
local sc591 = make_syscall(591)

local info_buf = memory.alloc(0x200)
local out_buf = memory.alloc(0x200)
local name_buf = memory.alloc(0x1000)

local best_handle = nil

for handle = 0, 10 do
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
        best_handle = handle
    else
        print(string.format("  handle=%d: 593 ret=%d", handle, ret))
    end
end

if best_handle == nil then
    print("  *** NO VALID HANDLE FOUND FROM 593 ***")
    print("  Trying handles 0xFFFF and 0x10000:")
    for handle in pairs({0xFFFF, 0x10000, 0x10001}) do
        for i = 0, 0x57 do wd(info_buf + i * 4, 0) end
        wd(info_buf, 0x160)
        local ok, rv = pcall(function()
            return sc593(uint64(handle), uint64(info_buf))
        end)
        local ret = ok and to_num(rv) or -999
        print(string.format("  handle=%d: 593 ret=%d", handle, ret))
        if ok and ret == 0 then best_handle = handle end
    end
end

print("")
print("[B] Test sys 591 (dynlib_dlsym) with known NID strings:")
print("")

if best_handle ~= nil then
    for nid_idx, nid_str in ipairs(NID_STRINGS) do
        for i = 0, 0x9FF do wd(name_buf + i, 0) end
        for i = 1, #nid_str do
            wd(name_buf + i - 1, string.byte(nid_str, i))
        end
        for i = 0, 0x57 do wd(out_buf + i * 4, 0) end
        
        local ok, rv = pcall(function()
            return sc591(uint64(best_handle), uint64(name_buf), uint64(out_buf))
        end)
        local ret = ok and to_num(rv) or -999
        
        local out_val = "N/A"
        if ok then
            local ov = rq(out_buf)
            if ov then
                local oh, ol = 0, to_num(ov)
                if type(ov) == "table" and ov.h then oh, ol = ov.h, ov.l end
                out_val = string.format("0x%08X_%08X", oh, ol)
            end
        end
        
        print(string.format("  591(h=%d, \"%s\"): ret=%-4s out=%s",
            best_handle, nid_str, ret, out_val))
    end
else
    print("  (skipped — no valid handle from 593)")
end

print("")
print("[C] Test sys 591 with handle=0 (control — should return error 3):")
for nid_idx, nid_str in ipairs(NID_STRINGS) do
    for i = 0, 0x57 do wd(out_buf + i * 4, 0) end
    for i = 0, 0x9FF do wd(name_buf + i, 0) end
    for i = 1, #nid_str do
        wd(name_buf + i - 1, string.byte(nid_str, i))
    end
    local ok, rv = pcall(function()
        return sc591(uint64(0), uint64(name_buf), uint64(out_buf))
    end)
    local ret = ok and to_num(rv) or -999
    print(string.format("  591(h=0, \"%s\"): ret=%-4s", nid_str, ret))
end

print("")
print("[D] Test sys 591 with handle=1 (control):")
for nid_idx, nid_str in ipairs(NID_STRINGS) do
    for i = 0, 0x57 do wd(out_buf + i * 4, 0) end
    for i = 0, 0x9FF do wd(name_buf + i, 0) end
    for i = 1, #nid_str do
        wd(name_buf + i - 1, string.byte(nid_str, i))
    end
    local ok, rv = pcall(function()
        return sc591(uint64(1), uint64(name_buf), uint64(out_buf))
    end)
    local ret = ok and to_num(rv) or -999
    print(string.format("  591(h=1, \"%s\"): ret=%-4s", nid_str, ret))
end

print("")
print("[E] Test sys 591 with handle=0xFFFFFFFF (control):")
for nid_idx, nid_str in ipairs(NID_STRINGS) do
    for i = 0, 0x57 do wd(out_buf + i * 4, 0) end
    for i = 0, 0x9FF do wd(name_buf + i, 0) end
    for i = 1, #nid_str do
        wd(name_buf + i - 1, string.byte(nid_str, i))
    end
    local ok, rv = pcall(function()
        return sc591(uint64(0xFFFFFFFF), uint64(name_buf), uint64(out_buf))
    end)
    local ret = ok and to_num(rv) or -999
    print(string.format("  591(h=0xFFFFFFFF, \"%s\"): ret=%-4s", nid_str, ret))
end

print("")
print("[F] Stability check:")
local ok, rv = pcall(function() return sc593(uint64(0), uint64(info_buf)) end)
print("  593(0, ...): ret=" .. (ok and to_num(rv) or "FAIL"))

print("")
print("=== PROBE 591a COMPLETE ===")
