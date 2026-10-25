-- CRASH_CLASS: ZERO
-- PROBE 656a: dynlib_get_info_for_libdbg — debug-unit gate
--
-- Context: Handler 0x34c350, narg 2: 656(id: u32, info: void* (size qword at +0 must be 0x160))
-- Gate: 0xacce10() != 0 || 0xacce50() != 0 — debug-unit predicates.
-- On retail, both predicates likely fail → error 1.
-- A single live call settles whether the debug-unit predicates pass on this console.
--
-- Strategy:
--   A) Call 656(handle, ptr-to-0x160) for handles 0-10
--   B) Dump all 0x160 bytes, scan for kernel pointers
--   C) Compare with 593 output

print("=== PROBE 656a: DYNLIB_GET_INFO_FOR_LIBDBG ===")
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

local sc593 = make_syscall(593)
local sc656 = make_syscall(656)

local info_buf = memory.alloc(0x200)
local info656_buf = memory.alloc(0x200)

print("[A] Enumerate valid handles via sys 593:")
print("")

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
    else
        print(string.format("  handle=%d: 593 ret=%d", handle, ret))
    end
end

print("")
print("[B] Call sys 656 (dynlib_get_info_for_libdbg) for each valid handle:")
print("")
print("  NOTE: 656 has a debug-unit gate. On retail, likely returns error 1.")
print("  A single live call settles whether the gate passes on this console.")
print("")

for hi, handle in ipairs(valid_handles) do
    print(string.format("--- handle=%d ---", handle))
    
    -- Zero buffer and set size
    for i = 0, 0x57 do wd(info656_buf + i * 4, 0) end
    local ok, rv = pcall(function()
        return sc656(uint64(handle), uint64(info656_buf))
    end)
    local ret = ok and to_num(rv) or -999
    
    if ok and ret == 0 then
        print("  656 ret=0 — DEBUG UNIT GATE PASSES!")
        
        -- Read name
        local name_bytes = {}
        for j = 0, 31 do
            local b = rd(info656_buf + 8 + j) or 0
            local c = b % 256
            if c >= 32 and c <= 126 then
                table.insert(name_bytes, string.char(c))
            else
                break
            end
        end
        local name = table.concat(name_bytes)
        print(string.format("  name=%s", name))
        
        -- Read segment count
        local seg_count = rd(info656_buf + 0x148) or 0
        print(string.format("  segment_count=%d", seg_count))
        
        -- Read segments
        for s = 0, math.min(seg_count - 1, 3) do
            local seg_base = info656_buf + 0x108 + s * 16
            local addr_val = rq(seg_base)
            local size_val = rq(seg_base + 8)
            if addr_val then
                local ah, al = 0, to_num(addr_val)
                if type(addr_val) == "table" and addr_val.h then ah, al = addr_val.h, addr_val.l end
                local sh, sl = 0, to_num(size_val)
                if type(size_val) == "table" and size_val.h then sh, sl = size_val.h, size_val.l end
                print(string.format("    seg[%d]: addr=%s size=%s",
                    s, string.format("0x%08X_%08X", ah, al),
                    string.format("0x%08X_%08X", sh, sl)))
                if ah >= 0xFFFF8000 and ah ~= 0xFFFFFFFF then
                    print("    *** KERNEL POINTER IN SEGMENT ADDRESS ***")
                end
            end
        end
        
        -- Check NID/fingerprint block at +0x14C
        print("    nid_fingerprint[+0x14C]:")
        for i = 0, 15 do
            local tv = rd(info656_buf + 0x14C + i * 4) or 0
            if tv ~= 0 then
                print(string.format("      +0x%X: 0x%08X", 0x14C + i * 4, tv))
            end
        end
        
        -- Kernel pointer scan
        print("    kernel_ptr_scan:")
        for off = 0, 0x158, 8 do
            local val = rq(info656_buf + off)
            if val then
                local h, l = 0, to_num(val)
                if type(val) == "table" and val.h then h, l = val.h, val.l end
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print(string.format("      *** KERNEL PTR at +0x%03X: %s ***",
                        off, string.format("0x%08X_%08X", h, l)))
                end
            end
        end
    else
        print(string.format("  656 ret=%d (gate likely fails on retail)", ret))
    end
    print("")
end

if #valid_handles == 0 then
    print("  (no valid handles — testing 656 with handle=0 as fallback)")
    for i = 0, 0x57 do wd(info656_buf + i * 4, 0) end
    local ok, rv = pcall(function()
        return sc656(uint64(0), uint64(info656_buf))
    end)
    local ret = ok and to_num(rv) or -999
    print(string.format("  656(0, ...): ret=%d", ret))
end

print("[C] Stability check:")
local ok, rv = pcall(function() return sc593(uint64(0), uint64(info_buf)) end)
print("  593(0, ...): ret=" .. (ok and to_num(rv) or "FAIL"))

print("")
print("=== PROBE 656a COMPLETE ===")
