-- CRASH_CLASS: ZERO
-- PROBE 660a: dynlib_get_info2 — NO GATE, untested with real args
--
-- Context: Handler 0x34bc60, narg 2: 660(id: u32, info: void*)
-- No authid gate, no bit-62 gate. Prologue matches 593's exactly.
-- 14.10: six-zeros probe returns -1 (same as 593 with handle=0).
--
-- Strategy:
--   A) Get real handles from 593
--   B) Call 660(handle, ptr-to-0x160) for each valid handle
--   C) Dump all 0x160 bytes, sentinel-scan for kernel pointers
--   D) Diff against 593 output for differences

print("=== PROBE 660a: DYNLIB_GET_INFO2 NO GATE ===")
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
local function fmt(val)
    if type(val) == "table" and val.h then
        return string.format("0x%08X_%08X", val.h, val.l)
    end
    local n = to_num(val)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end

local sc593 = make_syscall(593)
local sc660 = make_syscall(660)

local info_buf = memory.alloc(0x200)
local info2_buf = memory.alloc(0x200)
local handles_buf = memory.alloc(0x1000)

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

if #valid_handles == 0 then
    print("  *** NO VALID HANDLES FROM 593 — trying broader range ***")
    for handle = 0, 100 do
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
            if #valid_handles >= 10 then break end
        end
    end
end

print("")
print("[B] Call sys 660 (dynlib_get_info2) for each valid handle:")
print("")

for hi, handle in ipairs(valid_handles) do
    print(string.format("--- handle=%d ---", handle))
    
    -- Call 660
    for i = 0, 0x57 do wd(info2_buf + i * 4, 0) end
    local ok, rv = pcall(function()
        return sc660(uint64(handle), uint64(info2_buf))
    end)
    local ret = ok and to_num(rv) or -999
    
    if ok and ret == 0 then
        -- Read name
        local name_bytes = {}
        for j = 0, 31 do
            local b = rd(info2_buf + 8 + j) or 0
            local c = b % 256
            if c >= 32 and c <= 126 then
                table.insert(name_bytes, string.char(c))
            else
                break
            end
        end
        local name = table.concat(name_bytes)
        print(string.format("  660 ret=0, name=%s", name))
        
        -- Read segment count
        local seg_count = rd(info2_buf + 0x148) or 0
        print(string.format("  segment_count=%d", seg_count))
        
        -- Read segments
        for s = 0, math.min(seg_count - 1, 3) do
            local seg_base = info2_buf + 0x108 + s * 16
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
        
        -- Check tail at +0x14C
        print("    tail[+0x14C]:")
        for i = 0, 7 do
            local tv = rd(info2_buf + 0x14C + i * 4) or 0
            if tv ~= 0 then
                print(string.format("      +0x%X: 0x%08X", 0x14C + i * 4, tv))
            end
        end
        
        -- Kernel pointer scan of full 0x160
        print("    kernel_ptr_scan:")
        for off = 0, 0x158, 8 do
            local val = rq(info2_buf + off)
            if val then
                local h, l = 0, to_num(val)
                if type(val) == "table" and val.h then h, l = val.h, val.l end
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print(string.format("      *** KERNEL PTR at +0x%03X: %s ***",
                        off, string.format("0x%08X_%08X", h, l)))
                end
            end
        end
        
        -- Compare with 593
        for i = 0, 0x57 do wd(info_buf + i * 4, 0) end
        wd(info_buf, 0x160)
        local ok2, rv2 = pcall(function()
            return sc593(uint64(handle), uint64(info_buf))
        end)
        if ok2 and to_num(rv2) == 0 then
            local diffs = 0
            for off = 0x108, 0x15F, 4 do
                local v1 = rd(info_buf + off) or 0
                local v2 = rd(info2_buf + off) or 0
                if v1 ~= v2 then diffs = diffs + 1 end
            end
            if diffs > 0 then
                print(string.format("    *** %d DIFFERENCES vs 593 in segment area ***", diffs))
            else
                print("    (identical to 593 in segment area)")
            end
        end
    else
        if ret == 1 then
            print(string.format("  660 ret=1 (not dynamic or filtered)"))
        elseif ret == 3 then
            print(string.format("  660 ret=3 (handle not found)"))
        else
            print(string.format("  660 ret=%d", ret))
        end
    end
    print("")
end

if #valid_handles == 0 then
    print("  (no valid handles to test 660)")
end

print("[C] Stability check:")
local ok, rv = pcall(function() return sc593(uint64(0), uint64(info_buf)) end)
print("  593(0, ...): ret=" .. (ok and to_num(rv) or "FAIL"))

print("")
print("=== PROBE 660a COMPLETE ===")
