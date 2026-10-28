-- CRASH_CLASS: LOW
-- PROBE 74e: Verify module data kernel-shaped values across connections
--
-- 74c found 1033 kernel-shaped values in module writable data segments
-- (modules 2, 17, 20, 34, 49, 50). Run this TWICE and compare:
-- - Same values both runs → could be real kernel pointers (same KASLR slide)
-- - Different values → NID hashes or userland-derived data
-- Per-connection ASLR only affects userland. Kernel base is fixed per boot.

print("=== PROBE 74e: MODULE KPTR VERIFICATION ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local sc_info = mk(593)
local targets = {2, 17, 20, 34, 49, 50}

for _, handle in ipairs(targets) do
    local minfo = memory.alloc(0x200)
    wd(N(minfo), 0x160)
    local ret = -999
    pcall(function() ret = N(sc_info(uint64(handle), minfo)) end)
    if ret ~= 0 then
        print(string.format("module %d: not found", handle))
    else
        local data_lo = rd(N(minfo) + 0x118) or 0
        local data_hi = rd(N(minfo) + 0x11C) or 0
        local data_sz = rd(N(minfo) + 0x120) or 0
        if data_lo < 0 then data_lo = data_lo + 0x100000000 end
        if data_hi < 0 then data_hi = data_hi + 0x100000000 end
        if data_sz < 0 then data_sz = data_sz + 0x100000000 end

        local text_lo = rd(N(minfo) + 0x108) or 0
        local text_hi = rd(N(minfo) + 0x10C) or 0
        if text_lo < 0 then text_lo = text_lo + 0x100000000 end
        if text_hi < 0 then text_hi = text_hi + 0x100000000 end

        print(string.format("MODULE %d: text=0x%X%08X data=0x%X%08X size=0x%X",
            handle, text_hi, text_lo, data_hi, data_lo, data_sz))

        if data_sz > 0 and data_hi > 0 then
            local scan_sz = math.min(data_sz, 0x40000)
            local count = 0
            local i = 0
            while i + 7 < scan_sz do
                local addr = uint64(string.format("0x%X%08X", data_hi, data_lo + i))
                local val = rq(addr)
                if val then
                    local h, l = get_hi_lo(val)
                    if h < 0 then h = h + 0x100000000 end
                    if l < 0 then l = l + 0x100000000 end
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        count = count + 1
                        if count <= 15 then
                            print(string.format("  +0x%04X = 0x%08X%08X", i, h, l))
                        end
                    end
                end
                i = i + 8
            end
            print(string.format("  total kshape: %d", count))
        end
    end
end

print("")
print("=== PROBE 74e COMPLETE ===")
