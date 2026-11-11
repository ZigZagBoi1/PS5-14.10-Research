-- CRASH_CLASS: MODERATE
-- PROBE 937a: the three handlers whose 13.60 bodies contradict our verdicts
--
-- docs/ATTACK_SURFACE.md records 641 get_cpu_usage_proc, 642 get_map_statistics
-- and 646 get_kernel_mem_statistics as "-1", but the decompiled 13.60 bodies
-- cannot return -1 at all: 641 returns a computed value, 642 and 646 copy a
-- statistics block to the caller's buffer. So the -1 in those rows came from the
-- argument shape we used, not from a gate.
--
-- 646 is the interesting one: "kernel memory statistics" is a KASLR-adjacent
-- oracle if it can be reached. Each layout is tried with a 0x400 scratch buffer
-- that is zeroed first, and every nonzero dword is printed.

print("=== PROBE 937a: 641 / 642 / 646 ARGUMENT SHAPES ===")
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
local function safe_wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function safe_rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function call(num, a1, a2, a3, a4)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a1, a2, a3, a4 or 0, 0, 0) end)
    if not ok then return "PCALL-FAIL" end
    return to_num(rv)
end

local BUF = memory.alloc(0x400)
local N   = 0x400

local function clear()
    for off = 0, 0x3FC, 4 do safe_wd(BUF + off, 0) end
end
local function dump(tag)
    local nz = {}
    for off = 0, 0x3FC, 4 do
        local v = safe_rd(BUF + off)
        if v and v ~= 0 then
            nz[#nz + 1] = string.format("%03X=%08X", off, v)
            if #nz >= 24 then break end
        end
    end
    if #nz == 0 then
        print("    " .. tag .. " buffer all zero")
    else
        print("    " .. tag .. " " .. table.concat(nz, " "))
    end
end

print("[0] pid=" .. call(20, 0, 0, 0, 0) .. " bufp=" .. string.format("%X", to_num(BUF)))
print("")

-- 642 get_map_statistics
clear()
print("[A] 642(buf, 0x400)      map statistics")
print("    -> " .. tostring(call(642, BUF, N, 0, 0)))
dump("A")

clear()
print("[B] 642(buf, 0x400, 0)   map statistics, selector 0")
print("    -> " .. tostring(call(642, BUF, N, 0, 0)))
dump("B")
print("")

-- 646 get_kernel_mem_statistics
clear()
print("[C] 646(buf, 0x400)      kernel memory statistics")
print("    -> " .. tostring(call(646, BUF, N, 0, 0)))
dump("C")

clear()
print("[D] 646(0, buf, 0x400)   kernel mem stats, buffer second")
print("    -> " .. tostring(call(646, 0, BUF, N, 0)))
dump("D")
print("")

-- 641 get_cpu_usage_proc
print("[E] 641(pid, 0)          cpu usage")
print("    -> " .. tostring(call(641, call(20, 0, 0, 0, 0), 0, 0, 0)))

clear()
print("[F] 641(pid, buf)        cpu usage into buffer")
print("    -> " .. tostring(call(641, call(20, 0, 0, 0, 0), BUF, 0, 0)))
dump("F")

print("")
print("=== COMPLETE ===")
