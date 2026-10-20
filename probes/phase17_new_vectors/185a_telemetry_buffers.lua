-- CRASH_CLASS: LOW
-- PROBE 185a: the statistics family with a real output buffer
--
-- Context: 611, 613, 615, 618, 627, 641, 642, 646 all returned -1 to six zero
-- arguments in the 601-660 sweep. That is what a call that wants a buffer looks
-- like, and no earlier probe ever handed one over in more than one layout. Each is
-- tried with (pid, buf, size), (buf, size, 0), (buf, 0, 0) and (pid, size, buf) on
-- a canary page; the probe prints how many dwords changed and flags anything whose
-- high half looks like a kernel pointer (>= 0xFFFF8000), which is the only thing in
-- this family worth having.

print("=== PROBE 185a: STATISTICS CALLS WITH OUTPUT BUFFERS ===")
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
local function u64(v)
    return uint64(string.format("0x%08X", v))
end
local function hi_lo(v)
    local ok, s = pcall(function() return tostring(v) end)
    if not ok then return 0, 0 end
    local h = s:gsub("^0x", "")
    h = string.rep("0", 16 - #h) .. h
    return tonumber(h:sub(1, 8), 16) or 0, tonumber(h:sub(9, 16), 16) or 0
end
local zero = u64(0)

local sc20 = make_syscall(20)
local pid = to_num(sc20())

local buf = memory.alloc(0x8000)
local CANARY = 0xC1C1C1C1
local function fill()
    for off = 0, 0x7FF8, 4 do
        pcall(function() memory.write_dword(buf + off, CANARY) end)
    end
end
local function scan()
    local changed, kernelish, first = 0, {}, {}
    for off = 0, 0x7FF8, 4 do
        local ok, v = pcall(function() return memory.read_dword(buf + off) end)
        if ok and to_num(v) ~= CANARY then
            changed = changed + 1
            if #first < 12 then
                first[#first + 1] = string.format("+0x%03X=0x%08X", off, to_num(v))
            end
            -- a qword whose high dword is in kernel range starts at an 8-aligned
            -- offset with this dword as the low half
            if off % 8 == 0 then
                local ok8, q = pcall(function() return memory.read_qword(buf + off) end)
                if ok8 then
                    local h = hi_lo(q)
                    if h >= 0xFFFF8000 then
                        kernelish[#kernelish + 1] = string.format("+0x%03X", off)
                    end
                end
            end
        end
    end
    return changed, first, kernelish
end

local names = {
    [611] = "get_paging_stats_of_all_threads",
    [613] = "get_resident_count",
    [615] = "get_resident_fmem_count",
    [618] = "get_paging_stats_of_all_objects",
    [627] = "get_cpu_usage_all",
    [641] = "get_cpu_usage_proc",
    [642] = "get_map_statistics",
    [646] = "get_kernel_mem_statistics",
}

local stats = { { "pid,buf,size", "pbs" }, { "buf,size,0", "bs0" },
                { "buf,0,0", "b00" }, { "pid,size,buf", "psb" } }

print(string.format("[0] pid=%d buf=0x%X", pid, to_num(buf)))
print("")

for _, num in ipairs({ 611, 613, 615, 618, 627, 641, 642, 646 }) do
    local sc = make_syscall(num)
    print(string.format("[*] sys %d %s", num, names[num]))
    for _, layout in ipairs(stats) do
        local kind = layout[2]
        local a1, a2, a3
        if kind == "pbs" then a1, a2, a3 = u64(pid), buf, u64(0x8000)
        elseif kind == "bs0" then a1, a2, a3 = buf, u64(0x8000), zero
        elseif kind == "b00" then a1, a2, a3 = buf, zero, zero
        else a1, a2, a3 = u64(pid), u64(0x8000), buf end
        fill()
        local ok, ret = pcall(function() return sc(a1, a2, a3, zero, zero, zero) end)
        if not ok then
            print("    " .. layout[1] .. " -> KILLED")
            break
        end
        local changed, first, kernelish = scan()
        print(string.format("    %-12s -> %s changed=%d %s%s",
            layout[1], tostring(ret), changed,
            table.concat(first, " "),
            #kernelish > 0 and (" KERNEL-SHAPED:" .. table.concat(kernelish, ",")) or ""))
    end
    print("")
end

print("[*] done")
