-- CRASH_CLASS: MODERATE
-- PROBE 199a: 619 test_debug_rwmem and the statistics calls
--
-- Context: the 601-660 sweep killed 609, 614, 621, 622, 631, 650 and 651 and
-- returned for the rest. 619 is named test_debug_rwmem in the 13.60 capture.
-- The bounds fuzz pass gave it a buffer and a size in three layouts and it
-- wrote nothing, but a debug copy call takes a source, a destination and a
-- length, which none of those layouts supplied.
--
-- Section A hands 619 a filled source page and an untouched destination page in
-- eight orders, and reports whether the destination received a copy. Section B
-- asks the statistics calls for their record with a canary buffer and reports
-- writes and any kernel-shaped qword, because a statistics record is exactly
-- the kind of structure that carries a kernel base on other platforms.

print("=== PROBE 199a: 619 rwmem and statistics ===")
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
    if type(v) == "number" then return uint64(string.format("0x%08X", v)) end
    return v
end
local function show(v)
    if v == nil then return "killed" end
    return tostring(v)
end
local dead = false

local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(u64(a1 or 0), u64(a2 or 0), u64(a3 or 0), u64(a4 or 0), u64(a5 or 0), u64(a6 or 0))
    end)
    if not ok then
        dead = true
        return nil, nil
    end
    return ret, to_num(ret)
end

local SRC = memory.alloc(0x100)
local DST = memory.alloc(0x100)

local function fill(addr, n, byte)
    for off = 0, n - 4, 4 do
        pcall(function() memory.write_dword(addr + off, u64(byte)) end)
    end
end
local function scan_record(addr, n, canary)
    local changed, hits, first = 0, 0, nil
    local hex = {}
    for off = 0, n - 4, 4 do
        local ok, v = pcall(function() return memory.read_dword(addr + off) end)
        local val = ok and to_num(v) or 0
        if off < 32 then hex[#hex + 1] = string.format("%08X", val) end
        if val ~= canary then changed = changed + 1 end
    end
    for off = 0, n - 8, 8 do
        local ok, v = pcall(function() return memory.read_qword(addr + off) end)
        if ok then
            local hi, lo = 0, 0
            if type(v) == "table" and v.h then hi, lo = v.h, v.l else lo = to_num(v) end
            if hi >= 0xFFFF8000 and hi ~= 0xFFFFFFFF then
                hits = hits + 1
                if first == nil then first = string.format("%X:%08X%08X", off, hi, lo) end
            end
        end
    end
    return changed, hits, first, table.concat(hex, " ")
end

local _, pid = call(20)
print("[0] getpid " .. show(pid) .. " src=" .. show(to_num(SRC)) .. " dst=" .. show(to_num(DST)))
print("")

local SRC_A = to_num(SRC)
local DST_A = to_num(DST)

print("[A] 619 with a filled source and an untouched destination")
local shapes = {
    { "src,dst,len",      SRC_A, DST_A, 0x40 },
    { "dst,src,len",      DST_A, SRC_A, 0x40 },
    { "src,len,dst",      SRC_A, 0x40, DST_A },
    { "len,src,dst",      0x40, SRC_A, DST_A },
    { "0,src,dst,len",    0, SRC_A, DST_A, 0x40 },
    { "1,src,dst,len",    1, SRC_A, DST_A, 0x40 },
    { "src,0x40,0,dst",   SRC_A, 0x40, 0, DST_A },
    { "src,dst,0x40,0",   SRC_A, DST_A, 0x40, 0 },
}
for _, s in ipairs(shapes) do
    if dead then break end
    fill(SRC, 0x100, 0x41414141)
    fill(DST, 0x100, 0x42424242)
    local _, rv = call(619, s[2], s[3], s[4], s[5])
    local copied = 0
    for off = 0, 0x80, 4 do
        local ok, v = pcall(function() return memory.read_dword(DST + off) end)
        if ok and to_num(v) == 0x41414141 then copied = copied + 1 end
    end
    print(string.format("    %-16s -> rev=%s copied=%d", s[1], show(rv), copied))
end
print("")

print("[B] statistics records")
local stats = { 611, 618, 642, 646 }
for _, num in ipairs(stats) do
    if dead then break end
    for _, layout in ipairs({ { "buf,size", DST_A, 0x100 }, { "size,buf", 0x100, DST_A }, { "buf", DST_A } }) do
        if dead then break end
        fill(DST, 0x100, 0x43434343)
        local _, rv = call(num, layout[2], layout[3])
        local changed, hits, first, hex = scan_record(DST, 0x100, 0x43434343)
        print(string.format("    %d %-9s -> rev=%s changed=%d kp=%d %s",
            num, layout[1], show(rv), changed, hits, first or ""))
        print("        " .. hex)
    end
end
print("")

print("=== PROBE 199a COMPLETE ===")
