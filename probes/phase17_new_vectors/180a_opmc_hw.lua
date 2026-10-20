-- CRASH_CLASS: LOW
-- PROBE 180a: sys 625 opmc_set_hw / 626 opmc_get_hw with the opmc family's own shape
--
-- Context: 177b-177d showed 563-567 accept arg1=0 and an arg2 of 0..4, and reject
-- everything else. The _hw pair is the MSR side of opmc, and every earlier attempt
-- at 625/626 used invented indices for an RDMSR model. This walks the same shape
-- the sibling calls accept, plus a valid output page, and prints whatever comes
-- back inline (a get_hw that succeeds may return the value as the syscall result).

print("=== PROBE 180a: SYS 625/626 opmc_set_hw / opmc_get_hw ===")
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

local buf = memory.alloc(0x4000)
for off = 0, 0x3FF8, 8 do
    pcall(function() memory.write_qword(buf + off, u64(0xA5A5A5A5)) end)
end

local function canary_changed()
    local hits = 0
    for off = 0, 0x3FF8, 8 do
        local ok, v = pcall(function() return memory.read_qword(buf + off) end)
        if ok and to_num(v) ~= 0xA5A5A5A5 then hits = hits + 1 end
    end
    return hits
end

local zero = u64(0)

local function run(num, a1, a2, usebuf)
    local sc = make_syscall(num)
    local a3 = zero
    if usebuf then a3 = buf end
    local ok, ret = pcall(function() return sc(a1, a2, a3, zero, zero, zero) end)
    local label = string.format("sys %d arg1=0x%X arg2=0x%X %s",
        num, to_num(a1), to_num(a2), usebuf and "buf" or "nobuf")
    if not ok then
        print("[!] " .. label .. " -> pcall failed")
        return
    end
    print(string.format("[*] %s -> ret=0x%016X changed=%d", label, to_num(ret), canary_changed()))
end

print("[0] buf=" .. tostring(buf))
print("")

for _, num in ipairs({ 626, 625 }) do
    for a1 in ipairs({ 0, 1, 0x10 }) do
        local v1 = u64(a1 - 1 == 0 and 0 or ({ 0, 1, 0x10 })[a1])
        for _, a2 in ipairs({ 0, 1, 2, 3, 4 }) do
            run(num, v1, u64(a2))
        end
    end
end

print("")
print("[*] with an output page in arg3")
for _, num in ipairs({ 626, 625 }) do
    for _, a2 in ipairs({ 0, 1, 2, 3, 4, 8, 0xFFFFFFFF }) do
        run(num, zero, u64(a2), true)
    end
end

print("")
print("[*] done")
