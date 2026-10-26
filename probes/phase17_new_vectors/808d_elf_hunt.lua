-- CRASH_CLASS: HIGH
-- PROBE 808d: find the ELF magic and identify the image in the low physical cluster
print("=== PROBE 808d: ELF HUNT IN THE LOW CLUSTER ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end
    return nil
end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)
pcall(function() return getpid() end)
local s = "/dev/dmem0"
local cpath = memory.alloc(32)
for i = 1, #s do pcall(function() memory.write_byte(cpath + i - 1, s:byte(i)) end) end
pcall(function() memory.write_byte(cpath + #s, 0) end)
local fd = to_num(select(2, pcall(function() return sc_open(uint64(cpath), uint64(2), uint64(0)) end)))
print("[0] fd=" .. fd)
local VA = 0x880000000
local function map_page(phys)
    pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end)
    local ok, r = pcall(function()
        return sc_mmap(uint64(VA), uint64(0x4000), uint64(0x33), uint64(0x11),
            uint64(fd), u64(math.floor(phys / 4294967296), phys % 4294967296))
    end)
    if not ok then return false end
    return to_num(r) == VA
end
local function unmap() pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end) end

print("")
print("[1] ELF magic anywhere in [0x10000000,0x2000000)")
local found = {}
local p = 0x1000000
while p < 0x2000000 do
    if map_page(p) then
        for off = 0, 0x3FF0, 4 do
            local v = rd(VA + off)
            if v == 0x464C457F then
                found[#found + 1] = p + off
            end
        end
        unmap()
    end
    p = p + 0x4000
end
print("  hits: " .. #found)
for i = 1, math.min(#found, 10) do
    local phys = found[i]
    print(string.format("   ELF at %X", phys))
    if map_page(phys - (phys % 0x4000)) then
        local base = phys - (phys % 0x4000)
        local off = phys - base
        local t = {}
        for k = 0, 31 do
            local b = rb(VA + off + k)
            t[#t + 1] = string.format("%02X", b or 0)
        end
        print("     " .. table.concat(t, " "))
        unmap()
    end
end
print("")
print("[2] ASCII search for kernel markers in the same window")
local pats = {"FreeBSD", "r230171", "kernel", "Sony"}
local p2 = 0x1000000
local done = 0
while p2 < 0x3000000 and done < 1 do
    if map_page(p2) then
        for off = 0, 0x3F00, 0x10 do
            local b0, b1 = rb(VA + off), rb(VA + off + 1)
            if b0 and b1 then
                if b0 == 70 and b1 == 114 then
                    local str = ""
                    for k = 0, 15 do
                        local c = rb(VA + off + k)
                        if not c or c == 0 then break end
                        if c >= 32 and c < 127 then str = str .. string.char(c) else break end
                    end
                    if #str >= 5 then print(string.format("   %X: %s", p2 + off, str)) end
                end
            end
        end
        unmap()
    end
    p2 = p2 + 0x4000
end
print("")
print("[3] alive pid=" .. to_num(getpid()))
