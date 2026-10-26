-- CRASH_CLASS: HIGH
-- PROBE 808e: printable strings and ELF magic inside the seven mapped low pages
print("=== PROBE 808e: LOW CLUSTER TEXT ===")
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
local PAGES = {0x1000000, 0x10014000, 0x10018000, 0x1001C000, 0x10020000, 0x10024000, 0x10028000, 0x10D80000, 0x11600000}
print("")
for _, phys in ipairs(PAGES) do
    if map_page(phys) then
        local elf = nil
        local runs = {}
        local cur, curstart = "", 0
        for off = 0, 0xFFF do
            local b = rb(VA + off)
            if b == nil then break end
            if off <= 0xFFC and not elf then
                local v = rd(VA + off)
                if v == 0x464C457F then elf = off end
            end
            if b >= 32 and b < 127 then
                if #cur == 0 then curstart = off end
                cur = cur .. string.char(b)
            else
                if #cur >= 6 then runs[#runs + 1] = string.format("%03X:%s", curstart, cur) end
                cur = ""
            end
        end
        if #cur >= 6 then runs[#runs + 1] = string.format("%03X:%s", curstart, cur) end
        print(string.format("  %08X elf=%s strings=%d", phys, elf and string.format("%X", elf) or "none", #runs))
        for i = 1, math.min(#runs, 6) do print("     " .. runs[i]) end
        unmap()
    else
        print(string.format("  %08X map-fail", phys))
    end
end
print("")
print("[2] alive pid=" .. to_num(getpid()))
