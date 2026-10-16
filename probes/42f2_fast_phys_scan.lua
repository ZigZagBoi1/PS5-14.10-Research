-- CRASH_CLASS: SAFE (read-only mmap of physical memory)
-- PROBE 42f2: fast physical memory survey via /dev/dmem0
--
-- 42f timed out doing deep scans. This version ONLY does step 1:
-- mmap 1 page at each offset, read first 2 qwords, check for ELF/FreeBSD, unmap.
-- No string searches, no kernel pointer scans.

print("=== PROBE 42f2: FAST PHYSICAL MEMORY SURVEY ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function qw_hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%X%08X", v.h, v.l), v.h, v.l
    end
    local n = to_num(v)
    return string.format("0x%X", n), 0, n
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)

local function dev_open(path)
    local name_buf = memory.alloc(256)
    for i = 1, #path do
        pcall(function() memory.write_byte(name_buf + i - 1, string.byte(path, i)) end)
    end
    pcall(function() memory.write_byte(name_buf + #path, 0) end)
    local fd = nil
    pcall(function() fd = sc_open(name_buf, uint64(2), uint64(0)) end)
    return fd and to_num(fd) or -1
end

local dmem_fd = dev_open("/dev/dmem0")
print("dmem0 fd: " .. dmem_fd)
if dmem_fd < 0 then print("FAILED"); return end

local PAGE = 0x4000
local MB = 0x100000

-- Build offset list: focus on likely kernel addresses
local offsets = {}
-- 0 to 4MB in 256KB steps
for i = 0, 15 do offsets[#offsets + 1] = i * 256 * 1024 end
-- 4MB to 64MB in 2MB steps
for i = 2, 32 do offsets[#offsets + 1] = i * 2 * MB end
-- 64MB to 512MB in 16MB steps
for i = 4, 32 do offsets[#offsets + 1] = i * 16 * MB end
-- 512MB to 4GB in 256MB steps
for i = 2, 15 do offsets[#offsets + 1] = i * 256 * MB end

print("scanning " .. #offsets .. " offsets...")
print("")

local hits = 0

for _, phys_off in ipairs(offsets) do
    local off_hi = math.floor(phys_off / 0x100000000)
    local off_lo = phys_off % 0x100000000
    local off_u64 = uint64(string.format("0x%X%08X", off_hi, off_lo))

    local addr = nil
    local ok = pcall(function()
        addr = sc_mmap(uint64(0), uint64(PAGE), uint64(1),
            uint64(1), uint64(dmem_fd), off_u64)
    end)

    if ok and addr then
        local _, ah, al = qw_hex(addr)
        if not (ah == 0xFFFFFFFF and al == 0xFFFFFFFF) then
            local d0 = safe_rd(addr)
            local d4 = safe_rd(addr + 4)

            if d0 ~= nil and (d0 ~= 0 or (d4 and d4 ~= 0)) then
                hits = hits + 1
                local tag = ""
                if d0 == 0x464C457F then tag = " *** ELF ***" end

                print(string.format("0x%X%08X: %08X_%08X%s",
                    off_hi, off_lo, d4 or 0, d0, tag))

                -- If ELF found, dump header
                if d0 == 0x464C457F then
                    for off = 8, 0x38, 8 do
                        local q = safe_rq(addr + off)
                        if q then
                            print(string.format("  +0x%02X: %s", off, qw_hex(q)))
                        end
                    end
                end
            end

            pcall(function() sc_munmap(addr, uint64(PAGE)) end)
        end
    end
end

print("")
print("non-zero: " .. hits)

pcall(function() sc_close(uint64(dmem_fd)) end)
print("=== PROBE 42f2 COMPLETE ===")
