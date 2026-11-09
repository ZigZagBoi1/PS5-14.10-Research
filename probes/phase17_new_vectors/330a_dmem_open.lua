-- CRASH_CLASS: LOW
-- PROBE 330a: which of the direct-memory nodes open, and mmap_dmem through one
--
-- 329a saw /dev/dmem0 refuse both modes, but the node was never in the 298a
-- sweep table, so this is the first explicit measurement. If one of dmem0-2
-- opens, sys 628 is called with that descriptor and physical offsets.

print("=== PROBE 330a: DMEM NODES ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(v)
    local l = to_num(v)
    if l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end
local function ptr(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end

local sc_open = make_syscall(5)
local sc = make_syscall(628)

local PATHBUF = memory.alloc(0x100)
local function put_str(str)
    for i = 1, #str do
        pcall(function() memory.write_byte(PATHBUF + (i - 1), string.byte(str, i)) end)
    end
    pcall(function() memory.write_byte(PATHBUF + #str, 0) end)
    return PATHBUF
end
local function do_open(path, mode)
    local ok, rv = pcall(function()
        return sc_open(uint64(put_str(path)), uint64(mode), uint64(0))
    end)
    if not ok then return -1 end
    return sgn(lo_of(rv))
end

local NODES = { "dmem0", "dmem1", "dmem2", "dce", "gic", "gc", "zero" }
local opened = {}

for _, n in ipairs(NODES) do
    local r = do_open("/dev/" .. n, 0)
    local w = do_open("/dev/" .. n, 2)
    print(string.format("  %-8s O_RDONLY=%d O_RDWR=%d", n, r, w))
    if r > 0 then opened[n] = r end
    if w > 0 then opened[n] = w end
end

local fd = opened["dmem0"] or opened["dmem1"] or opened["dmem2"]
print("")
if not fd then
    print("[A] no direct-memory node opened; 628 cannot be given a descriptor")
    print("=== 330a DONE ===")
    return
end

print(string.format("[A] descriptor = %d", fd))

local function try(tag, off_lo)
    local ok, rv = pcall(function()
        return sc(ptr(0, 0), ptr(0, 0x4000), uint64(fd),
                  ptr(0, 3), ptr(0, 0), ptr(0, off_lo))
    end)
    if not ok then
        print(string.format("%s RAISED", tag))
        return
    end
    local lo, hi = lo_of(rv)
    print(string.format("%s off=0x%X ret=0x%08X%08X (%d)", tag, off_lo, hi, lo, sgn(lo)))
    if hi == 0 and lo >= 0x10000 and lo < 0x80000000 then
        local out = {}
        for i = 0, 7 do
            local v = safe_rd(ptr(0, lo) + i * 4)
            if v == nil then break end
            out[#out + 1] = string.format("%08X", v)
        end
        print(string.format("  page@0x%X: %s", lo, table.concat(out, " ")))
    end
end

try("[B] phys 0x0", 0)
try("[C] phys 0x100000", 0x100000)
try("[D] phys 0x1000000", 0x1000000)
try("[E] phys 0x10000000", 0x10000000)

print("")
print("=== 330a DONE ===")
