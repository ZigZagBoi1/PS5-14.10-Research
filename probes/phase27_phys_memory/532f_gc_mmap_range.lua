-- CRASH_CLASS: MODERATE
-- PROBE 532f: mmap via /dev/gc and other device fds
--
-- dmem0-2 only reach GPU memory (phys 0x100000000-0x200000000).
-- The kernel is in system RAM (phys < 0x100000000?).
--
-- Test: mmap with different device fds — /dev/gc, /dev/dce, /dev/zero, etc.
-- Some drivers might map different physical regions.
-- Also test: does mmap_dmem(628) with varied descriptors do anything different?

print("=== PROBE 532f: GC/DEVICE MMAP RANGE ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(b, n) for off = 0, n-4, 4 do wd(b+off, 0) end end

local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)

-- Helper: open a device by path string
local devpath = memory.alloc(64)
local function open_dev(path)
    zero(devpath, 64)
    for ci = 1, #path do
        local byte_val = string.byte(path, ci)
        local off = ci - 1
        local dw_off = math.floor(off / 4) * 4
        local byte_pos = off % 4
        local cur = rd(to_num(devpath) + dw_off) or 0
        if cur < 0 then cur = cur + 0x100000000 end
        cur = cur + byte_val * (256 ^ byte_pos)
        wd(devpath + dw_off, cur)
    end
    local ok_o, fd = pcall(function()
        return sc_open(uint64(devpath), uint64(0x10002), uint64(0))
    end)
    if not ok_o then return nil end
    local fdn = to_num(fd)
    if fdn < 0 then fdn = fdn + 0x100000000 end
    if fdn >= 0xFFFF0000 then return nil end
    return fd, fdn
end

-- Helper: try mmap with device fd
local function try_dev_mmap(fd, offset, prot, flags)
    prot = prot or uint64(3)    -- RW
    flags = flags or uint64(1)  -- MAP_SHARED
    local ok_m, va = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), prot, flags, fd, offset)
    end)
    if not ok_m then return nil end
    local vah = 0
    if type(va) == "table" and va.h then vah = va.h; if vah < 0 then vah = vah + 0x100000000 end end
    if vah == 0xFFFFFFFF then return nil end
    local van = to_num(va); if van < 0 then van = van + 0x100000000 end
    if van == 0 then return nil end
    return va, van
end

-- [1] Open devices
print("[1] Open devices")
local devices = {
    "/dev/gc", "/dev/dce", "/dev/ajm",
    "/dev/dmem0", "/dev/dmem1",
    "/dev/zero", "/dev/rng", "/dev/camera",
}
local fds = {}
for _, path in ipairs(devices) do
    local fd, fdn = open_dev(path)
    if fd then
        print(string.format("  %-16s fd=%d", path, fdn))
        fds[path] = fd
    else
        print(string.format("  %-16s OPEN_FAIL", path))
    end
end

-- [2] Try mmap on each device with various offsets
print("")
print("[2] mmap tests per device")
local offsets = {
    uint64(0),
    uint64(0x1000),
    uint64(0x10000),
    uint64(0x100000),
}

for _, path in ipairs(devices) do
    local fd = fds[path]
    if fd then
        print(string.format("  %s:", path))
        for _, off in ipairs(offsets) do
            local va, van = try_dev_mmap(fd, off)
            if va then
                local d = rd(van)
                local ds = d and string.format("0x%08X", d < 0 and d + 0x100000000 or d) or "FAULT"
                print(string.format("    off=%s → %s first=%s", q(off), q(va), ds))
                pcall(function() sc_munmap(va, uint64(0x4000)) end)
            else
                print(string.format("    off=%s → FAIL", q(off)))
            end
        end
    end
end

-- [3] Try mmap with /dev/gc using different flag combos
-- /dev/gc is the GPU controller — it might allow MMIO mapping
print("")
print("[3] /dev/gc special mmap tests")
local gc_fd = fds["/dev/gc"]
if gc_fd then
    -- MAP_SHARED=1, MAP_PRIVATE=2, MAP_FIXED=0x10
    -- Also try: prot=5 (RX), prot=1 (R)
    local gc_tests = {
        { prot = 1, flags = 1, name = "R+SHARED" },
        { prot = 3, flags = 1, name = "RW+SHARED" },
        { prot = 3, flags = 2, name = "RW+PRIVATE" },
        { prot = 1, flags = 2, name = "R+PRIVATE" },
    }
    for _, t in ipairs(gc_tests) do
        local va, van = try_dev_mmap(gc_fd, uint64(0), uint64(t.prot), uint64(t.flags))
        if va then
            local d = rd(van)
            local ds = d and string.format("0x%08X", d < 0 and d + 0x100000000 or d) or "FAULT"
            print(string.format("  %-14s → %s first=%s", t.name, q(va), ds))
            pcall(function() sc_munmap(va, uint64(0x4000)) end)
        else
            print(string.format("  %-14s → FAIL", t.name))
        end
    end
end

-- [4] Try mmap_dmem(628) syscall directly
-- mmap_dmem was documented as: addr, len, prot, flags, offset, align
-- where descriptor=-1 "bypasses device lookup"
print("")
print("[4] mmap_dmem(628) tests")
local sc_mmap_dmem = make_syscall(628)
local mmdm_tests = {
    { desc = -1, off = 0,          name = "desc=-1 off=0" },
    { desc = -1, off = 0x10010000, name = "desc=-1 off=alloc" },
    { desc = 0,  off = 0,          name = "desc=0 off=0" },
    { desc = 0,  off = 0x10010000, name = "desc=0 off=alloc" },
}
for _, t in ipairs(mmdm_tests) do
    local ok_m, rv = pcall(function()
        return sc_mmap_dmem(
            uint64(0),          -- addr
            uint64(0x4000),     -- len
            uint64(3),          -- prot
            uint64(0x40),       -- flags (0x40 from dossier)
            uint64(t.off),      -- offset
            uint64(0x4000)      -- align
        )
    end)
    if ok_m then
        print(string.format("  %-24s → %s", t.name, q(rv)))
    else
        print(string.format("  %-24s → PCALL_FAIL", t.name))
    end
end

print("")
print("=== 532f DONE ===")
