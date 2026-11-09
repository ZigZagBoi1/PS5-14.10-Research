-- CRASH_CLASS: LOW
-- PROBE 58c: msync(MS_INVALIDATE) on every mappable /dev node

print("=== PROBE 58c: MSYNC DEVICE SCAN ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

local sc_open   = make_syscall(5)
local sc_close  = make_syscall(6)
local sc_mmap   = make_syscall(477)
local sc_msync  = make_syscall(65)
local sc_munmap = make_syscall(73)

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local path_buf = memory.alloc(64)
local PAGE = 0x4000

local devices = {
    "/dev/gc", "/dev/dce", "/dev/ajm",
    "/dev/dmem0", "/dev/dmem1",
    "/dev/camera", "/dev/rng", "/dev/gic",
    "/dev/notification0", "/dev/notification1",
    "/dev/usb", "/dev/hid", "/dev/bt"
}

for _, devpath in ipairs(devices) do
    for i = 1, #devpath do
        memory.write_byte(path_buf + i - 1, string.byte(devpath, i))
    end
    memory.write_byte(path_buf + #devpath, 0)

    -- Try O_RDWR=2, then O_RDONLY=0
    local fdv = -1
    for _, mode in ipairs({2, 0}) do
        if fdv >= 0 then break end
        local ok_o, dfd = pcall(function()
            return sc_open(uint64(path_buf), uint64(mode), uint64(0))
        end)
        if ok_o then fdv = to_num(dfd) end
    end

    if fdv < 0 then
        print(devpath .. ": OPEN_FAIL")
    else
        -- Try mmap with multiple prot/flag combinations
        local mapped = false
        local dmap = nil
        local combos = {
            {1, 0x0001},   -- PROT_READ, MAP_SHARED
            {3, 0x0001},   -- PROT_READ|WRITE, MAP_SHARED
            {1, 0x0002},   -- PROT_READ, MAP_PRIVATE
            {0x33, 0x0001}, -- GPU flags, MAP_SHARED
        }
        for _, c in ipairs(combos) do
            if mapped then break end
            local ok_m, mret = pcall(function()
                return sc_mmap(uint64(0), uint64(PAGE), uint64(c[1]),
                    uint64(c[2]), uint64(fdv), uint64(0))
            end)
            if ok_m then
                local mh, ml = get_hi_lo(mret)
                if mh ~= 0 or ml ~= 0 then
                    dmap = mret
                    mapped = true
                end
            end
        end

        if not mapped then
            print(devpath .. ": fd=" .. fdv .. " MMAP_FAIL")
        else
            local mh, ml = get_hi_lo(dmap)

            -- MS_INVALIDATE = 2
            local ok_inv, ret_inv = pcall(function()
                return sc_msync(uint64(dmap), uint64(PAGE), uint64(2))
            end)
            local inv_r = ok_inv and to_num(ret_inv) or -999

            -- MS_SYNC = 0
            local ok_sync, ret_sync = pcall(function()
                return sc_msync(uint64(dmap), uint64(PAGE), uint64(0))
            end)
            local sync_r = ok_sync and to_num(ret_sync) or -999

            -- MS_ASYNC = 1
            local ok_async, ret_async = pcall(function()
                return sc_msync(uint64(dmap), uint64(PAGE), uint64(1))
            end)
            local async_r = ok_async and to_num(ret_async) or -999

            -- MS_INVALIDATE|MS_SYNC = 2
            -- MS_INVALIDATE|MS_ASYNC = 3
            local ok_inv_a, ret_inv_a = pcall(function()
                return sc_msync(uint64(dmap), uint64(PAGE), uint64(3))
            end)
            local inv_a_r = ok_inv_a and to_num(ret_inv_a) or -999

            print(string.format("%s: fd=%d map=0x%X%08X inv=%d sync=%d async=%d inv+a=%d",
                devpath, fdv, mh, ml, inv_r, sync_r, async_r, inv_a_r))

            if inv_r == 0 then
                print("  *** MS_INVALIDATE SUCCEEDED ***")
            end

            pcall(function() sc_munmap(uint64(dmap), uint64(PAGE)) end)
        end

        pcall(function() sc_close(uint64(fdv)) end)
    end
end

-- Also test on a regular pipe fd (socketpair)
print("")
print("--- SOCKETPAIR MSYNC ---")
local sp_buf = memory.alloc(16)
local ok_sp, sp_ret = pcall(function()
    return make_syscall(135)(uint64(1), uint64(1), uint64(0), uint64(sp_buf))
end)
if ok_sp and to_num(sp_ret) == 0 then
    print("socketpair ok")
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
