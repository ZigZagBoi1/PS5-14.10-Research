-- CRASH_CLASS: MODERATE
-- PROBE 271d: ioctl 3-direction group sweep on all openable devices
--
-- 271c only tried _IOW (0x80000000). gc's data commands are _IOR (0x40000000).
-- This probe sweeps all 3 directions × 256 groups on each device.
-- For any (device, direction, group) that responds, it tries a larger buffer
-- and scans for kernel pointers.

print("=== PROBE 271d: 3-direction ioctl sweep ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local SENTINEL = 0xCAFEBABE
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

local function path_buf(p)
    local b = memory.alloc(0x100)
    for i = 0, 0xFC, 4 do wd(N(b) + i, 0) end
    for i = 0, #p - 1, 4 do
        local d = 0
        for j = 0, 3 do
            if i + j < #p then d = d + string.byte(p, i + j + 1) * (256 ^ j) end
        end
        wd(N(b) + i, d)
    end
    return b
end

local sc5 = mk(5)
local sc6 = mk(6)
local sc_ioctl = mk(54)

local nodes = {
    "gc", "dce", "dmem0", "dmem1", "camera",
    "hid", "bt", "rng", "gic",
    "notification0", "notification1", "notification2",
    "notification3", "notification4", "notification5",
    "ajm", "usb",
}

print("[A] open")
local fds = {}
for _, nm in ipairs(nodes) do
    local ok1, rv = pcall(function() return sc5(path_buf("/dev/" .. nm), uint64(2)) end)
    local fd = ok1 and N(rv) or -1
    if fd >= 0 and fd < 0x10000 then
        fds[#fds + 1] = {nm, fd}
    end
end
print("  opened " .. #fds .. "/" .. #nodes)

local buf = memory.alloc(0x200)
local ba = N(buf)

-- Direction names and bits
-- _IOR = 0x40000000 (OUT: kernel writes to user buffer)
-- _IOW = 0x80000000 (IN: user writes to kernel)
-- _IOWR = 0xC0000000 (both)
local dirs = {
    {0x40000000, "IOR"},   -- kernel → user (DATA OUT)
    {0x80000000, "IOW"},   -- user → kernel
    {0xC0000000, "IOWR"},  -- both
}

print("")
print("[B] 3-direction sweep: 4B buffer, cmd=0x01")

local discoveries = {}

for fi = 1, #fds do
    if not alive() then print("DEAD"); break end
    local nm, fd = fds[fi][1], fds[fi][2]
    local dev_hits = {}

    for _, dp in ipairs(dirs) do
        local dir_bits, dir_name = dp[1], dp[2]

        for g = 0, 255 do
            -- code = dir | (size=4 << 16) | (group << 8) | cmd=1
            local code = dir_bits + 0x00040000 + g * 0x100 + 0x01
            for off = 0, 0x1FC, 4 do wd(ba + off, SENTINEL) end

            local ok, rv = pcall(function()
                return sc_ioctl(uint64(fd), uint64(code), uint64(ba))
            end)
            if not ok then
                if not alive() then
                    print(string.format("  %s KILLED dir=%s g=0x%02X", nm, dir_name, g))
                    break
                end
            else
                local r = N(rv)
                if r ~= -1 then
                    dev_hits[#dev_hits + 1] = {dir_name, g, r, code}
                end
            end
        end
        if not alive() then break end
    end

    -- Report
    if #dev_hits == 0 then
        print(string.format("  %-16s nothing", nm))
    elseif #dev_hits > 200 then
        print(string.format("  %-16s catch-all (%d hits)", nm, #dev_hits))
    else
        for _, h in ipairs(dev_hits) do
            local uv = h[3]; if uv < 0 then uv = uv + 0x100000000 end
            print(string.format("  %-16s %s g=0x%02X ret=0x%X",
                nm, h[1], h[2], uv))
        end
        -- Save for deep probe
        for _, h in ipairs(dev_hits) do
            discoveries[#discoveries + 1] = {nm, fd, h[1], h[2], h[3], h[4]}
        end
    end
end

if not alive() then print("DEAD after sweep"); return end

-- [C] Deep probe: for each discovery, try 256B OUT buffer with sentinel
print("")
print("[C] deep scan discoveries (256B sentinel buffer)")

for _, d in ipairs(discoveries) do
    if not alive() then print("DEAD"); break end
    local nm, fd, dir_name, g, ret_small, small_code = d[1], d[2], d[3], d[4], d[5], d[6]

    -- Build a 256-byte version of the same (dir, group, cmd)
    local dir_bits
    if dir_name == "IOR" then dir_bits = 0x40000000
    elseif dir_name == "IOW" then dir_bits = 0x80000000
    else dir_bits = 0xC0000000 end

    local big_code = dir_bits + 0x01000000 + g * 0x100 + 0x01  -- size=0x100=256

    for off = 0, 0x1FC, 4 do wd(ba + off, SENTINEL) end

    local ok, rv = pcall(function()
        return sc_ioctl(uint64(fd), uint64(big_code), uint64(ba))
    end)
    if not ok then
        if not alive() then
            print(string.format("  %s g=0x%02X KILLED on big", nm, g))
            break
        end
    else
        local r = N(rv)
        if r ~= -1 then
            -- Count modified dwords
            local modified = 0
            local first_mod, last_mod = nil, nil
            for off = 0, 0x1FC, 4 do
                local v = rd(ba + off)
                if v ~= SENTINEL then
                    modified = modified + 1
                    if not first_mod then first_mod = off end
                    last_mod = off
                end
            end
            if modified > 0 then
                local uv = r; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("  %s %s g=0x%02X ret=0x%X: %d dwords, +0x%X..+0x%X",
                    nm, dir_name, g, uv, modified, first_mod, last_mod))

                -- Kernel pointer scan
                for off = 0, (last_mod or 0) + 4, 4 do
                    local lo = rd(ba + off) or SENTINEL
                    local hi = rd(ba + off + 4) or SENTINEL
                    if lo ~= SENTINEL and hi ~= SENTINEL then
                        local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
                        local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                        if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                            print(string.format("    *** KPTR %s g=0x%02X +0x%X: 0x%08X%08X ***",
                                nm, g, off, uhi, ulo))
                        end
                    end
                end

                -- Dump first 64B of modified data
                if modified <= 32 then
                    for off = first_mod, math.min(last_mod, first_mod + 60), 4 do
                        local v = rd(ba + off)
                        if v and v ~= SENTINEL then
                            local uv2 = v; if uv2 < 0 then uv2 = uv2 + 0x100000000 end
                            print(string.format("    +0x%02X: 0x%08X", off, uv2))
                        end
                    end
                end
            end
        end
    end
end

-- Cleanup
for fi = 1, #fds do
    pcall(function() sc6(uint64(fds[fi][2])) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271d COMPLETE ===")
