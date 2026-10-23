-- CRASH_CLASS: MODERATE
-- PROBE 271e: gc group 0x81 cmd sweep + multi-device cmd sweep
--
-- 271d showed gc returns -1 for cmd=0x01 on all groups. But 56m found 25
-- commands in group 0x81. This means gc requires specific cmd bytes.
-- Part A: sweep cmd 0x00-0xFF on gc group 0x81, all 3 directions.
-- Part B: sweep cmd 0x00-0x20 on all devices for groups 0x80-0x90.
-- Part C: for each HIT, try 512B sentinel buffer and scan for kptrs.

print("=== PROBE 271e: gc cmd sweep + multi-device ===")
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

local SENTINEL = 0xABCD1234
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

-- Open devices
local targets = {"gc", "dce", "dmem0", "dmem1", "bt", "gic", "notification0", "rng"}
local fds = {}
for _, nm in ipairs(targets) do
    local ok1, rv = pcall(function() return sc5(path_buf("/dev/" .. nm), uint64(2)) end)
    local fd = ok1 and N(rv) or -1
    if fd >= 0 and fd < 0x10000 then fds[nm] = fd end
end
print("opened: " .. (function()
    local s = {}; for k, v in pairs(fds) do s[#s + 1] = k .. "=" .. v end
    return table.concat(s, ", ")
end)())

local buf = memory.alloc(0x400)
local ba = N(buf)
local function fill() for off = 0, 0x3FC, 4 do wd(ba + off, SENTINEL) end end

local dirs = {
    {0x40000000, "IOR"},
    {0x80000000, "IOW"},
    {0xC0000000, "IOWR"},
}

local discoveries = {}

-- [A] gc: sweep cmd 0x00-0xFF in group 0x81, all directions
print("")
print("[A] gc group 0x81: cmd 0x00-0xFF × 3 dirs")
local gc_fd = fds["gc"]
if gc_fd then
    for _, dp in ipairs(dirs) do
        if not alive() then break end
        local dir_bits, dir_name = dp[1], dp[2]
        local hits = {}
        for cmd = 0, 255 do
            -- size=4 for discovery
            local code = dir_bits + 0x00040000 + 0x8100 + cmd
            fill()
            local ok, rv = pcall(function()
                return sc_ioctl(uint64(gc_fd), uint64(code), uint64(ba))
            end)
            if ok then
                local r = N(rv)
                if r ~= -1 then
                    hits[#hits + 1] = cmd
                    discoveries[#discoveries + 1] = {gc_fd, "gc", dir_name, 0x81, cmd, r, code}
                end
            elseif not alive() then
                print("  KILLED at " .. dir_name .. " cmd=" .. cmd)
                break
            end
        end
        if #hits > 0 then
            local cs = {}
            for _, c in ipairs(hits) do cs[#cs + 1] = string.format("%02X", c) end
            print(string.format("  gc %s: %d hits: %s", dir_name, #hits, table.concat(cs, ",")))
        end
    end
else
    print("  gc not open")
end

-- [B] dce: sweep cmd 0x00-0xFF in groups 0x80-0x8F
print("")
print("[B] dce groups 0x80-0x8F: cmd 0x00-0xFF (IOR only)")
local dce_fd = fds["dce"]
if dce_fd and alive() then
    for g = 0x80, 0x8F do
        if not alive() then break end
        local hits = {}
        for cmd = 0, 255 do
            local code = 0x40040000 + g * 0x100 + cmd  -- IOR, size=4
            fill()
            local ok, rv = pcall(function()
                return sc_ioctl(uint64(dce_fd), uint64(code), uint64(ba))
            end)
            if ok then
                local r = N(rv)
                if r ~= -1 then
                    hits[#hits + 1] = cmd
                    discoveries[#discoveries + 1] = {dce_fd, "dce", "IOR", g, cmd, r, code}
                end
            elseif not alive() then
                print(string.format("  KILLED g=0x%02X cmd=%d", g, cmd))
                break
            end
        end
        if #hits > 0 then
            local cs = {}
            for _, c in ipairs(hits) do cs[#cs + 1] = string.format("%02X", c) end
            print(string.format("  dce IOR g=0x%02X: %d hits: %s", g, #hits, table.concat(cs, ",")))
        end
    end
end

-- [C] Other devices: groups 0x80-0x90, cmd 0x00-0x10, IOR+IOWR
print("")
print("[C] remaining devices: groups 0x80-0x90 × cmd 0x00-0x10")
local others = {"dmem0", "dmem1", "bt", "gic", "notification0", "rng"}
for _, nm in ipairs(others) do repeat
    if not alive() then break end
    local fd = fds[nm]
    if not fd then break end

    local dev_hits = 0
    for g = 0x80, 0x90 do
        for cmd = 0, 16 do
            for _, dp in ipairs(dirs) do
                local code = dp[1] + 0x00040000 + g * 0x100 + cmd
                fill()
                local ok, rv = pcall(function()
                    return sc_ioctl(uint64(fd), uint64(code), uint64(ba))
                end)
                if ok then
                    local r = N(rv)
                    if r ~= -1 then
                        dev_hits = dev_hits + 1
                        discoveries[#discoveries + 1] = {fd, nm, dp[2], g, cmd, r, code}
                        local uv = r; if uv < 0 then uv = uv + 0x100000000 end
                        print(string.format("  %s %s g=0x%02X cmd=0x%02X ret=0x%X",
                            nm, dp[2], g, cmd, uv))
                    end
                elseif not alive() then
                    print(string.format("  %s KILLED g=0x%02X cmd=%d", nm, g, cmd))
                    break
                end
            end
            if not alive() then break end
        end
        if not alive() then break end
    end
    if dev_hits == 0 then
        print(string.format("  %-16s nothing", nm))
    end
until true end

if not alive() then print("DEAD before deep scan"); return end

-- [D] Deep scan: 512B sentinel buffer for each discovery
print("")
print(string.format("[D] deep scan %d discoveries", #discoveries))

for _, d in ipairs(discoveries) do
    if not alive() then break end
    local fd, nm, dir_name, g, cmd, small_ret, small_code = d[1], d[2], d[3], d[4], d[5], d[6], d[7]

    local dir_bits
    if dir_name == "IOR" then dir_bits = 0x40000000
    elseif dir_name == "IOW" then dir_bits = 0x80000000
    else dir_bits = 0xC0000000 end

    -- 512-byte buffer
    local big_code = dir_bits + 0x02000000 + g * 0x100 + cmd  -- size=0x200
    fill()
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(fd), uint64(big_code), uint64(ba))
    end)
    if ok then
        local r = N(rv)
        if r ~= -1 then
            local modified = 0
            local first_mod, last_mod = nil, nil
            for off = 0, 0x3FC, 4 do
                local v = rd(ba + off)
                if v ~= SENTINEL then
                    modified = modified + 1
                    if not first_mod then first_mod = off end
                    last_mod = off
                end
            end
            if modified > 0 then
                local uv = r; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("  %s %s g=0x%02X cmd=0x%02X ret=0x%X: %d dw mod +0x%X..+0x%X",
                    nm, dir_name, g, cmd, uv, modified, first_mod, last_mod))

                -- kptr scan
                for off = 0, (last_mod or 0) + 4, 4 do
                    local lo = rd(ba + off) or SENTINEL
                    local hi = rd(ba + off + 4) or SENTINEL
                    if lo ~= SENTINEL and hi ~= SENTINEL then
                        local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
                        local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
                        if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                            print(string.format("    *** KPTR %s g=0x%02X cmd=0x%02X +0x%X: 0x%08X%08X ***",
                                nm, g, cmd, off, uhi, ulo))
                        end
                    end
                end

                -- Dump first 128B of data
                if modified <= 64 then
                    for off = first_mod, math.min(last_mod, first_mod + 124), 4 do
                        local v = rd(ba + off)
                        if v and v ~= SENTINEL then
                            local uv2 = v; if uv2 < 0 then uv2 = uv2 + 0x100000000 end
                            print(string.format("    +0x%02X: 0x%08X", off, uv2))
                        end
                    end
                end
            end
        end
    elseif not alive() then
        print(string.format("  %s KILLED on big g=0x%02X cmd=0x%02X", nm, g, cmd))
        break
    end
end

-- Cleanup
for _, fd in pairs(fds) do
    pcall(function() sc6(uint64(fd)) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271e COMPLETE ===")
