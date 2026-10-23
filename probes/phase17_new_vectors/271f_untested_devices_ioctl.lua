-- CRASH_CLASS: MODERATE
-- PROBE 271f: ioctl sweep on untested device nodes
--
-- 271a-271e covered gc, dce, dmem0-1, bt, gic, notification0, camera, hid.
-- This probe targets the UNTESTED nodes: HMD (8 nodes), ajm, ajmi, usbctl,
-- usb, ugen0.2, rng, random, urandom, deci_stdin, notification6, notification7.
-- For each, tries groups from 13.60 catalog + 0x80-0x90 with cmd 0x00-0x1F,
-- IOR + IOWR directions. Any non-(-1) return is deep-scanned for kptrs.

print("=== PROBE 271f: untested devices ioctl sweep ===")
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

local SENTINEL = 0xBEEFCAFE
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

local targets = {
    "hmd_cmd", "hmd_snsr", "hmd_3da", "hmd_dist",
    "hmd2_cmd", "hmd2_imu", "hmd2_leddet", "hmd2_gaze",
    "ajm", "ajmi", "usbctl", "usb",
    "rng", "random", "urandom",
    "notification6", "notification7",
    "deci_stdin",
}

print("[A] open devices")
local fds = {}
for _, nm in ipairs(targets) do
    local path = "/dev/" .. nm
    -- Try O_RDWR first, then O_RDONLY
    local ok1, rv = pcall(function() return sc5(path_buf(path), uint64(2)) end)
    local fd = ok1 and N(rv) or -1
    if fd < 0 or fd >= 0x10000 then
        ok1, rv = pcall(function() return sc5(path_buf(path), uint64(0)) end)
        fd = ok1 and N(rv) or -1
    end
    if fd >= 0 and fd < 0x10000 then
        fds[#fds + 1] = {nm, fd}
        print(string.format("  %-16s fd=%d", nm, fd))
    end
end
print(string.format("  opened %d/%d", #fds, #targets))
if #fds == 0 then print("ABORT: no devices opened"); return end

-- Groups to test: 13.60 catalog groups + Sony range
local groups = {
    0x41, 0x42, 0x44, 0x48, 0x4B, 0x4F, 0x50, 0x53, 0x55, 0x66, 0x74,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
    0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90,
}

local buf = memory.alloc(0x400)
local ba = N(buf)
local function fill() for off = 0, 0x3FC, 4 do wd(ba + off, SENTINEL) end end

local dirs = {
    {0x40000000, "IOR"},
    {0xC0000000, "IOWR"},
}

-- Sizes to try: 4, 8, 64 (covers most struct sizes)
local sizes = {
    {0x00040000, 4},   -- size=4
    {0x00080000, 8},   -- size=8
    {0x00400000, 64},  -- size=64
}

local discoveries = {}

print("")
print("[B] sweep: " .. #groups .. " groups × 32 cmds × 2 dirs × 3 sizes")
for fi = 1, #fds do
    if not alive() then print("DEAD"); break end
    local nm, fd = fds[fi][1], fds[fi][2]
    local dev_hits = 0
    local is_catchall = false

    -- Quick catchall test: if group 0x00 cmd 0x00 IOR size=4 returns non-(-1), it's a catchall
    local test_code = 0x40040001  -- IOR size=4 group=0x00 cmd=0x01
    local ok_t, rv_t = pcall(function() return sc_ioctl(uint64(fd), uint64(test_code), uint64(ba)) end)
    if ok_t and N(rv_t) ~= -1 then
        is_catchall = true
        print(string.format("  %-16s CATCH-ALL (skip)", nm))
    end

    if not is_catchall then
        for _, sz in ipairs(sizes) do
            if not alive() then break end
            local sz_bits, sz_bytes = sz[1], sz[2]

            for _, g in ipairs(groups) do
                if not alive() then break end
                for cmd = 0, 31 do
                    for _, dp in ipairs(dirs) do
                        local code = dp[1] + sz_bits + g * 0x100 + cmd
                        fill()
                        local ok, rv = pcall(function()
                            return sc_ioctl(uint64(fd), uint64(code), uint64(ba))
                        end)
                        if ok then
                            local r = N(rv)
                            if r ~= -1 then
                                dev_hits = dev_hits + 1
                                discoveries[#discoveries + 1] = {fd, nm, dp[2], g, cmd, r, code, sz_bytes}
                                local uv = r; if uv < 0 then uv = uv + 0x100000000 end
                                print(string.format("  HIT %-12s %s g=0x%02X cmd=0x%02X sz=%d ret=0x%X",
                                    nm, dp[2], g, cmd, sz_bytes, uv))
                            end
                        elseif not alive() then
                            print(string.format("  %s KILLED g=0x%02X cmd=0x%02X sz=%d", nm, g, cmd, sz_bytes))
                            break
                        end
                    end
                    if not alive() then break end
                end
            end
        end
    end

    if dev_hits == 0 and not is_catchall then
        print(string.format("  %-16s nothing (%d groups × 32 cmds × 2 dirs × 3 sizes)", nm, #groups))
    end
end

if not alive() then print("DEAD before deep scan"); return end

-- [C] Deep scan discoveries with sentinel buffer
print("")
print(string.format("[C] deep scan %d discoveries", #discoveries))

for _, d in ipairs(discoveries) do
    if not alive() then break end
    local fd, nm, dir_name, g, cmd, ret_small, code, sz_bytes = d[1], d[2], d[3], d[4], d[5], d[6], d[7], d[8]

    fill()
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(fd), uint64(code), uint64(ba))
    end)
    if ok then
        local r = N(rv)
        if r ~= -1 then
            local modified = 0
            local first_mod, last_mod = nil, nil
            for off = 0, math.min(sz_bytes + 64, 0x3FC), 4 do
                local v = rd(ba + off)
                if v ~= SENTINEL then
                    modified = modified + 1
                    if not first_mod then first_mod = off end
                    last_mod = off
                end
            end
            if modified > 0 then
                local uv = r; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("  %s %s g=0x%02X cmd=0x%02X sz=%d ret=0x%X: %d dw mod +0x%X..+0x%X",
                    nm, dir_name, g, cmd, sz_bytes, uv, modified, first_mod, last_mod))

                -- Overcopy check
                if last_mod and (last_mod + 4) > sz_bytes then
                    print(string.format("    *** OVERCOPY: declared %d bytes, last mod at +0x%X ***", sz_bytes, last_mod))
                end

                -- kptr scan
                for off = 0, (last_mod or 0), 4 do
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

                -- Dump modified data
                if modified <= 32 then
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
        print(string.format("  %s KILLED on scan g=0x%02X cmd=0x%02X", nm, g, cmd))
        break
    end
end

-- Cleanup
for fi = 1, #fds do
    pcall(function() sc6(uint64(fds[fi][2])) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271f COMPLETE ===")
