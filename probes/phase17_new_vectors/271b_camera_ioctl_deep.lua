-- CRASH_CLASS: MODERATE
-- PROBE 271b: Deep ioctl scan on /dev/camera — OUT commands with sentinel buffers
--
-- 271a showed /dev/camera dispatches 55/57 codes from the 13.60 catalog,
-- returning EINVAL (0x16) with zero buffers. The OUT-direction commands
-- (0x80xxxxxx) should copyout data if given valid args. This probe:
--   1. Uses sentinel-filled buffers to detect over-copy
--   2. Tries each OUT command with several input patterns
--   3. Scans for kernel pointers in any written data
--   4. Also tries IN commands with small valid-looking structs

print("=== PROBE 271b: /dev/camera ioctl deep ===")
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
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end

local SENTINEL = 0xDEADBEEF
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

-- Open /dev/camera
local sc5 = mk(5)
local ok1, rv1 = pcall(function() return sc5(path_buf("/dev/camera"), uint64(2)) end)
local cam_fd = ok1 and N(rv1) or -1
print("camera fd=" .. cam_fd)
if cam_fd < 0 then print("ABORT: cannot open /dev/camera"); return end

local sc_ioctl = mk(54)

-- OUT commands (0x80xxxxxx): kernel copies data TO user
local out_codes = {
    {0x80044103, "A:0x03", 4},
    {0x8004410C, "A:0x0C", 4},
    {0x8004410E, "A:0x0E", 4},
    {0x8004410F, "A:0x0F", 4},
    {0x80044808, "f:0x08", 4},
    {0x80045501, "U:0x01", 4},
    {0x80045502, "U:0x02", 4},
    {0x80045506, "U:0x06", 4},
    {0x80047401, "t:0x01", 4},
    {0x80047402, "t:0x02", 4},
    {0x80047404, "t:0x04", 4},
    {0x80047410, "t:0x10", 4},
    {0x80084107, "A:0x07", 8},
    {0x80084108, "A:0x08", 8},
    {0x80084109, "A:0x09", 8},
    {0x8008410E, "A:0x0E8", 8},
    {0x802C7414, "t:0x14", 0x2C},
    {0x802C7416, "t:0x16", 0x2C},
}

-- INOUT commands (0xC0xxxxxx): kernel reads AND writes
local inout_codes = {
    {0xC00C440D, "D:0x0D", 0x0C},
    {0xC00C440E, "D:0x0E", 0x0C},
    {0xC0104410, "D:0x10", 0x10},
    {0xC0104411, "D:0x11", 0x10},
    {0xC0185501, "U:0x01io", 0x18},
    {0xC0845301, "S:0x01io", 0x84},
    {0xC0845302, "S:0x02", 0x84},
    {0xC0A84B00, "K:0x00", 0xA8},
    {0xC1785504, "U:0x04", 0x178},
}

-- Allocate big buffer with sentinel fill
local buf = memory.alloc(0x1000)
local ba = N(buf)

local function fill_sentinel()
    for off = 0, 0xFFC, 4 do wd(ba + off, SENTINEL) end
end

local function scan_buffer(code, name, decl_sz)
    local modified = 0
    local first_mod, last_mod = nil, nil
    for off = 0, 0xFFC, 4 do
        local v = rd(ba + off)
        if v ~= SENTINEL then
            modified = modified + 1
            if not first_mod then first_mod = off end
            last_mod = off
        end
    end

    if modified == 0 then return false end

    local overcopy = last_mod and (last_mod + 4) > decl_sz
    print(string.format("  %s 0x%08X: %d dwords modified, range +0x%X..+0x%X (decl=%d)%s",
        name, code, modified, first_mod or 0, last_mod or 0, decl_sz,
        overcopy and " OVERCOPY!" or ""))

    -- Dump all modified qwords
    local kptr_found = false
    for off = 0, (last_mod or 0) + 4, 4 do
        local lo = rd(ba + off) or SENTINEL
        local hi = rd(ba + off + 4) or SENTINEL
        if lo ~= SENTINEL or hi ~= SENTINEL then
            local ulo = lo; if ulo < 0 then ulo = ulo + 0x100000000 end
            local uhi = hi; if uhi < 0 then uhi = uhi + 0x100000000 end
            if uhi >= 0xFFFF8000 and uhi < 0xFFFFFFFF then
                kptr_found = true
                print(string.format("    *** KPTR +0x%X: 0x%08X%08X ***", off, uhi, ulo))
            end
        end
    end

    if not kptr_found and modified <= 16 then
        -- Dump first modified values
        for off = first_mod, math.min(last_mod, first_mod + 60), 4 do
            local v = rd(ba + off) or SENTINEL
            if v ~= SENTINEL then
                local uv = v; if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("    +0x%02X: 0x%08X", off, uv))
            end
        end
    end

    return kptr_found
end

-- ===== Section A: OUT commands with sentinel buffer =====
print("")
print("--- A: OUT commands (sentinel buffer) ---")
for _, entry in ipairs(out_codes) do
    if not alive() then print("DEAD"); return end
    local code, name, sz = entry[1], entry[2], entry[3]
    fill_sentinel()
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(cam_fd), uint64(code), uint64(ba))
    end)
    local r = ok and N(rv) or -999
    if r ~= -1 and r ~= -999 then
        local uv = r; if uv < 0 then uv = uv + 0x100000000 end
        print(string.format("  ret=0x%X %s", uv, name))
        scan_buffer(code, name, sz)
    end
end

-- ===== Section B: INOUT commands with sentinel buffer =====
print("")
print("--- B: INOUT commands (sentinel buffer) ---")
for _, entry in ipairs(inout_codes) do
    if not alive() then print("DEAD"); return end
    local code, name, sz = entry[1], entry[2], entry[3]
    fill_sentinel()
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(cam_fd), uint64(code), uint64(ba))
    end)
    local r = ok and N(rv) or -999
    if r ~= -1 and r ~= -999 then
        local uv = r; if uv < 0 then uv = uv + 0x100000000 end
        print(string.format("  ret=0x%X %s", uv, name))
        scan_buffer(code, name, sz)
    end
end

-- ===== Section C: OUT commands with zero buffer (try to get real copyout) =====
print("")
print("--- C: OUT commands (zero buffer — may produce copyout) ---")
for _, entry in ipairs(out_codes) do
    if not alive() then print("DEAD"); return end
    local code, name, sz = entry[1], entry[2], entry[3]
    -- Zero the declared size, sentinel the rest
    for off = 0, 0xFFC, 4 do
        if off < sz then wd(ba + off, 0) else wd(ba + off, SENTINEL) end
    end
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(cam_fd), uint64(code), uint64(ba))
    end)
    local r = ok and N(rv) or -999
    if r ~= -1 and r ~= -999 then
        local uv = r; if uv < 0 then uv = uv + 0x100000000 end
        -- Only report if buffer was modified
        local any_mod = false
        for off = 0, sz + 32, 4 do
            local v = rd(ba + off)
            if off < sz then
                if v ~= 0 then any_mod = true end
            else
                if v ~= SENTINEL then any_mod = true end
            end
        end
        if any_mod then
            print(string.format("  DATA ret=0x%X %s", uv, name))
            scan_buffer(code, name, sz)
        end
    end
end

-- ===== Section D: INOUT with small valid-looking input =====
print("")
print("--- D: INOUT commands (cmd=0 in first dword) ---")
for _, entry in ipairs(inout_codes) do
    if not alive() then print("DEAD"); return end
    local code, name, sz = entry[1], entry[2], entry[3]
    -- Fill with sentinel, then set first few dwords to small values
    fill_sentinel()
    wd(ba, 0)         -- cmd/type = 0
    wd(ba + 4, 0)     -- sub = 0
    wd(ba + 8, sz)    -- size = declared size
    wd(ba + 12, 0)
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(cam_fd), uint64(code), uint64(ba))
    end)
    local r = ok and N(rv) or -999
    if r ~= -1 and r ~= -999 then
        local uv = r; if uv < 0 then uv = uv + 0x100000000 end
        print(string.format("  ret=0x%X %s", uv, name))
        scan_buffer(code, name, sz)
    end
end

-- ===== Section E: Also try /dev/hid with OUT commands =====
print("")
print("--- E: /dev/hid OUT commands (sentinel) ---")
local ok_h, rv_h = pcall(function() return sc5(path_buf("/dev/hid"), uint64(2)) end)
local hid_fd = ok_h and N(rv_h) or -1
print("hid fd=" .. hid_fd)
if hid_fd >= 0 then
    for _, entry in ipairs(out_codes) do
        if not alive() then print("DEAD"); break end
        local code, name, sz = entry[1], entry[2], entry[3]
        fill_sentinel()
        local ok, rv = pcall(function()
            return sc_ioctl(uint64(hid_fd), uint64(code), uint64(ba))
        end)
        local r = ok and N(rv) or -999
        if r ~= -1 and r ~= -999 then
            local uv = r; if uv < 0 then uv = uv + 0x100000000 end
            scan_buffer(code, "hid:" .. name, sz)
        end
    end
    pcall(function() mk(6)(uint64(hid_fd)) end)
end

pcall(function() mk(6)(uint64(cam_fd)) end)

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 271b COMPLETE ===")
