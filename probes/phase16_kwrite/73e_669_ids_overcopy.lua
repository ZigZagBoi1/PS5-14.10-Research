-- CRASH_CLASS: LOW
-- PROBE 73e: Does 669 (submit) write more than 4 bytes per ID to the output?
--
-- 669(cmd, reqs, count, class, ids_out) — ids_out receives created IDs.
-- Every probe reads only the first dword (the ID). But what if the kernel
-- writes a STRUCT per ID (containing kernel pointers)?
--
-- Also: what if the IDs output contains the R+0x00/R+0x08 kernel pointers?
-- The submit handler builds the R object and copies out some handle. If
-- the copyout includes any R fields, we get KASLR for free.
--
-- Tests with sentinel-filled buffers of various sizes.

print("=== PROBE 73e: 669 IDS OUTPUT OVERCOPY ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function wb(a, v) pcall(function() memory.write_byte(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end

local pid = N(mk(20)())
print("pid=" .. pid)

local function put_str(s)
    local p = memory.alloc(#s + 2)
    for i = 1, #s do wb(N(p) + i - 1, string.byte(s, i)) end
    wb(N(p) + #s, 0)
    return p
end

local fd_zero = N(mk(5)(put_str("/dev/zero"), uint64(0), uint64(0)))
print("zero_fd=" .. fd_zero)

local sc669 = mk(669)
local sc662 = mk(662)
local sc664 = mk(664)
local data_buf = memory.alloc(0x100)

-- Test 1: Single submit with oversized IDs buffer
print("")
print("[A] Single submit (count=1) — IDs buffer sizes 4 to 256")
for _, ids_size in ipairs({4, 8, 16, 32, 64, 128, 256}) do
    local req = memory.alloc(0x30)
    local ids_buf = memory.alloc(ids_size + 32)  -- extra for overcopy detect

    -- Fill ENTIRE buffer with sentinel
    for i = 0, ids_size + 28, 4 do wd(N(ids_buf) + i, 0xCCCCCCCC) end

    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(64))
    wq(N(req) + 0x10, data_buf)
    wq(N(req) + 0x18, uint64(0))
    wq(N(req) + 0x20, uint64(fd_zero))

    local ret = N(sc669(uint64(1), req, uint64(1), uint64(1), ids_buf))

    -- Count modified dwords
    local mods = 0
    local last_mod = -1
    local overcopy = 0
    for off = 0, ids_size + 28, 4 do
        local d = rd(N(ids_buf) + off)
        if d ~= 0xCCCCCCCC then
            mods = mods + 1
            if off >= ids_size then overcopy = overcopy + 1 end
            last_mod = off
        end
    end

    print(string.format("  ids_size=%3d: ret=%d mods=%d last_mod=+%02X overcopy=%d",
        ids_size, ret, mods, last_mod, overcopy))

    -- Dump all modified values
    if mods > 0 then
        for off = 0, ids_size + 28, 4 do
            local d = rd(N(ids_buf) + off)
            if d ~= 0xCCCCCCCC then
                local tag = ""
                -- Check qword at this offset
                if off % 8 == 0 then
                    local q = rq(N(ids_buf) + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 then tag = " *** KPTR ***" end
                    end
                end
                print(string.format("    +%02X: 0x%08X%s", off, d, tag))
            end
        end
    end

    -- Clean up
    local id = rd(N(ids_buf))
    if id and id > 0 and id ~= 0xCCCCCCCC then
        if id < 0 then id = id + 0x100000000 end
        pcall(function() sc664(uint64(id)) end)
        local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
    end
end

-- Test 2: Batch submit (count=4) with large IDs buffer
print("")
print("[B] Batch submit (count=4) — IDs buffer stride analysis")
do
    local batch = memory.alloc(4 * 0x28)
    local ids_buf = memory.alloc(256)

    -- Fill IDs buffer with sentinel
    for i = 0, 252, 4 do wd(N(ids_buf) + i, 0xCCCCCCCC) end

    -- Build 4 requests
    for i = 0, 3 do
        local base = N(batch) + i * 0x28
        wq(base + 0x00, uint64(0))
        wq(base + 0x08, uint64(64))
        wq(base + 0x10, data_buf)
        wq(base + 0x18, uint64(0))
        wq(base + 0x20, uint64(fd_zero))
    end

    local ret = N(sc669(uint64(1), batch, uint64(4), uint64(1), ids_buf))
    print(string.format("  batch ret=%d", ret))

    -- Dump ALL modified values
    print("  Modified dwords in 256-byte IDs buffer:")
    local prev_off = -1
    for off = 0, 252, 4 do
        local d = rd(N(ids_buf) + off)
        if d ~= 0xCCCCCCCC then
            local stride = ""
            if prev_off >= 0 then stride = string.format(" (stride=%d)", off - prev_off) end
            print(string.format("    +%02X: 0x%08X%s", off, d, stride))
            prev_off = off
        end
    end

    -- Qword dump of first 64 bytes
    print("  Qword dump (first 64B):")
    for off = 0, 56, 8 do
        local q = rq(N(ids_buf) + off)
        if q then
            local h, l = get_hi_lo(q)
            if h ~= 0xCCCCCCCC or l ~= 0xCCCCCCCC then
                local tag = ""
                if h >= 0xFFFF8000 then tag = " *** KPTR ***" end
                print(string.format("    +%02X: %s%s", off, fmt(q), tag))
            end
        end
    end

    -- Clean up
    for i = 0, 3 do
        local id = rd(N(ids_buf) + i * 4)
        if id and id > 0 and id ~= 0xCCCCCCCC then
            if id < 0 then id = id + 0x100000000 end
            pcall(function() sc664(uint64(id)) end)
            local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
            wd(N(ibuf), id)
            pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
        end
    end
end

-- Test 3: Does IDs output contain qwords or dwords?
print("")
print("[C] IDs output: dword vs qword format")
do
    local req = memory.alloc(0x30)
    local ids_buf = memory.alloc(32)

    -- Fill with pattern that distinguishes adjacent dwords
    wq(N(ids_buf) + 0, uint64(0x1111111111111111))
    wq(N(ids_buf) + 8, uint64(0x2222222222222222))
    wq(N(ids_buf) + 16, uint64(0x3333333333333333))
    wq(N(ids_buf) + 24, uint64(0x4444444444444444))

    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(64))
    wq(N(req) + 0x10, data_buf)
    wq(N(req) + 0x18, uint64(0))
    wq(N(req) + 0x20, uint64(fd_zero))

    N(sc669(uint64(1), req, uint64(1), uint64(1), ids_buf))

    -- Read back as both dwords and qwords
    print("  Dword view:")
    for off = 0, 28, 4 do
        local d = rd(N(ids_buf) + off)
        print(string.format("    +%02X: 0x%08X", off, d or 0))
    end
    print("  Qword view:")
    for off = 0, 24, 8 do
        print(string.format("    +%02X: %s", off, fmt(rq(N(ids_buf) + off))))
    end

    -- Check if hi dword of first qword was modified
    local hi = rd(N(ids_buf) + 4)
    if hi ~= 0x11111111 then
        print("  *** 669 writes QWORD per ID (8 bytes, not 4) ***")
        local q = rq(N(ids_buf))
        local qh, ql = get_hi_lo(q)
        if qh >= 0xFFFF8000 then
            print("  *** HIGH DWORD IS KERNEL RANGE: " .. fmt(q) .. " ***")
        end
    else
        print("  669 writes DWORD per ID (4 bytes)")
    end

    -- Clean up
    local id = rd(N(ids_buf))
    if id and id > 0 then
        if id < 0 then id = id + 0x100000000 end
        pcall(function() sc664(uint64(id)) end)
        local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
    end
end

-- Test 4: Different cmd values for 669
print("")
print("[D] 669 cmd sweep (0-7)")
for cmd = 0, 7 do
    local req = memory.alloc(0x30)
    local ids_buf = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(ids_buf) + i, 0xCCCCCCCC) end

    wq(N(req) + 0x00, uint64(0))
    wq(N(req) + 0x08, uint64(64))
    wq(N(req) + 0x10, data_buf)
    wq(N(req) + 0x18, uint64(0))
    wq(N(req) + 0x20, uint64(fd_zero))

    local ok, ret = pcall(function() return sc669(uint64(cmd), req, uint64(1), uint64(1), ids_buf) end)
    local id = rd(N(ids_buf))
    local hi = rd(N(ids_buf) + 4)
    print(string.format("  cmd=%d: ret=%s id=0x%08X hi=0x%08X",
        cmd, ok and tostring(N(ret)) or "FAIL", id or 0, hi or 0))

    if id and id > 0 and id ~= 0xCCCCCCCC then
        if id < 0 then id = id + 0x100000000 end
        pcall(function() sc664(uint64(id)) end)
        local dbuf = memory.alloc(4); local ibuf = memory.alloc(4)
        wd(N(ibuf), id)
        pcall(function() sc662(ibuf, uint64(1), dbuf, uint64(0), uint64(0), uint64(0)) end)
    end
end

print("")
print("alive=YES")
print("=== PROBE 73e COMPLETE ===")
