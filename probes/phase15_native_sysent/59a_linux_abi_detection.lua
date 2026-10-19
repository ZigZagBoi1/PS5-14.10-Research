-- CRASH_CLASS: LOW
-- PROBE 59a: Linuxulator (linux64.ko) presence detection via sysctl
--
-- Context: CVE-2026-49424 is a kernel stack info leak in FreeBSD's Linux
-- waitid() emulation that leaks 104 bytes of uninitialized kernel stack per
-- call — a trivial KASLR defeat if reachable. The vulnerable code lives in
-- the Linuxulator (linux64.ko), which has its own sysent table separate from
-- the native FreeBSD sysent that make_syscall() uses.
--
-- The Linuxulator is unlikely on PS5: Sony's custom kernel has no use case
-- for Linux binary compatibility, and the module is not in FreeBSD's default
-- GENERIC kernel. But the payoff (KASLR defeat) justifies a cheap probe.
--
-- This probe does NOT attempt to call Linux syscalls. It uses the native
-- FreeBSD sysctl(202) interface to look for Linuxulator-specific sysctl
-- nodes that only exist when linux64.ko (or linux.ko) is loaded:
--   - compat.linux (top-level node for Linux ABI settings)
--   - compat.linux.osrelease (fake Linux version string)
--   - compat.linux.oss_version (fake OSS version)
--   - kern.features.linux64 (feature flag)
--
-- If ANY of these resolve, the Linuxulator is loaded and CVE-2026-49424
-- becomes a priority target. If all fail, the module is absent.
--
-- Secondary test: sysctl name walk. Probe 42e's tree walker can be used
-- to search for "linux" in sysctl names. This probe uses a targeted
-- approach instead: query known MIBs directly, which is faster and safer.

print("=== PROBE 59a: LINUXULATOR DETECTION ===")
print("")

-- Standard helpers (same as 58d/57c)
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function hex(n)
    if type(n) == "table" and n.h then
        return string.format("0x%08X%08X", n.h, n.l)
    end
    return string.format("0x%X", tonumber(n) or 0)
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
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function safe_rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end

local sc_sysctl = make_syscall(202)
local sc_getpid = make_syscall(20)

--------------------------------------------------------------------
-- CANARY
--------------------------------------------------------------------
print("--- CANARY: getpid ---")
local ok_pid, pid = pcall(function() return sc_getpid() end)
if ok_pid then
    print("  getpid: " .. tostring(to_num(pid)))
else
    print("  getpid FAILED — loader broken")
    print("=== PROBE 59a COMPLETE ===")
    return
end

--------------------------------------------------------------------
-- Helper: resolve a sysctl name to its MIB via the meta-interface
-- sysctl({0, 3}, 2, name_string, &mib_out, &mib_len)
-- {0, 3} = CTL_SYSCTL, CTL_SYSCTL_NAME2OID
--------------------------------------------------------------------
local mib_buf  = memory.alloc(64)  -- input MIB
local out_buf  = memory.alloc(64)  -- output MIB or value
local len_buf  = memory.alloc(8)   -- output length
local name_mem = memory.alloc(128) -- name string

local function write_string(addr, str)
    for i = 1, #str do
        safe_wb(addr + (i-1), string.byte(str, i))
    end
    safe_wb(addr + #str, 0)
end

local function read_string(addr, maxlen)
    local chars = {}
    for i = 0, maxlen - 1 do
        local b = safe_rb(addr + i)
        if not b or b == 0 then break end
        chars[#chars + 1] = string.char(b)
    end
    return table.concat(chars)
end

-- name2oid: resolve "compat.linux.osrelease" -> MIB array
-- FreeBSD meta-interface: sysctl({0, 3}, 2, name, strlen(name), oid_out, &oid_len)
local function name2oid(name)
    -- Input MIB: {0, 3}
    safe_wd(mib_buf, 0)
    safe_wd(mib_buf + 4, 3)

    -- Write name into name_mem
    write_string(name_mem, name)

    -- Output buffer for the resolved MIB
    for i = 0, 60, 4 do safe_wd(out_buf + i, 0) end
    safe_wq(len_buf, uint64(64))

    local ok, ret = pcall(function()
        return sc_sysctl(
            uint64(mib_buf), uint64(2),
            uint64(out_buf), uint64(len_buf),
            uint64(name_mem), uint64(#name)
        )
    end)

    if not ok then return nil, "PCALL-FAIL" end
    local rv = to_num(ret)
    if rv ~= 0 then return nil, "ret=" .. rv end

    -- Read the resolved MIB length (in bytes, each int = 4 bytes)
    local out_len = to_num(safe_rq(len_buf) or 0)
    local oid_count = math.floor(out_len / 4)
    if oid_count == 0 then return nil, "empty" end

    local oid = {}
    for i = 0, oid_count - 1 do
        oid[i + 1] = safe_rd(out_buf + i * 4) or 0
    end
    return oid, nil
end

-- Read a sysctl value by MIB
local val_buf = memory.alloc(0x200)

local function read_sysctl(oid)
    -- Write MIB
    for i = 1, #oid do
        safe_wd(mib_buf + (i-1) * 4, oid[i])
    end

    -- Output
    for i = 0, 0x1FC, 4 do safe_wd(val_buf + i, 0) end
    safe_wq(len_buf, uint64(0x200))

    local ok, ret = pcall(function()
        return sc_sysctl(
            uint64(mib_buf), uint64(#oid),
            uint64(val_buf), uint64(len_buf),
            uint64(0), uint64(0)
        )
    end)

    if not ok then return nil, "PCALL-FAIL" end
    local rv = to_num(ret)
    if rv ~= 0 then return nil, "ret=" .. rv end

    local out_len = to_num(safe_rq(len_buf) or 0)
    return out_len, nil
end

--------------------------------------------------------------------
-- SECTION A: Query known Linuxulator sysctl names
--------------------------------------------------------------------
print("")
print("--- SECTION A: LINUXULATOR SYSCTL DETECTION ---")
print("  Strategy: resolve known sysctl names that only exist when")
print("  linux64.ko or linux.ko is loaded.")
print("")

local linux_found = false
local targets = {
    "compat.linux.osrelease",
    "compat.linux.oss_version",
    "compat.linux.osname",
    "compat.linux.preserve_vstatus",
    "kern.features.linux64",
    "kern.features.linux",
}

for _, name in ipairs(targets) do
    print("[BEFORE] name2oid: " .. name)
    local oid, err = name2oid(name)
    if oid then
        print("  RESOLVED! MIB = {" .. table.concat(oid, ", ") .. "}")
        linux_found = true

        -- Try to read the value
        print("[BEFORE] read_sysctl: " .. name)
        local vlen, verr = read_sysctl(oid)
        if vlen then
            print("  VALUE length: " .. vlen .. " bytes")
            -- Try to read as string
            local val_str = read_string(val_buf, math.min(vlen, 64))
            if #val_str > 0 then
                print("  VALUE (string): \"" .. val_str .. "\"")
            end
            -- Also dump first 16 bytes as hex
            local hexdump = {}
            for i = 0, math.min(vlen - 1, 15) do
                local b = safe_rb(val_buf + i)
                if b then hexdump[#hexdump + 1] = string.format("%02X", b) end
            end
            if #hexdump > 0 then
                print("  VALUE (hex): " .. table.concat(hexdump, " "))
            end
        else
            print("  READ FAILED: " .. (verr or "unknown"))
        end
        print("[AFTER] " .. name)
    else
        print("  NOT FOUND: " .. (err or "unknown"))
        print("[AFTER] " .. name)
    end
    print("")
end

--------------------------------------------------------------------
-- SECTION B: Walk compat.* subtree for any linux reference
--------------------------------------------------------------------
print("--- SECTION B: COMPAT SUBTREE WALK ---")
print("  Looking for any 'compat' sysctl node (even without linux).")
print("")

-- Try to resolve "compat" itself
print("[BEFORE] name2oid: compat")
local compat_oid, compat_err = name2oid("compat")
if compat_oid then
    print("  RESOLVED: compat = {" .. table.concat(compat_oid, ", ") .. "}")

    -- Enumerate children using {0, 1, <compat_oid>} (get-next)
    -- Walk up to 20 children
    local current = {}
    for _, v in ipairs(compat_oid) do current[#current + 1] = v end

    for step = 1, 20 do
        -- Build query: {0, 1, current_oid...}
        safe_wd(mib_buf, 0)
        safe_wd(mib_buf + 4, 1)
        for i = 1, #current do
            safe_wd(mib_buf + 4 + i * 4, current[i])
        end

        for i = 0, 60, 4 do safe_wd(out_buf + i, 0) end
        safe_wq(len_buf, uint64(64))

        local ok, ret = pcall(function()
            return sc_sysctl(
                uint64(mib_buf), uint64(#current + 2),
                uint64(out_buf), uint64(len_buf),
                uint64(0), uint64(0)
            )
        end)

        if not ok or to_num(ret) ~= 0 then
            print("  walk ended at step " .. step)
            break
        end

        local next_len = math.floor(to_num(safe_rq(len_buf) or 0) / 4)
        if next_len == 0 then break end

        local next_oid = {}
        for i = 0, next_len - 1 do
            next_oid[i + 1] = safe_rd(out_buf + i * 4) or 0
        end

        -- Check if still under compat.* (first component matches)
        if next_oid[1] ~= compat_oid[1] then
            print("  left compat subtree at step " .. step)
            break
        end

        -- Get the name of this OID via {0, 2, oid...}
        safe_wd(mib_buf, 0)
        safe_wd(mib_buf + 4, 2)
        for i = 1, #next_oid do
            safe_wd(mib_buf + 4 + i * 4, next_oid[i])
        end

        for i = 0, 252, 4 do safe_wd(name_mem + i, 0) end
        safe_wq(len_buf, uint64(128))

        local ok2, ret2 = pcall(function()
            return sc_sysctl(
                uint64(mib_buf), uint64(#next_oid + 2),
                uint64(name_mem), uint64(len_buf),
                uint64(0), uint64(0)
            )
        end)

        local node_name = "?"
        if ok2 and to_num(ret2) == 0 then
            node_name = read_string(name_mem, 128)
        end

        print("  [" .. step .. "] {" .. table.concat(next_oid, ",") .. "} = " .. node_name)

        if node_name:find("linux") then
            print("  >>> LINUX NODE FOUND IN COMPAT TREE <<<")
            linux_found = true
        end

        current = next_oid
    end
else
    print("  'compat' NOT FOUND: " .. (compat_err or "unknown"))
    print("  (If no compat subtree exists, Linuxulator is almost certainly absent)")
end

print("[AFTER] compat subtree walk")

--------------------------------------------------------------------
-- SECTION C: kern.features subtree (feature flags)
--------------------------------------------------------------------
print("")
print("--- SECTION C: KERN.FEATURES CHECK ---")

print("[BEFORE] name2oid: kern.features")
local features_oid, features_err = name2oid("kern.features")
if features_oid then
    print("  RESOLVED: kern.features = {" .. table.concat(features_oid, ", ") .. "}")

    -- Walk up to 30 feature entries
    local current = {}
    for _, v in ipairs(features_oid) do current[#current + 1] = v end

    for step = 1, 30 do
        safe_wd(mib_buf, 0)
        safe_wd(mib_buf + 4, 1)
        for i = 1, #current do
            safe_wd(mib_buf + 4 + i * 4, current[i])
        end

        for i = 0, 60, 4 do safe_wd(out_buf + i, 0) end
        safe_wq(len_buf, uint64(64))

        local ok, ret = pcall(function()
            return sc_sysctl(
                uint64(mib_buf), uint64(#current + 2),
                uint64(out_buf), uint64(len_buf),
                uint64(0), uint64(0)
            )
        end)

        if not ok or to_num(ret) ~= 0 then break end

        local next_len = math.floor(to_num(safe_rq(len_buf) or 0) / 4)
        if next_len == 0 then break end

        local next_oid = {}
        for i = 0, next_len - 1 do
            next_oid[i + 1] = safe_rd(out_buf + i * 4) or 0
        end

        -- Check still under kern.features
        local still_under = true
        for i = 1, #features_oid do
            if next_oid[i] ~= features_oid[i] then still_under = false; break end
        end
        if not still_under then break end

        -- Get name
        safe_wd(mib_buf, 0)
        safe_wd(mib_buf + 4, 2)
        for i = 1, #next_oid do
            safe_wd(mib_buf + 4 + i * 4, next_oid[i])
        end
        for i = 0, 252, 4 do safe_wd(name_mem + i, 0) end
        safe_wq(len_buf, uint64(128))

        local ok2, ret2 = pcall(function()
            return sc_sysctl(
                uint64(mib_buf), uint64(#next_oid + 2),
                uint64(name_mem), uint64(len_buf),
                uint64(0), uint64(0)
            )
        end)

        local feat_name = "?"
        if ok2 and to_num(ret2) == 0 then
            feat_name = read_string(name_mem, 128)
        end

        -- Read value (integer, 4 bytes)
        local feat_val = nil
        local vlen, verr = read_sysctl(next_oid)
        if vlen and vlen >= 4 then
            feat_val = safe_rd(val_buf)
        end

        local val_str = feat_val and tostring(feat_val) or "?"
        print("  " .. feat_name .. " = " .. val_str)

        if feat_name:find("linux") then
            print("  >>> LINUX FEATURE FLAG FOUND <<<")
            linux_found = true
        end

        current = next_oid
    end
else
    print("  'kern.features' NOT FOUND: " .. (features_err or "unknown"))
end

print("[AFTER] kern.features check")

--------------------------------------------------------------------
-- VERDICT
--------------------------------------------------------------------
print("")
print("====================================")
if linux_found then
    print(">>> LINUXULATOR DETECTED <<<")
    print("CVE-2026-49424 (waitid stack leak) may be reachable.")
    print("NEXT: research how to invoke Linux-ABI syscalls from a")
    print("native FreeBSD process (sysarch ABI switch, or direct")
    print("int 0x80 with Linux syscall numbers).")
else
    print(">>> LINUXULATOR NOT DETECTED <<<")
    print("No linux-related sysctl nodes found. The Linuxulator is")
    print("almost certainly not loaded. CVE-2026-49424 is NOT reachable.")
end
print("====================================")

--------------------------------------------------------------------
-- FINAL CANARY
--------------------------------------------------------------------
print("")
print("--- FINAL CANARY ---")
local ok_pid2, pid2 = pcall(function() return sc_getpid() end)
if ok_pid2 then
    print("  getpid: " .. tostring(to_num(pid2)) .. " — process survived")
else
    print("  getpid FAILED — process state corrupted")
end

print("")
print("=== PROBE 59a COMPLETE ===")
