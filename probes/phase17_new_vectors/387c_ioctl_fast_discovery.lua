-- CRASH_CLASS: LOW
-- PROBE 387c: fast two-pass ioctl discovery + overcopy scan
--
-- 387b timed out because fill_sentinel + scan on EVERY call is too slow.
-- This probe uses two passes:
--   Pass 1: fast ret-only check (no buffer fill/scan) — just call ioctl,
--            record which (device, group, size, dir) combos return ret >= 0.
--   Pass 2: for hits only, fill sentinel buffer, re-call, scan for
--            overcopy and kernel pointers.
-- Targets: 19 non-catch-all, non-gc/dce devices.

print("=== PROBE 387c: fast ioctl discovery + overcopy ===")
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

-- One buffer, zeroed once, reused for pass 1 (data doesn't matter)
local buf = memory.alloc(0x1000)
for i = 0, 0xFFC, 4 do wd(N(buf) + i, 0) end

-- [A] Open devices
print("[A] open devices")
local targets = {
    "ajm", "ajmi", "bt", "rng", "random", "urandom",
    "gic", "dmem0", "dmem1", "dmem2",
    "notification0", "notification1", "notification2", "notification3",
    "notification4", "notification5", "notification6", "notification7",
    "deci_stdin", "sce_zlib", "usbctl", "usb", "zero", "hmd_dist",
}

local fds = {}
for _, nm in ipairs(targets) do
    local path = "/dev/" .. nm
    local ok1, rv = pcall(function() return sc5(path_buf(path), uint64(2)) end)
    local fd = ok1 and N(rv) or -1
    if fd < 0 or fd >= 0x10000 then
        ok1, rv = pcall(function() return sc5(path_buf(path), uint64(0)) end)
        fd = ok1 and N(rv) or -1
    end
    if fd >= 0 and fd < 0x10000 then
        fds[#fds + 1] = {nm, fd}
    end
end
print(string.format("  opened %d/%d", #fds, #targets))
if not alive() then print("DEAD after open"); return end

-- ===================================================================
-- [B] Pass 1: fast group discovery (ret-only, no buffer ops)
-- ===================================================================
print("")
print("[B] pass 1: fast group discovery")

local sizes = {0x04, 0x10, 0x40, 0x100, 0x400}
local hits = {}  -- {dev_name, fd, code, sz, ret}
local total_calls = 0

for dev_idx, entry in ipairs(fds) do
    local nm, fd = entry[1], entry[2]
    if not alive() then break end

    for grp = 0, 0xFF do
        if grp == 0x66 then
            -- skip file-layer group
        else
            if not alive() then break end
            for _, sz in ipairs(sizes) do
                -- IOC_OUT
                local code = 0x40000000 + sz * 0x10000 + grp * 0x100
                local ok, rv = pcall(function()
                    return sc_ioctl(uint64(fd), uint64(code), buf)
                end)
                total_calls = total_calls + 1
                local ret = ok and N(rv) or -999
                if ret >= 0 and ret < 0x10000 then
                    hits[#hits + 1] = {nm, fd, code, sz, ret, "OUT"}
                    break  -- found working size for this group
                end
                -- IOC_INOUT
                code = 0xC0000000 + sz * 0x10000 + grp * 0x100
                ok, rv = pcall(function()
                    return sc_ioctl(uint64(fd), uint64(code), buf)
                end)
                total_calls = total_calls + 1
                ret = ok and N(rv) or -999
                if ret >= 0 and ret < 0x10000 then
                    hits[#hits + 1] = {nm, fd, code, sz, ret, "INOUT"}
                    break
                end
            end
        end
    end

    print(string.format("  [%d/%d] %s done, %d hits so far, %d calls",
        dev_idx, #fds, nm, #hits, total_calls))
end
if not alive() then print("DEAD after pass 1"); return end

print(string.format("  pass 1 total: %d hits, %d calls", #hits, total_calls))

-- ===================================================================
-- [C] Pass 2: sentinel overcopy check on hits only
-- ===================================================================
print("")
print("[C] pass 2: sentinel overcopy check on " .. #hits .. " hits")

local SENTINEL = 0xDEAD0000
local function fill_sentinel()
    local a = N(buf)
    for i = 0, 0xFFC, 4 do wd(a + i, SENTINEL) end
end

local all_kptrs = {}
local all_overcopy = {}
local data_hits = 0

for _, h in ipairs(hits) do
    if not alive() then break end
    local nm, fd, code, sz, orig_ret, dir = h[1], h[2], h[3], h[4], h[5], h[6]

    fill_sentinel()
    local ok, rv = pcall(function()
        return sc_ioctl(uint64(fd), uint64(code), buf)
    end)
    local ret = ok and N(rv) or -999

    if ret >= 0 then
        -- Scan buffer
        local a = N(buf)
        local modified = 0
        local max_off = -1
        local kptrs = {}
        for i = 0, 0xFFC - 4, 4 do
            local dw = rd(a + i)
            if dw == nil then break end
            if dw < 0 then dw = dw + 0x100000000 end
            if dw ~= SENTINEL then
                modified = modified + 1
                if i > max_off then max_off = i end
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

        local overcopy = (max_off >= sz)
        if modified > 0 then
            data_hits = data_hits + 1
            local tag = ""
            if overcopy then tag = " *** OVERCOPY ***" end
            if #kptrs > 0 then tag = tag .. " *** KPTR ***" end
            print(string.format("  %s %s code=0x%08X ret=%d sz=0x%X mod=%d max=0x%X%s",
                nm, dir, code, ret, sz, modified, max_off, tag))
            if overcopy then
                all_overcopy[#all_overcopy + 1] = {dev=nm, code=code, sz=sz, mx=max_off, mod=modified}
            end
            for _, kp in ipairs(kptrs) do
                all_kptrs[#all_kptrs + 1] = {dev=nm, code=code, off=kp.off, hi=kp.hi, lo=kp.lo}
                print(string.format("    KPTR +0x%X: 0x%08X%08X", kp.off, kp.hi, kp.lo))
            end

            -- Also dump first 16 non-sentinel dwords for context
            if data_hits <= 10 then
                local vals = {}
                for i = 0, 0x3C, 4 do
                    local dw = rd(a + i) or 0
                    if dw < 0 then dw = dw + 0x100000000 end
                    vals[#vals + 1] = string.format("%08X", dw)
                end
                print("    first 64B: " .. table.concat(vals, " "))
            end
        end
    end
end
if not alive() then print("DEAD after pass 2"); return end

-- ===================================================================
-- [D] Pass 3: expand hits — try cmds 0x01-0x3F for each hit group
-- ===================================================================
if #hits > 0 then
    print("")
    print("[D] expand: cmds 0x01-0x3F for " .. #hits .. " active groups")

    local seen = {}
    for _, h in ipairs(hits) do
        if not alive() then break end
        local nm, fd, base_code, sz = h[1], h[2], h[3], h[4]
        local grp = math.floor(base_code / 0x100) % 0x100
        local dir_bits = base_code - (base_code % 0x10000000)
        local key = nm .. "_" .. grp
        if seen[key] then
            -- skip duplicate group
        else
            seen[key] = true
            for cmd = 1, 0x3F do
                if not alive() then break end
                local code = dir_bits + sz * 0x10000 + grp * 0x100 + cmd
                fill_sentinel()
                local ok, rv = pcall(function()
                    return sc_ioctl(uint64(fd), uint64(code), buf)
                end)
                local ret = ok and N(rv) or -999
                if ret >= 0 and ret < 0x10000 then
                    local a = N(buf)
                    local modified = 0
                    local max_off = -1
                    local kptrs = {}
                    for i = 0, 0xFFC - 4, 4 do
                        local dw = rd(a + i)
                        if dw == nil then break end
                        if dw < 0 then dw = dw + 0x100000000 end
                        if dw ~= SENTINEL then
                            modified = modified + 1
                            if i > max_off then max_off = i end
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
                    local overcopy = (max_off >= sz)
                    if modified > 0 then
                        local tag = ""
                        if overcopy then tag = " *** OVERCOPY ***" end
                        if #kptrs > 0 then tag = tag .. " *** KPTR ***" end
                        print(string.format("  %s grp=0x%02X cmd=0x%02X code=0x%08X ret=%d mod=%d max=0x%X%s",
                            nm, grp, cmd, code, ret, modified, max_off, tag))
                        if overcopy then
                            all_overcopy[#all_overcopy + 1] = {dev=nm, code=code, sz=sz, mx=max_off, mod=modified}
                        end
                        for _, kp in ipairs(kptrs) do
                            all_kptrs[#all_kptrs + 1] = {dev=nm, code=code, off=kp.off, hi=kp.hi, lo=kp.lo}
                            print(string.format("    KPTR +0x%X: 0x%08X%08X", kp.off, kp.hi, kp.lo))
                        end
                    end
                end
            end
        end
    end
end
if not alive() then print("DEAD after expand"); return end

-- ===================================================================
-- [E] Summary
-- ===================================================================
print("")
print("[E] SUMMARY")
print(string.format("  devices scanned: %d", #fds))
print(string.format("  pass 1 hits (ret>=0): %d", #hits))
print(string.format("  pass 2 data hits: %d", data_hits))
print(string.format("  kernel pointers: %d", #all_kptrs))
print(string.format("  overcopy incidents: %d", #all_overcopy))

if #all_kptrs > 0 then
    print("")
    print("  *** KERNEL POINTERS ***")
    for _, kp in ipairs(all_kptrs) do
        print(string.format("    %s code=0x%08X +0x%X: 0x%08X%08X",
            kp.dev, kp.code, kp.off, kp.hi, kp.lo))
    end
end

if #all_overcopy > 0 then
    print("")
    print("  *** OVERCOPY ***")
    for _, oc in ipairs(all_overcopy) do
        print(string.format("    %s code=0x%08X declared=0x%X actual=0x%X mod=%d",
            oc.dev, oc.code, oc.sz, oc.mx, oc.mod))
    end
end

if #all_kptrs == 0 and #all_overcopy == 0 then
    print("  CLEAN — no kernel pointers or overcopy on any tested device")
end

for _, e in ipairs(fds) do
    pcall(function() sc6(uint64(e[2])) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 387c COMPLETE ===")
