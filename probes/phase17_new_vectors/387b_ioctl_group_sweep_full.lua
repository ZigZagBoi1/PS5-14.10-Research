-- CRASH_CLASS: LOW
-- PROBE 387b: full 256-group ioctl sweep on non-catch-all, non-gc/dce devices
--
-- Context: 387a confirmed ugen0.2 clean (6 data cmds, no overcopy, no kptrs).
-- Catch-all devices (camera/hid/hmd_*) just echo the fd for every code.
-- gc (25 cmds) and dce (1 cmd) are clean (56m).
-- 271f tested only 28 selected groups. This probe sweeps ALL 256 groups on
-- each remaining non-catch-all device at multiple lengths and directions.
-- With sentinel-buffer overcopy detection on every hit.

print("=== PROBE 387b: full group sweep (non-catch-all) ===")
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

local SENTINEL = 0xDEAD0000
local BUF_SZ = 0x1000
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

local sbuf = memory.alloc(BUF_SZ)
local function fill_sentinel()
    local a = N(sbuf)
    for i = 0, BUF_SZ - 4, 4 do wd(a + i, SENTINEL) end
end

local function scan_buf(declared)
    local a = N(sbuf)
    local modified = 0
    local max_off = -1
    local kptrs = {}
    for i = 0, BUF_SZ - 8, 4 do
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
    return modified, max_off, kptrs, (max_off >= declared)
end

-- [A] Open non-catch-all, non-gc/dce devices
print("[A] open devices")
local targets = {
    "ajm", "ajmi", "bt", "rng", "random", "urandom",
    "gic", "dmem0", "dmem1", "dmem2",
    "notification0", "notification1", "notification2", "notification3",
    "notification4", "notification5", "notification6", "notification7",
    "deci_stdin", "sce_zlib", "usbctl", "usb", "zero",
    "hmd_dist",
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
for _, e in ipairs(fds) do
    print(string.format("  %-16s fd=%d", e[1], e[2]))
end
if not alive() then print("DEAD after open"); return end

-- [B] Full sweep: 256 groups × 5 sizes × 2 directions, cmd=0 first
print("")
print("[B] group discovery: 256 groups × 5 sizes × 2 dirs per device")

local sizes = {0x04, 0x10, 0x40, 0x100, 0x400}
local all_kptrs = {}
local all_overcopy = {}
local all_hits = {}
local total_calls = 0

for dev_idx, entry in ipairs(fds) do
    local nm, fd = entry[1], entry[2]
    if not alive() then break end
    local dev_hits = {}

    for grp = 0, 0xFF do
        if not alive() then break end
        -- Skip file-layer group 0x66
        if grp ~= 0x66 then
            local found = false
            for _, sz in ipairs(sizes) do
                if found then break end
                -- IOC_OUT = 0x40000000
                local code = 0x40000000 + sz * 0x10000 + grp * 0x100
                fill_sentinel()
                local ok, rv = pcall(function()
                    return sc_ioctl(uint64(fd), uint64(code), sbuf)
                end)
                total_calls = total_calls + 1
                local ret = ok and N(rv) or -999
                if ret >= 0 and ret < 0x10000 then
                    local mod, mx, kps, oc = scan_buf(sz)
                    dev_hits[grp] = {code=code, ret=ret, sz=sz, dir="OUT",
                        mod=mod, mx=mx, kps=kps, oc=oc}
                    found = true
                end
                if not found then
                    -- IOC_INOUT = 0xC0000000
                    code = 0xC0000000 + sz * 0x10000 + grp * 0x100
                    fill_sentinel()
                    ok, rv = pcall(function()
                        return sc_ioctl(uint64(fd), uint64(code), sbuf)
                    end)
                    total_calls = total_calls + 1
                    ret = ok and N(rv) or -999
                    if ret >= 0 and ret < 0x10000 then
                        local mod, mx, kps, oc = scan_buf(sz)
                        dev_hits[grp] = {code=code, ret=ret, sz=sz, dir="INOUT",
                            mod=mod, mx=mx, kps=kps, oc=oc}
                        found = true
                    end
                end
            end
        end
    end

    -- Report
    local count = 0
    for _ in pairs(dev_hits) do count = count + 1 end
    if count > 0 then
        print(string.format("  %s: %d active groups (fd=%d)", nm, count, fd))
        for grp, h in pairs(dev_hits) do
            local tag = ""
            if h.oc then tag = " *** OVERCOPY ***" end
            if #h.kps > 0 then tag = tag .. " *** KPTR ***" end
            local data_tag = ""
            if h.mod > 0 then data_tag = string.format(" mod=%d mx=0x%X", h.mod, h.mx) end
            print(string.format("    grp=0x%02X %s code=0x%08X ret=%d sz=0x%X%s%s",
                grp, h.dir, h.code, h.ret, h.sz, data_tag, tag))
            if h.oc then
                all_overcopy[#all_overcopy + 1] = {dev=nm, code=h.code, sz=h.sz, mx=h.mx, mod=h.mod}
            end
            for _, kp in ipairs(h.kps) do
                all_kptrs[#all_kptrs + 1] = {dev=nm, code=h.code, off=kp.off, hi=kp.hi, lo=kp.lo}
                print(string.format("      KPTR +0x%X: 0x%08X%08X", kp.off, kp.hi, kp.lo))
            end
            all_hits[#all_hits + 1] = {nm=nm, fd=fd, grp=grp, h=h}
        end
    end

    -- Progress heartbeat
    print(string.format("  [%d/%d] %s done (%d calls)", dev_idx, #fds, nm, total_calls))
end
if not alive() then print("DEAD after discovery"); return end

-- [C] Expand: for each hit, sweep cmds 0x01-0x3F
print("")
print("[C] expand " .. #all_hits .. " groups: cmds 0x01-0x3F")

for _, hit in ipairs(all_hits) do
    if not alive() then break end
    local nm, fd, grp = hit.nm, hit.fd, hit.grp
    local base_sz = hit.h.sz
    local try_sizes = {base_sz}
    -- Add adjacent sizes
    if base_sz < 0x100 then try_sizes[#try_sizes + 1] = 0x100 end
    if base_sz < 0x400 then try_sizes[#try_sizes + 1] = 0x400 end

    for cmd = 1, 0x3F do
        if not alive() then break end
        for _, sz in ipairs(try_sizes) do
            local code = 0x40000000 + sz * 0x10000 + grp * 0x100 + cmd
            fill_sentinel()
            local ok, rv = pcall(function()
                return sc_ioctl(uint64(fd), uint64(code), sbuf)
            end)
            total_calls = total_calls + 1
            local ret = ok and N(rv) or -999
            if ret >= 0 and ret < 0x10000 then
                local mod, mx, kps, oc = scan_buf(sz)
                if mod > 0 then
                    local tag = ""
                    if oc then tag = " *** OVERCOPY ***" end
                    if #kps > 0 then tag = tag .. " *** KPTR ***" end
                    print(string.format("  %s grp=0x%02X cmd=0x%02X sz=0x%X ret=%d mod=%d mx=0x%X%s",
                        nm, grp, cmd, sz, ret, mod, mx, tag))
                    if oc then
                        all_overcopy[#all_overcopy + 1] = {dev=nm, code=code, sz=sz, mx=mx, mod=mod}
                    end
                    for _, kp in ipairs(kps) do
                        all_kptrs[#all_kptrs + 1] = {dev=nm, code=code, off=kp.off, hi=kp.hi, lo=kp.lo}
                        print(string.format("    KPTR +0x%X: 0x%08X%08X", kp.off, kp.hi, kp.lo))
                    end
                end
                break  -- found working size
            end
        end
    end
end
if not alive() then print("DEAD after expand"); return end

-- [D] Summary
print("")
print("[D] SUMMARY")
print(string.format("  total ioctl calls: %d", total_calls))
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
        print(string.format("    %s code=0x%08X declared=0x%X actual_max=0x%X mod=%d",
            oc.dev, oc.code, oc.sz, oc.mx, oc.mod))
    end
end

if #all_kptrs == 0 and #all_overcopy == 0 then
    print("  CLEAN — no kernel pointers or overcopy found")
end

for _, e in ipairs(fds) do
    pcall(function() sc6(uint64(e[2])) end)
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 387b COMPLETE ===")
