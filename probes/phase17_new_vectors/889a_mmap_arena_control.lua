-- CRASH_CLASS: LOW
-- PROBE 889a: control for the 888a mmap anomaly
--
-- Context: in 888a a 256 MiB GPU mapping succeeded while a 64 MiB limit was
-- set (ret=0) and then FAILED after the limit was restored to 1 GiB (ret=-1).
-- Two explanations: (a) the 637 limit really is enforced and the restore
-- arithmetic is not what the name suggests, or (b) the GPU VA arena is simply
-- exhausted after several 256 MiB reservations and 637 has no effect at all.
--
-- This probe never calls 637 in section B, so a failure there proves the arena
-- cap explains 888a C4 without any limit involved.

print("=== PROBE 889a: MMAP ARENA CONTROL ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function show(tag, ok, rv)
    if not ok then
        print(string.format("  [%s] PCALL-FAIL", tag))
        return
    end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X (lo=%u)", tag, h, l, l))
end

local sc20 = make_syscall(20)
local pid = 0
repeat
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
until true
print(string.format("[A] self pid = %u", pid))

local sc477 = make_syscall(477)
local function gpu_map(size)
    local ok, rv = pcall(function()
        return sc477(uint64(0), uint64(size), uint64(0x33),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    return ok, rv
end

print("[B] 256 MiB reservations, no 637 call anywhere in this section:")
for i = 1, 4 do
    local ok, rv = gpu_map(0x10000000)
    show(string.format("mmap 256M #%d", i), ok, rv)
end

print("[C] now set a 1-byte limit and map 1 MiB:")
local sc637 = make_syscall(637)
local okc, rvc = pcall(function() return sc637(uint64(pid), uint64(1)) end)
show("637(pid,1)", okc, rvc)
local ok1, rv1 = gpu_map(0x40000)
show("mmap 256K", ok1, rv1)
local ok2, rv2 = gpu_map(0x4000000)
show("mmap 64M", ok2, rv2)

print("[D] restore 1 GiB:")
local okd, rvd = pcall(function() return sc637(uint64(pid), uint64(0x40000000)) end)
show("637 restore", okd, rvd)

print("")
print("=== PROBE 889a DONE ===")
