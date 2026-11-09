-- CRASH_CLASS: LOW
-- PROBE 455b: which msync flag sets does 14.10 accept on a device mapping?
--
-- 455a showed msync(65) works (MS_SYNC 4 and MS_ASYNC 1 return 0) but
-- MS_INVALIDATE alone (2) returns -1 on every mapping, including anonymous
-- memory. CVE-2026-49418 needs MS_INVALIDATE to be *accepted* on an unmanaged
-- device object, so the first question is which flag combination the handler
-- takes on /dev/dmem0 and /dev/gc, both of which mmap successfully.

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v.tonumber() end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function u64(h, l)
    return uint64(string.format("0x%X%08X", h % 0x100000000, l % 0x100000000))
end
local function sgn(v)
    local h, l = 0, 0
    if type(v) == "table" and v.h then h, l = v.h, v.l else l = tonumber(v) or 0 end
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then return -1 end
    if h >= 0x80000000 and h < 0xFFFFFFFF then return -1 end
    return l
end
local function rd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(v) end
    return nil
end
local function put_name(s)
    local b = memory.alloc(#s + 1)
    local i = 0
    while i < #s do memory.write_byte(b + i, string.byte(s, i + 1)); i = i + 1 end
    memory.write_byte(b + #s, 0)
    return b
end

local sc_open, sc_close = make_syscall(5), make_syscall(6)
local sc_mmap, sc_munmap = make_syscall(477), make_syscall(73)
local sc_msync = make_syscall(65)
local Z, NEG = uint64(0), u64(0xFFFFFFFF, 0xFFFFFFFF)
local PAGE = 0x4000

print("=== PROBE 455b: ACCEPTED MSYNC FLAG SETS ON DEVICE MAPPINGS ===")
print("")

local function mmap(size, prot, flags, fd, off)
    local ok, v = pcall(function() return sc_mmap(Z, uint64(size), uint64(prot), uint64(flags), fd, uint64(off)) end)
    if not ok then return nil end
    local s = sgn(v)
    if s < 0 or s == 0 then return nil end
    local h, l = 0, s
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    return h * 4294967296 + l
end

local combos = {
    { 0, "0 (none)" },
    { 1, "1 MS_ASYNC" },
    { 2, "2 MS_INVALIDATE" },
    { 3, "3 ASYNC|INVALIDATE" },
    { 4, "4 MS_SYNC" },
    { 6, "6 SYNC|INVALIDATE" },
    { 7, "7 all" },
    { 8, "8 invalid bit" },
}

local function probe_map(tag, addr, size)
    for _, c in ipairs(combos) do
        local ok, rv = pcall(function()
            return sc_msync(uint64(addr), uint64(size), uint64(c[1]))
        end)
        print(string.format("    %-14s flags=%-20s rv=%s", tag, c[2], tostring(ok and sgn(rv) or "THREW")))
    end
end

print("[A] anonymous control (4 pages)")
local anon = mmap(4 * PAGE, 3, 0x1002, NEG, 0)
if anon then
    pcall(function() memory.write_dword(anon, 0x11223344) end)
    probe_map("anon", anon, 4 * PAGE)
else
    print("    mmap failed")
end

for _, path in ipairs({ "/dev/dmem0", "/dev/gc" }) do
    print(string.format("[B] %s", path))
    local name = put_name(path)
    local okf, fd = pcall(function() return sc_open(name, uint64(2), uint64(0)) end)
    local f = okf and sgn(fd) or -1
    if f < 0 then
        print(string.format("    open rv=%d", f))
    else
        local m = mmap(4 * PAGE, 3, 1, uint64(f), 0)     -- MAP_SHARED
        if m then
            local w = pcall(function() memory.write_dword(m, 0x11223344) end)
            print(string.format("    mapped=0x%X fd=%d write=%s rd=0x%X", m, f, tostring(w), rd(m) or 0))
            probe_map(path, m, 4 * PAGE)
            print(string.format("    munmap=%d", sgn(sc_munmap(uint64(m), uint64(4 * PAGE)))))
        else
            print("    mmap(MAP_SHARED) failed")
        end
        pcall(function() return sc_close(uint64(f)) end)
    end
end

print("")
print("=== 455b DONE ===")
