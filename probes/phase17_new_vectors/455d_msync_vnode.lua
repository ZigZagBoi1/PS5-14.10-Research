-- CRASH_CLASS: LOW
-- PROBE 455d: is msync(MS_INVALIDATE) refused for the flag, or for the object?
--
-- 455c: MS_INVALIDATE returns -1 on anonymous, GPU-shaped and device mappings
-- (dmem0, gc), while 0/1/4 succeed and an unused bit 3 is ignored. If a
-- vnode-backed mapping accepts MS_INVALIDATE, the refusal in 455c is about the
-- object type (OBJT_DEVICE), which is exactly the object CVE-2026-49418 needs -
-- so the bug would be unreachable from here. If every mapping refuses it, the
-- call itself is gated.

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

print("=== PROBE 455d: MSYNC(INVALIDATE) ON A VNODE MAPPING ===")
print("")

local function rows(tag, h, l)
    local au = uint64(string.format("0x%X%08X", h, l))
    for _, c in ipairs({ { 0, "none" }, { 1, "ASYNC" }, { 2, "INVALIDATE" }, { 4, "SYNC" }, { 6, "SYNC|INV" } }) do
        local ok, rv = pcall(function() return sc_msync(au, uint64(0x4000), uint64(c[1])) end)
        local rh, rl = 0, 0
        if ok then rh, rl = split(rv) end
        print(string.format("    %-24s %-12s rv=%s", tag, c[2], ok and hex(rh, rl) or "THREW"))
    end
end

for _, case in ipairs({
    { "/app0/eboot.bin", 1, 2, "file MAP_PRIVATE prot READ" },
    { "/app0/eboot.bin", 3, 2, "file MAP_PRIVATE prot RW" },
    { "/savedata0/MAIN.LUA", 1, 2, "savedata MAP_PRIVATE prot READ" },
}) do
    local path, prot, mflags, label = case[1], case[2], case[3], case[4]
    print(string.format("[A] %s (%s)", path, label))
    local okf, fdv = pcall(function() return sc_open(put_name(path), uint64(0), uint64(0)) end)
    local fh, fl = 0, 0
    if okf then fh, fl = split(fdv) end
    if isneg(fh, fl) or fl == 0 then
        print(string.format("    open rv=%s", hex(fh, fl)))
    else
        print(string.format("    open fd=%d", fl))
        local okm, mrv = pcall(function()
            return sc_mmap(ZERO, uint64(0x4000), uint64(prot), uint64(mflags), uint64(fl), uint64(0))
        end)
        local h, l = 0, 0
        if okm then h, l = split(mrv) end
        if not okm or isneg(h, l) or (h == 0 and l == 0) then
            print(string.format("    mmap refused %s", hex(h, l)))
        else
            print(string.format("    mapped=%s", hex(h, l)))
            rows(path, h, l)
            pcall(function() return sc_munmap(uint64(string.format("0x%X%08X", h, l)), uint64(0x4000)) end)
        end
        pcall(function() return sc_close(uint64(fl)) end)
    end
end

print("")
print("=== 455d DONE ===")
