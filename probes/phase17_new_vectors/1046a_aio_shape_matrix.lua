-- CRASH_CLASS: LOW
-- PROBE 1046a: which create shape makes a deletable object?
-- The delete gate in _aio_multi_delete (sys_662.c:604-615) answers 0x80020010 when the
-- object byte at +0xc is zero, and again when the qword at +0x28 is non-zero.  Every object
-- made with flags=0x1001/mode=1 hits the first condition.  Sweep the (flags, count, mode,
-- poll-before-delete) matrix and report the status of a serial delete for each shape.
print("=== PROBE 1046a: create/delete shape matrix ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function mk(n) local t = {} for k, v in pairs(syscall.pipe) do t[k] = v end t.syscall_no = n setmetatable(t, getmetatable(syscall.pipe)) return t end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end) if o then return to_num(v) end end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function zero(a, n) pcall(function() for i = 0, n - 4, 4 do memory.write_dword(a + i, 0) end end) end
local pid0 = to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))
print("[0] pid=" .. pid0)
local _, a = pcall(function() return mk(477)(uint64(0), uint64(0x20000), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local page = to_num(a)
if page == 0 then print("[!] mmap failed"); return end
zero(page, 0x20000)
local D, OUT, ST, PO = page, page + 0x4000, page + 0x8000, page + 0xC000
local sc669, sc662, sc664 = mk(669), mk(662), mk(664)
local function create(flags, count, mode)
    wd(D + 0x00, 0); wd(D + 0x08, 0); wd(D + 0x10, 0); wd(D + 0x18, 0); wd(D + 0x20, -1); wd(D + 0x24, 0)
    wd(OUT, 0)
    local ok, rv = pcall(function() return sc669(uint64(flags), uint64(D), uint64(count), uint64(mode), uint64(OUT)) end)
    return ok, to_num(rv), rd(OUT) or 0
end
local function del(id)
    wq(OUT, uint64(id))
    wd(ST, 0)
    local ok, rv = pcall(function() return sc662(uint64(OUT), uint64(1), uint64(ST)) end)
    return ok, rd(ST) or 0, to_num(rv)
end
local function poll(id)
    wq(PO, uint64(id))
    wd(ST, 0)
    local ok, rv = pcall(function() return sc664(uint64(PO), uint64(1), uint64(ST)) end)
    return ok, rd(ST) or 0, to_num(rv)
end
local shapes = {
    { 1, 1, 1 }, { 1, 1, 2 }, { 1, 1, 3 }, { 2, 1, 1 }, { 2, 1, 2 }, { 2, 1, 3 },
    { 0x1001, 1, 1 }, { 0x1001, 1, 2 }, { 0x1001, 1, 3 },
    { 0x1001, 2, 1 }, { 0x1001, 2, 2 }, { 0x1001, 2, 3 },
    { 0x1002, 1, 1 }, { 0x1002, 2, 1 }, { 0x1002, 4, 2 },
}
local okc, rvc, id = create(0x1001, 1, 1)
print(string.format("[A] control create ok=%s rv=%d id=%08X", tostring(okc), rvc, id))
if id == 0 then print("[!] no control object"); return end
local okd, std, rvd = del(id)
print(string.format("[A] control delete ok=%s st=%08X rv=%d", tostring(okd), std, rvd))

for _, s in ipairs(shapes) do
    local flags, count, mode = s[1], s[2], s[3]
    local ok1, rv1, id1 = create(flags, count, mode)
    if id1 == 0 then
        print(string.format("[S] f=%08X c=%d m=%d create_fail rv=%d", flags, count, mode, rv1))
    else
        local ok2, st2, rv2 = del(id1)
        print(string.format("[S] f=%08X c=%d m=%d id=%08X del st=%08X rv=%d", flags, count, mode, id1, st2, rv2))
    end
end
print("--- poll first, then delete ---")
for _, s in ipairs(shapes) do
    local flags, count, mode = s[1], s[2], s[3]
    local ok1, rv1, id1 = create(flags, count, mode)
    if id1 == 0 then
        print(string.format("[P] f=%08X c=%d m=%d create_fail rv=%d", flags, count, mode, rv1))
    else
        local okp, stp, rvp = poll(id1)
        local ok2, st2, rv2 = del(id1)
        print(string.format("[P] f=%08X c=%d m=%d id=%08X poll st=%08X rv=%d | del st=%08X rv=%d",
            flags, count, mode, id1, stp, rvp, st2, rv2))
    end
end
print("[Z] alive pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))
