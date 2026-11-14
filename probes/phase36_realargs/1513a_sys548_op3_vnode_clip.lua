-- CRASH_CLASS: MODERATE -- a vnode mapping is clipped by 548 op 3. Nothing here writes to the
--   mapping: every access is a read, so the file on disk cannot be modified by this probe.
-- PROBE 1513a: op 3 clip of a MAP_SHARED vnode entry -- is the vm_object it clips SHARED?
--
-- Why: 1512a proved 548 op 3 with MAP_FIXED splits a large entry (head / carve / tail) rather than
-- replacing it whole, i.e. it runs vm_map_clip_start and vm_map_clip_end on a live entry. In the
-- 13.60 dump both clippers have a special case gated by `cmp byte [obj+0x9d], 2` and
-- `cmp qword [entry+0x70], 0` (0x8ac8b564 clip_start, 0x8ac8b7e5 clip_end) that writes
-- [obj+0x1a0] = entry->[0x70] and [obj+0x1a8] = end - start. Object type 2 is OBJT_VNODE, so a
-- file mapping is the one entry kind the clipper mutates in place.
--
-- A vnode mapping's vm_object is the vnode's page-cache object, and it is shared by every mapping
-- of the same file. If clipping mutates size/offset on that shared object then a SECOND mapping of
-- the same file is a free witness: it should be untouched, and if it is not, one syscall can resize
-- the page cache of a file it does not own.
--
-- [A] open /app0/eboot.bin O_RDONLY, map it twice (A and B), confirm both read the ELF header
-- [B] 548(0, 0x10, {A+0x10000, 0, 0x4000, 3, op=3}, 1, &proc, 0) -- carve the middle of a vnode entry
-- [C] read both mappings again: A outside the carve, A inside it, B throughout; 547 the segments
-- [D] unmap B, carve A a second time -- A is now the only reference to the object
-- [E] unmap A, reopen the file, read the same bytes back and confirm the file is intact
--
-- -- prior art:
--   results/phase36_realargs/1512a_sys548_op3_split_20261109_230244.txt (op 3 splits: 16 MiB ->
--     0x4000 / 0x4000 / 0xFF8000, markers outside the carve survive)
--   results/phase36_realargs/1508a_sys548_map_fixed_20261109_224934.txt (MAP_FIXED bit 0x10;
--     rv equals the requested address)
--   results/phase36_realargs/1509b_sys548_op3_exec_20261109_225307.txt (op 3 strips exec then
--     applies write-implies-read)
--   results/phase36_realargs/1490a_rx_to_rw_20261109_215813.txt (op 2 refuses to lower any of the
--     41 executable entries -- but those are not vnode entries, so the clip path never ran)
--   results/phase34_shm_race/932b_*.txt, 933a_*.txt (shm objects refcount correctly; a shm object
--     is OBJT_SWAP, not OBJT_VNODE)
--   probe 56o (fstat on /app0/eboot.bin: size 0x63192E, so 0x40000 is well inside the file)

print("=== PROBE 1513a: 548 op 3 CLIP OF A VNODE MAPPING ===")

local function N(v) if type(v) == "table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function es() local ok,s = pcall(function() return get_error_string() end) if ok and type(s)=="string" then return s end return "errno?" end
local function sgn(v)
    local h, l = 0, N(v)
    if type(v) == "table" and v.h then h = N(v.h); l = N(v.l) end
    if h >= 2147483648 then h = h - 4294967296 end
    if h == -1 and l >= 2147483648 then return l - 4294967296 end
    return h * 4294967296 + l
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end
    return nil
end
local function rdq(a)
    local lo, hi = rd(a), rd(a + 4)
    if lo == nil or hi == nil then return nil end
    return lo + hi * 4294967296
end
local function str_addr(s)
    local b = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(b + i - 1, s:byte(i)) end) end
    pcall(function() memory.write_byte(b + #s, 0) end)
    return b
end

local PID = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[0] pid=%d", PID))

local sa = memory.alloc(0x80)
for i = 0, 0x60, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa, uint64(1)) end)
for _, s in ipairs({5, 6, 7, 8, 12, 24, 25, 26, 30, 31}) do
    pcall(function() return mk(416)(uint64(s), uint64(sa), uint64(0)) end)
end

local ent  = memory.alloc(0x40)
local done = memory.alloc(0x10)

local function batch(flags, start, len, prot, op)
    for i = 0, 0x38 do pcall(function() memory.write_byte(ent + i, 0) end) end
    pcall(function() memory.write_qword(ent, uint64(start)) end)
    pcall(function() memory.write_qword(ent + 0x10, uint64(len)) end)
    pcall(function() memory.write_dword(ent + 0x18, uint64(prot)) end)
    pcall(function() memory.write_byte(ent + 0x1C, op) end)
    pcall(function() memory.write_dword(done, uint64(0xEEEEEEEE)) end)
    local ok, rv = pcall(function()
        return mk(548)(uint64(0), uint64(flags), uint64(ent), uint64(1), uint64(done), uint64(0))
    end)
    if not ok then return -999, 0 end
    return sgn(rv), N(memory.read_dword(done))
end

local rec = memory.alloc(0x30)
local function q547(addr)
    for i = 0, 0x2C, 4 do pcall(function() memory.write_dword(rec + i, uint64(0)) end) end
    local ok, rv = pcall(function() return mk(547)(uint64(addr), uint64(rec), uint64(0), uint64(0), uint64(0), uint64(0)) end)
    if not ok then return nil end
    if sgn(rv) ~= 0 then return nil end
    local s, e = rdq(rec), rdq(rec + 8)
    if s == nil or e == nil then return nil end
    return s, e, rd(rec + 0x10), rd(rec + 0x14)
end

local function show547(tag, a)
    local s, e, p, f = q547(a)
    if s == nil then
        print(string.format("   %s 547(0x%X): no entry", tag, a))
    else
        print(string.format("   %s 547(0x%X): start=0x%X end=0x%X len=0x%X prot=0x%X flags=0x%X",
            tag, a, s, e, e - s, p or 0, f or 0))
    end
end

local function mmap_at(addr, len, prot, flags, fd, off)
    local ok, v = pcall(function()
        return mk(477)(uint64(addr), uint64(len), uint64(prot), uint64(flags), uint64(fd), uint64(off))
    end)
    if not ok then return -999 end
    return sgn(v)
end

-- read 8 dwords starting at a + off, return "XXXXXXXX XXXXXXXX ..." or "FAULT"
local function peek(tag, base, off)
    local t = {}
    for i = 0, 7 do
        local v = rd(base + off + i * 4)
        if v == nil then return string.format("   %-22s +0x%05X: FAULT", tag, off) end
        t[#t + 1] = string.format("%08X", v)
    end
    return string.format("   %-22s +0x%05X: %s", tag, off, table.concat(t, " "))
end

--============================================================== [A] two mappings
print("")
print("[A] open /app0/eboot.bin O_RDONLY and map it twice")
local pathb = str_addr("/app0/eboot.bin")
local okf, fd = pcall(function() return mk(5)(uint64(pathb), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
fd = okf and sgn(fd) or -1
print(string.format("   open = %d %s", fd, fd < 0 and es() or ""))
if fd < 0 then print("   VERDICT: VOID -- cannot open the file") return end

local LEN = 0x40000
local A = mmap_at(0, LEN, 1, 1, fd, 0)
print(string.format("   map A = %s %s", A > 0x10000 and string.format("0x%X", A) or "FAILED",
    A <= 0x10000 and es() or ""))
if A <= 0x10000 then print("   VERDICT: VOID -- cannot map the file") return end

local B = mmap_at(0, LEN, 1, 1, fd, 0)
print(string.format("   map B = %s", B > 0x10000 and string.format("0x%X", B) or "FAILED"))
if B <= 0x10000 then print("   VERDICT: VOID -- second mapping failed") return end

print(peek("A", A, 0))
print(peek("B", B, 0))
show547("A", A)

local a0, b0 = rd(A), rd(B)
if a0 == nil or b0 == nil then print("   VERDICT: VOID -- a mapping is not readable") return end
if a0 ~= b0 then
    print(string.format("   NOTE: the two mappings already differ (0x%08X vs 0x%08X)", a0, b0))
end

--============================================================== [B] carve the vnode entry
print("")
print("[B] 548 op3 MAP_FIXED carve of A+0x10000 inside the vnode entry")
local rv, proc = batch(0x10, A + 0x10000, 0x4000, 3, 3)
print(string.format("   rv=%d processed=%d %s", rv, proc, rv == -1 and es() or ""))
if proc ~= 1 then
    print("   VERDICT: op 3 refused a vnode entry -- nothing was clipped")
    return
end
print(string.format("   requested 0x%X, landed 0x%X%s", A + 0x10000, rv,
    rv == A + 0x10000 and "" or "  (NOT the requested address -- fill is not applied here)"))

--============================================================== [C] is B disturbed?
print("")
print("[C] after the carve: A below, A inside, A above, B throughout")
print(peek("A", A, 0))
print(peek("A", A, 0x8000))
print(peek("A", A, 0x10000))
print(peek("A", A, 0x14000))
print(peek("A", A, 0x30000))
print(peek("B", B, 0))
print(peek("B", B, 0x8000))
print(peek("B", B, 0x10000))
print(peek("B", B, 0x30000))
show547("A below", A)
show547("A at   ", A + 0x10000)
show547("A above", A + 0x30000)
show547("B      ", B)

local bhead = rd(B)
local aabove = rd(A + 0x30000)
print(string.format("   B head after = 0x%08X (was 0x%08X); A above = 0x%08X",
    bhead or 0xDEAD, b0, aabove or 0xDEAD))

--============================================================== [D] A alone, carve again
print("")
print("[D] unmap B, then carve A a second time -- A is now the only reference")
local mm = sgn(mk(73)(uint64(B), uint64(LEN), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("   munmap B = %d", mm))
local rv2, proc2 = batch(0x10, A + 0x20000, 0x4000, 3, 3)
print(string.format("   second carve rv=%d processed=%d %s", rv2, proc2, rv2 == -1 and es() or ""))
print(peek("A", A, 0))
print(peek("A", A, 0x20000))
print(peek("A", A, 0x24000))
show547("A below2", A)
show547("A above2", A + 0x30000)

--============================================================== [E] file intact?
print("")
print("[E] unmap A, reopen the file, read the same bytes back")
local mm2 = sgn(mk(73)(uint64(A), uint64(LEN), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("   munmap A = %d", mm2))
local okf2, fd2 = pcall(function() return mk(5)(uint64(pathb), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)) end)
fd2 = okf2 and sgn(fd2) or -1
print(string.format("   reopen = %d %s", fd2, fd2 < 0 and es() or ""))
if fd2 >= 0 then
    local buf = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do pcall(function() memory.write_dword(buf + i, uint64(0)) end) end
    local okr, rr = pcall(function() return mk(3)(uint64(fd2), uint64(buf), uint64(0x40), uint64(0), uint64(0), uint64(0)) end)
    rr = okr and sgn(rr) or -999
    print(string.format("   read = %d %s", rr, rr < 0 and es() or ""))
    local t = {}
    for i = 0, 3 do t[#t + 1] = string.format("%08X", rd(buf + i * 4) or 0) end
    print(string.format("   file head: %s", table.concat(t, " ")))
    if rr == 0x40 and rd(buf) == a0 then
        print("   file bytes match what the mapping showed -- the file was not modified")
    elseif rr == 0x40 then
        print(string.format("   NOTE: file head 0x%08X differs from the mapping's 0x%08X", rd(buf) or 0, a0))
    end
end

print("")
local final_pid = N(mk(20)(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))
print(string.format("[Z] alive pid=%d (was %d)", final_pid, PID))
print("=== PROBE 1513a COMPLETE ===")
