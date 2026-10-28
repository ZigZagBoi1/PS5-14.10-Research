-- CRASH_CLASS: LOW
-- PROBE 75b: sys 572/598/659 deep output scan
--
-- 572 virtual_query: 2 copyout sites, NO gate (13.60 decode).
--     Returns 0 but writes nothing with (addr,buf,size) or (buf,cmd,size).
--     The handler is likely 5-arg: (outbuf, cmd, addr, size, flags).
-- 598 dynlib_get_proc_param: returns 0, writes 0x60 at +0. Full output unknown.
-- 659 dynlib_get_list2: returns 0, count=3. Handles differ from 593.

print("=== PROBE 75b: SYS 572/598/659 DEEP SCAN ===")
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
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Get some real addresses for 572 testing
local heap_buf = memory.alloc(0x4000)
local gpu_addr = nil
pcall(function()
    gpu_addr = mk(477)(uint64(0), uint64(16*0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
print("heap=" .. fmt(uint64(N(heap_buf))))
print("gpu=" .. (gpu_addr and fmt(gpu_addr) or "nil"))

-- Get eboot base
local info_buf = memory.alloc(0x200)
for off = 0, 0x1FF, 4 do wd(N(info_buf) + off, 0) end
wq(N(info_buf), uint64(0x160))
local sc593 = mk(593)
pcall(function() sc593(uint64(0), info_buf) end)
local eboot_lo = rd(N(info_buf) + 0x108) or 0
local eboot_hi = rd(N(info_buf) + 0x10C) or 0
local eboot = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo))
print("eboot=" .. fmt(eboot))

local sc572 = mk(572)
local sc598 = mk(598)
local sc659 = mk(659)
local total_kptrs = 0

-- ============================================================
-- [A] sys 572: exhaustive arg layout search
-- ============================================================
print("")
print("[A] sys 572 virtual_query — arg layout search")
local out = memory.alloc(0x200)
local test_addrs = {uint64(N(heap_buf)), gpu_addr, eboot}

local layouts = {
    -- (addr, outbuf, size) — 3-arg, original
    {name="addr,buf,sz", args=function(addr)
        return {addr, uint64(N(out)), uint64(0x100)}
    end},
    -- (outbuf, cmd, size) — 3-arg, alternate
    {name="buf,0,sz", args=function(addr)
        return {uint64(N(out)), uint64(0), uint64(0x100)}
    end},
    -- (outbuf, cmd, addr, size, flags) — 5-arg suggested
    {name="buf,0,addr,sz,0", args=function(addr)
        return {uint64(N(out)), uint64(0), addr, uint64(0x100), uint64(0)}
    end},
    {name="buf,1,addr,sz,0", args=function(addr)
        return {uint64(N(out)), uint64(1), addr, uint64(0x100), uint64(0)}
    end},
    {name="buf,2,addr,sz,0", args=function(addr)
        return {uint64(N(out)), uint64(2), addr, uint64(0x100), uint64(0)}
    end},
    -- (addr, outbuf, size, cmd, flags) — alt 5-arg
    {name="addr,buf,sz,0,0", args=function(addr)
        return {addr, uint64(N(out)), uint64(0x100), uint64(0), uint64(0)}
    end},
    {name="addr,buf,sz,1,0", args=function(addr)
        return {addr, uint64(N(out)), uint64(0x100), uint64(1), uint64(0)}
    end},
    -- (addr, size, outbuf, outsz, flags) — reordered
    {name="addr,sz,buf,outsz,0", args=function(addr)
        return {addr, uint64(0x4000), uint64(N(out)), uint64(0x100), uint64(0)}
    end},
    -- (cmd, addr, outbuf, outsz) — cmd-first 4-arg
    {name="0,addr,buf,outsz", args=function(addr)
        return {uint64(0), addr, uint64(N(out)), uint64(0x100)}
    end},
    {name="1,addr,buf,outsz", args=function(addr)
        return {uint64(1), addr, uint64(N(out)), uint64(0x100)}
    end},
}

for _, layout in ipairs(layouts) do
    local best_mod = 0
    local best_ret = -999
    local found_kptr = false

    for _, addr in ipairs(test_addrs) do
        if addr == nil then break end
        for off = 0, 0x1FC, 4 do wd(N(out) + off, 0xDEAD) end
        local a = layout.args(addr)
        local ret = -999
        pcall(function()
            if #a == 3 then
                ret = N(sc572(a[1], a[2], a[3]))
            elseif #a == 4 then
                ret = N(sc572(a[1], a[2], a[3], a[4]))
            else
                ret = N(sc572(a[1], a[2], a[3], a[4], a[5]))
            end
        end)

        local modified = 0
        for off = 0, 0xFC, 4 do
            if rd(N(out) + off) ~= 0xDEAD then modified = modified + 1 end
        end

        if modified > best_mod then best_mod = modified end
        if ret ~= -999 then best_ret = ret end

        if modified > 0 then
            for off = 0, 0xF8, 8 do
                local q = rq(uint64(N(out) + off))
                if q and is_kptr(q) then
                    found_kptr = true
                    total_kptrs = total_kptrs + 1
                    print(string.format("  *** %s +0x%02X: KPTR %s ***", layout.name, off, fmt(q)))
                end
            end
        end
    end

    if best_mod > 0 or best_ret ~= -999 then
        print(string.format("  %-20s ret=%d mod=%d kptr=%s",
            layout.name, best_ret, best_mod, tostring(found_kptr)))
    end

    if not alive() then print("DEAD during 572 layout " .. layout.name); return end
end

-- ============================================================
-- [B] sys 572 with specific cmds 0-10 on the best layout
-- ============================================================
print("")
print("[B] sys 572 cmd sweep (5-arg: buf,cmd,addr,sz,0)")
local test_addr = uint64(N(heap_buf))
for cmd = 0, 10 do
    for off = 0, 0x1FC, 4 do wd(N(out) + off, 0xDEAD) end
    local ret = -999
    pcall(function()
        ret = N(sc572(uint64(N(out)), uint64(cmd), test_addr, uint64(0x100), uint64(0)))
    end)
    local modified = 0
    for off = 0, 0xFC, 4 do
        if rd(N(out) + off) ~= 0xDEAD then modified = modified + 1 end
    end

    if ret ~= -999 or modified > 0 then
        print(string.format("  cmd=%d ret=%d modified=%d", cmd, ret, modified))
        if modified > 0 then
            -- Dump first 64 bytes
            for off = 0, 56, 8 do
                local q = rq(uint64(N(out) + off))
                if q then
                    print(string.format("    +0x%02X: %s%s", off, fmt(q),
                        is_kptr(q) and " ***KPTR***" or ""))
                    if is_kptr(q) then total_kptrs = total_kptrs + 1 end
                end
            end
        end
    end

    if not alive() then print("DEAD at cmd=" .. cmd); return end
end

-- ============================================================
-- [C] sys 598 dynlib_get_proc_param deep scan
-- ============================================================
print("")
print("[C] sys 598 dynlib_get_proc_param — full output scan")
local proc_buf = memory.alloc(0x200)

-- Try with handle 0 (eboot)
for off = 0, 0x1FC, 4 do wd(N(proc_buf) + off, 0xDEAD) end
local ret598 = -999
pcall(function() ret598 = N(sc598(uint64(0), proc_buf)) end)
local mod598 = 0
for off = 0, 0x1FC, 4 do
    if rd(N(proc_buf) + off) ~= 0xDEAD then mod598 = mod598 + 1 end
end
print(string.format("  598(0,buf): ret=%d modified=%d", ret598, mod598))

if mod598 > 0 then
    -- Dump all modified qwords
    for off = 0, 0x1F8, 8 do
        local q = rq(uint64(N(proc_buf) + off))
        local h, l = get_hi_lo(q)
        if h ~= 0xDEADDEAD then
            print(string.format("    +0x%03X: %s%s", off, fmt(q),
                is_kptr(q) and " ***KPTR***" or ""))
            if is_kptr(q) then total_kptrs = total_kptrs + 1 end
        end
    end
end

-- Try 2-arg: 598(outbuf, out_size_ptr)
local sz_ptr = memory.alloc(16)
wq(N(sz_ptr), uint64(0x200))
for off = 0, 0x1FC, 4 do wd(N(proc_buf) + off, 0xDEAD) end
pcall(function() ret598 = N(sc598(proc_buf, sz_ptr)) end)
mod598 = 0
for off = 0, 0x1FC, 4 do
    if rd(N(proc_buf) + off) ~= 0xDEAD then mod598 = mod598 + 1 end
end
local out_sz = rd(N(sz_ptr)) or 0
print(string.format("  598(buf,szp): ret=%d modified=%d sz=%d", ret598, mod598, out_sz))
if mod598 > 0 and mod598 ~= 128 then
    for off = 0, math.min(out_sz, 0x100) - 1, 8 do
        local q = rq(uint64(N(proc_buf) + off))
        if q and is_kptr(q) then
            total_kptrs = total_kptrs + 1
            print(string.format("    +0x%02X: KPTR %s", off, fmt(q)))
        end
    end
end

-- Try 3-arg: 598(handle, outbuf, outsz)
for off = 0, 0x1FC, 4 do wd(N(proc_buf) + off, 0xDEAD) end
pcall(function() ret598 = N(sc598(uint64(0), proc_buf, uint64(0x200))) end)
mod598 = 0
for off = 0, 0x1FC, 4 do
    if rd(N(proc_buf) + off) ~= 0xDEAD then mod598 = mod598 + 1 end
end
print(string.format("  598(0,buf,0x200): ret=%d modified=%d", ret598, mod598))

if not alive() then print("DEAD after [C]"); return end

-- ============================================================
-- [D] sys 659 dynlib_get_list2 — full handle list + kernel scan
-- ============================================================
print("")
print("[D] sys 659 dynlib_get_list2 — full output")
local list_buf = memory.alloc(0x200)
local count_buf = memory.alloc(8)

-- Shape: (handles_out, capacity, count_out) per ATTACK_SURFACE
for off = 0, 0x1FC, 4 do wd(N(list_buf) + off, 0xDEAD) end
wd(N(count_buf), 0)
local ret659 = -999
pcall(function() ret659 = N(sc659(list_buf, uint64(64), count_buf)) end)
local count659 = rd(N(count_buf)) or 0
print(string.format("  659(buf,64,&cnt): ret=%d count=%d", ret659, count659))

if count659 > 0 then
    for i = 0, math.min(count659 - 1, 63) do
        local handle = rd(N(list_buf) + i * 4) or 0
        print(string.format("    handle[%d] = 0x%X", i, handle))
    end
    -- Scan beyond count for overcopy
    for off = count659 * 4, 0x100, 8 do
        local q = rq(uint64(N(list_buf) + off))
        if q and is_kptr(q) then
            total_kptrs = total_kptrs + 1
            print(string.format("    *** overcopy +0x%02X: KPTR %s ***", off, fmt(q)))
        end
    end
end

-- Try handles from 659 with 593 to see if they reveal different data
if count659 > 0 then
    print("  Testing 659 handles with 593:")
    for i = 0, math.min(count659 - 1, 5) do
        local h = rd(N(list_buf) + i * 4) or 0
        for off = 0, 0x1FF, 4 do wd(N(info_buf) + off, 0) end
        wq(N(info_buf), uint64(0x160))
        local ret = -1
        pcall(function() ret = N(sc593(uint64(h), info_buf)) end)
        print(string.format("    593(h=0x%X): ret=%d", h, ret))
        if ret == 0 then
            -- Scan for kernel pointers
            for off = 8, 0x158, 8 do
                local q = rq(uint64(N(info_buf) + off))
                if q and is_kptr(q) then
                    total_kptrs = total_kptrs + 1
                    print(string.format("      +0x%03X: KPTR %s", off, fmt(q)))
                end
            end
        end
    end
end

if not alive() then print("DEAD after [D]"); return end

-- ============================================================
-- [E] 638/639 time conversion — does copyout contain anything interesting?
-- ============================================================
print("")
print("[E] sys 638/639 time conversion output scan")
local sc638 = mk(638)
local sc639 = mk(639)
local time_buf = memory.alloc(0x100)

-- 638 utc_to_localtime: try (timestamp, outbuf, size)
for off = 0, 0xFC, 4 do wd(N(time_buf) + off, 0xDEAD) end
local ret638 = -999
pcall(function() ret638 = N(sc638(uint64(1729900000), time_buf, uint64(0x40))) end)
local mod638 = 0
for off = 0, 0x3C, 4 do
    if rd(N(time_buf) + off) ~= 0xDEAD then mod638 = mod638 + 1 end
end
print(string.format("  638(ts,buf,0x40): ret=%d modified=%d", ret638, mod638))
if mod638 > 0 then
    for off = 0, 0x38, 8 do
        local q = rq(uint64(N(time_buf) + off))
        if q and is_kptr(q) then
            total_kptrs = total_kptrs + 1
            print(string.format("    +0x%02X: KPTR %s", off, fmt(q)))
        end
    end
end

-- Try 1-arg: 638(outbuf)
for off = 0, 0xFC, 4 do wd(N(time_buf) + off, 0xDEAD) end
pcall(function() ret638 = N(sc638(time_buf)) end)
mod638 = 0
for off = 0, 0x3C, 4 do
    if rd(N(time_buf) + off) ~= 0xDEAD then mod638 = mod638 + 1 end
end
print(string.format("  638(buf): ret=%d modified=%d", ret638, mod638))

-- Try 2-arg: 638(timestamp, outbuf)
for off = 0, 0xFC, 4 do wd(N(time_buf) + off, 0xDEAD) end
pcall(function() ret638 = N(sc638(uint64(1729900000), time_buf)) end)
mod638 = 0
for off = 0, 0x3C, 4 do
    if rd(N(time_buf) + off) ~= 0xDEAD then mod638 = mod638 + 1 end
end
print(string.format("  638(ts,buf): ret=%d modified=%d", ret638, mod638))
if mod638 > 0 then
    for off = 0, 0x38, 4 do
        local v = rd(N(time_buf) + off) or 0
        if v ~= 0xDEAD and v ~= 0 then
            print(string.format("    +0x%02X: 0x%08X (%d)", off, v, v))
        end
    end
end

-- ============================================================
-- [F] SUMMARY
-- ============================================================
print("")
print("[F] SUMMARY")
print("  total kernel pointers: " .. total_kptrs)
print("  alive=" .. tostring(alive()))
print("")
print("=== PROBE 75b COMPLETE ===")
