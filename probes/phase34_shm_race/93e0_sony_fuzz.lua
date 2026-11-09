-- CRASH_CLASS: MODERATE
-- PROBE 93e0: Sony syscall deep argument fuzzing
--
-- Many Sony syscalls return -1 with zero args but work with proper structs.
-- Fuzz 596, 585, 606, 640, 572 with structured pointer arguments.
-- Also try unexplored syscalls in 540-570 range with real args.

print("=== PROBE 93e0: SONY SYSCALL DEEP FUZZ ===")
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
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local out = memory.alloc(0x400)
local out2 = memory.alloc(0x400)

local function sentinel_fill(buf, sz, tag)
    for i = 0, sz - 4, 4 do wd(N(buf) + i, tag) end
end

local function count_changed(buf, sz, tag)
    local c = 0
    for i = 0, sz - 4, 4 do
        local v = rd(N(buf) + i)
        if v and v ~= tag then c = c + 1 end
    end
    return c
end

local function scan_kptr(buf, sz)
    local kp = 0
    for i = 0, sz - 8, 8 do
        local lo = rd(N(buf) + i) or 0
        local hi = rd(N(buf) + i + 4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then kp = kp + 1 end
    end
    return kp
end

-- ======== SECTION A: sys 596 ========
print("--- A: sys 596 deep fuzz ---")
-- Try: (cmd, outbuf, size), (outbuf, cmd, size), (pid, cmd, outbuf, size)
local patterns_596 = {
    function(cmd) return mk(596)(uint64(cmd), uint64(N(out)), uint64(0x200), uint64(0), uint64(0)) end,
    function(cmd) return mk(596)(uint64(N(out)), uint64(cmd), uint64(0x200), uint64(0), uint64(0)) end,
    function(cmd) return mk(596)(uint64(N(out)), uint64(0x200), uint64(cmd), uint64(0), uint64(0)) end,
    function(cmd) return mk(596)(uint64(pid_val), uint64(cmd), uint64(N(out)), uint64(0x200), uint64(0)) end,
}
for pi, pfn in ipairs(patterns_596) do
    for cmd = 0, 30 do
        sentinel_fill(out, 0x200, 0xAA000000 + cmd)
        local ok_f, rv_f = pcall(pfn, cmd)
        local ret = ok_f and N(rv_f) or -999
        if ret >= 0x80000000 then ret = ret - 0x100000000 end
        local ch = count_changed(out, 0x200, 0xAA000000 + cmd)
        local kp = scan_kptr(out, 0x200)
        if ret ~= -1 or ch > 0 then
            print(string.format("  p%d cmd=%d: ret=%d ch=%d kp=%d", pi, cmd, ret, ch, kp))
        end
        if not alive() then print("DEAD"); return end
    end
end

-- ======== SECTION B: sys 585 ========
print("")
print("--- B: sys 585 deep fuzz ---")
for _, pid in ipairs({0, 1, pid_val}) do
    for cmd = 0, 20 do
        sentinel_fill(out, 0x200, 0xBB000000)
        local ok_f, rv_f = pcall(function()
            return mk(585)(uint64(pid), uint64(cmd), uint64(N(out)), uint64(0x200), uint64(0))
        end)
        local ret = ok_f and N(rv_f) or -999
        if ret >= 0x80000000 then ret = ret - 0x100000000 end
        local ch = count_changed(out, 0x200, 0xBB000000)
        if ret ~= -1 or ch > 0 then
            print(string.format("  pid=%d cmd=%d: ret=%d ch=%d kp=%d", pid, cmd, ret, ch, scan_kptr(out, 0x200)))
        end
    end
end

-- ======== SECTION C: sys 606 ========
print("")
print("--- C: sys 606 deep fuzz ---")
for cmd = 0, 40 do
    sentinel_fill(out, 0x200, 0xCC000000 + cmd)
    local ok_f, rv_f = pcall(function()
        return mk(606)(uint64(cmd), uint64(N(out)), uint64(0x200), uint64(pid_val), uint64(0))
    end)
    local ret = ok_f and N(rv_f) or -999
    if ret >= 0x80000000 then ret = ret - 0x100000000 end
    local ch = count_changed(out, 0x200, 0xCC000000 + cmd)
    if ret ~= -1 or ch > 0 then
        print(string.format("  cmd=%d: ret=%d ch=%d kp=%d", cmd, ret, ch, scan_kptr(out, 0x200)))
    end
    if not alive() then print("DEAD"); return end
end

-- ======== SECTION D: sys 640 ========
print("")
print("--- D: sys 640 deep fuzz ---")
for cmd = 0, 20 do
    for handle = 0, 5 do
        sentinel_fill(out, 0x200, 0xDD000000 + cmd)
        local ok_f, rv_f = pcall(function()
            return mk(640)(uint64(cmd), uint64(handle), uint64(N(out)), uint64(0x200), uint64(0))
        end)
        local ret = ok_f and N(rv_f) or -999
        if ret >= 0x80000000 then ret = ret - 0x100000000 end
        local ch = count_changed(out, 0x200, 0xDD000000 + cmd)
        if ret ~= -1 or ch > 0 then
            print(string.format("  cmd=%d h=%d: ret=%d ch=%d kp=%d", cmd, handle, ret, ch, scan_kptr(out, 0x200)))
        end
    end
    if not alive() then print("DEAD"); return end
end

-- ======== SECTION E: unexplored 540-570 range ========
print("")
print("--- E: syscalls 540-570 with struct args ---")
-- These are Sony syscalls. Many return -1 with zeros.
-- Try with: (outbuf, size, 0, 0, 0), (0, outbuf, size, 0, 0), (cmd, outbuf, size, 0, 0)
local tested = {533,534,535,536,537,538,540,544,547,548,549,557,558,559,560,561,563,564,565,566,567,570,572}
for _, sc in ipairs(tested) do
    -- Skip known lethal: 561 kills
    if sc ~= 561 then
        sentinel_fill(out, 0x200, 0xEE000000 + sc)
        -- Pattern: (outbuf, size)
        local ok_f, rv_f = pcall(function()
            return mk(sc)(uint64(N(out)), uint64(0x200), uint64(0), uint64(0), uint64(0))
        end)
        local ret = ok_f and N(rv_f) or -999
        if ret >= 0x80000000 then ret = ret - 0x100000000 end
        local ch = count_changed(out, 0x200, 0xEE000000 + sc)
        if ret ~= -1 or ch > 0 then
            print(string.format("  sc=%d (out,sz): ret=%d ch=%d kp=%d", sc, ret, ch, scan_kptr(out, 0x200)))
        end

        -- Pattern: (1, outbuf, size)
        sentinel_fill(out, 0x200, 0xFF000000 + sc)
        local ok_f2, rv_f2 = pcall(function()
            return mk(sc)(uint64(1), uint64(N(out)), uint64(0x200), uint64(0), uint64(0))
        end)
        local ret2 = ok_f2 and N(rv_f2) or -999
        if ret2 >= 0x80000000 then ret2 = ret2 - 0x100000000 end
        local ch2 = count_changed(out, 0x200, 0xFF000000 + sc)
        if ret2 ~= -1 or ch2 > 0 then
            print(string.format("  sc=%d (1,out,sz): ret=%d ch=%d kp=%d", sc, ret2, ch2, scan_kptr(out, 0x200)))
        end
        if not alive() then print("DEAD at sc=" .. sc); return end
    end
end

-- ======== SECTION F: sys 654/655/656/658/659/660 with real args ========
print("")
print("--- F: sys 654-660 with struct args ---")
for sc = 654, 660 do
    sentinel_fill(out, 0x200, 0x11000000 + sc)
    -- (outbuf, size)
    local ok_f, rv_f = pcall(function()
        return mk(sc)(uint64(N(out)), uint64(0x200), uint64(0), uint64(0), uint64(0))
    end)
    local ret = ok_f and N(rv_f) or -999
    if ret >= 0x80000000 then ret = ret - 0x100000000 end
    local ch = count_changed(out, 0x200, 0x11000000 + sc)
    if ret ~= -1 or ch > 0 then
        print(string.format("  sc=%d: ret=%d ch=%d kp=%d", sc, ret, ch, scan_kptr(out, 0x200)))
    end

    -- (cmd=0, handle=0, outbuf, size)
    sentinel_fill(out, 0x200, 0x22000000 + sc)
    local ok_f2, rv_f2 = pcall(function()
        return mk(sc)(uint64(0), uint64(0), uint64(N(out)), uint64(0x200), uint64(0))
    end)
    local ret2 = ok_f2 and N(rv_f2) or -999
    if ret2 >= 0x80000000 then ret2 = ret2 - 0x100000000 end
    local ch2 = count_changed(out, 0x200, 0x22000000 + sc)
    if ret2 ~= -1 or ch2 > 0 then
        print(string.format("  sc=%d (0,0,out,sz): ret=%d ch=%d kp=%d", sc, ret2, ch2, scan_kptr(out, 0x200)))
    end
    if not alive() then print("DEAD at sc=" .. sc); return end
end

print("")
print("alive=" .. tostring(alive()))
print("=== 93e0 COMPLETE ===")
