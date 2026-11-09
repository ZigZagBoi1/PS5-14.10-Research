-- CRASH_CLASS: LOW
-- PROBE 93e1: Sony syscall safe fuzz (avoid known lethal calls)
--
-- Fuzz only known-safe Sony syscalls with structured args.
-- Skip: 561 (kills), 573 (kills), any sc that killed before.

print("=== PROBE 93e1: SONY SAFE FUZZ ===")
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

local sa = memory.alloc(32); wq(N(sa), uint64(1))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local out = memory.alloc(0x400)

local function sf(buf, sz, tag)
    for i = 0, sz - 4, 4 do wd(N(buf) + i, tag) end
end
local function cc(buf, sz, tag)
    local c = 0
    for i = 0, sz - 4, 4 do
        local v = rd(N(buf) + i)
        if v and v ~= tag then c = c + 1 end
    end
    return c
end
local function kp(buf, sz)
    local k = 0
    for i = 0, sz - 8, 8 do
        local lo = rd(N(buf) + i) or 0
        local hi = rd(N(buf) + i + 4) or 0
        if lo < 0 then lo = lo + 0x100000000 end
        if hi < 0 then hi = hi + 0x100000000 end
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then k = k + 1 end
    end
    return k
end

local function try_sc(sc, args, label)
    sf(out, 0x200, 0xAA000000 + sc)
    local ok_f, rv_f = pcall(function()
        return mk(sc)(args[1] or uint64(0), args[2] or uint64(0),
            args[3] or uint64(0), args[4] or uint64(0), args[5] or uint64(0))
    end)
    local ret = ok_f and N(rv_f) or -999
    if ret >= 0x80000000 then ret = ret - 0x100000000 end
    local ch = cc(out, 0x200, 0xAA000000 + sc)
    local k = kp(out, 0x200)
    if ret ~= -1 or ch > 0 then
        print(string.format("  %s sc=%d: ret=%d ch=%d kp=%d", label, sc, ret, ch, k))
        if ch > 0 and k > 0 then
            -- Dump first few changed values
            for i = 0, 0x1F8, 8 do
                local lo = rd(N(out) + i) or 0
                local hi = rd(N(out) + i + 4) or 0
                if lo < 0 then lo = lo + 0x100000000 end
                if hi < 0 then hi = hi + 0x100000000 end
                if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
                    print(string.format("    +0x%02X: 0x%08X%08X KPTR!", i, hi, lo))
                end
            end
        end
    end
    return alive()
end

-- ======== SECTION A: 596 with various arg layouts ========
print("--- A: sys 596 ---")
for cmd = 0, 30 do
    if not try_sc(596, {uint64(cmd), uint64(N(out)), uint64(0x200)}, "p1") then return end
end
for cmd = 0, 10 do
    if not try_sc(596, {uint64(N(out)), uint64(0x200), uint64(cmd)}, "p2") then return end
end

-- ======== SECTION B: 585 ========
print("")
print("--- B: sys 585 ---")
for _, pid in ipairs({0, pid_val}) do
    for cmd = 0, 15 do
        if not try_sc(585, {uint64(pid), uint64(cmd), uint64(N(out)), uint64(0x200)}, string.format("pid=%d", pid)) then return end
    end
end

-- ======== SECTION C: 606 ========
print("")
print("--- C: sys 606 ---")
for cmd = 0, 30 do
    if not try_sc(606, {uint64(cmd), uint64(N(out)), uint64(0x200), uint64(pid_val)}, "c") then return end
end

-- ======== SECTION D: 640 ========
print("")
print("--- D: sys 640 ---")
for cmd = 0, 15 do
    if not try_sc(640, {uint64(cmd), uint64(0), uint64(N(out)), uint64(0x200)}, "c") then return end
end

-- ======== SECTION E: 654-660 (skip 657 blockpool) ========
print("")
print("--- E: sys 654-660 ---")
for sc = 654, 660 do
    if sc ~= 657 then
        if not try_sc(sc, {uint64(N(out)), uint64(0x200)}, "p1") then return end
        if not try_sc(sc, {uint64(0), uint64(N(out)), uint64(0x200)}, "p2") then return end
    end
end

-- ======== SECTION F: 572 new arg patterns ========
print("")
print("--- F: sys 572 ---")
for cmd = 0, 10 do
    if not try_sc(572, {uint64(cmd), uint64(N(out)), uint64(0x200)}, "p1") then return end
end
-- Try with heap address as query target
local heap = memory.alloc(0x100)
for cmd = 0, 5 do
    if not try_sc(572, {uint64(N(heap)), uint64(cmd), uint64(N(out)), uint64(0x200)}, "heap") then return end
end

-- ======== SECTION G: try 610-620 range ========
print("")
print("--- G: sys 610-620 ---")
local safe_610 = {610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620}
for _, sc in ipairs(safe_610) do
    if not try_sc(sc, {uint64(N(out)), uint64(0x200)}, "p1") then return end
    if not try_sc(sc, {uint64(0), uint64(N(out)), uint64(0x200)}, "p2") then return end
    if not try_sc(sc, {uint64(pid_val), uint64(N(out)), uint64(0x200)}, "pid") then return end
end

print("")
print("alive=" .. tostring(alive()))
print("=== 93e1 COMPLETE ===")
