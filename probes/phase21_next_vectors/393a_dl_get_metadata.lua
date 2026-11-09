-- CRASH_CLASS: MODERATE
-- PROBE 393a: sys 604 dl_get_metadata — last untested Sony syscall
--
-- 604 has narg=5, 13.60 thunk body not captured.
-- Name suggests dynlib metadata. Try module handles × type selectors
-- with output buffer, scan for kernel pointers.
-- Also test: what if arg layout is (type, handle, buf, len, flags)?

print("=== PROBE 393a: sys 604 dl_get_metadata ===")
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

local function zero_buf(addr, len)
    for i = 0, len - 4, 4 do wd(N(addr) + i, 0) end
end
local function fill_sent(buf, len)
    for i = 0, len - 4, 4 do wd(N(buf) + i, 0xDEADDEAD) end
end

-- Ignore SIGSYS
local act = memory.alloc(0x40)
zero_buf(act, 0x40)
wq(N(act), uint64(1))
pcall(function() mk(416)(uint64(12), act, uint64(0)) end)

-- Kptr scan using ONLY read_dword (read_qword corrupts stdout)
local function scan_kptrs(base, len, label)
    local baddr = N(base)
    local mod = 0
    local kptrs = 0
    for off = 0, len - 4, 4 do
        local d = rd(baddr + off)
        if d ~= nil and d ~= 0xDEADDEAD and d ~= 0 then mod = mod + 1 end
    end
    for off = 0, len - 8, 8 do
        local lo = rd(baddr + off)
        local hi = rd(baddr + off + 4)
        if hi and hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            kptrs = kptrs + 1
            if kptrs <= 5 then
                print(string.format("  %s +0x%03X: KPTR hi=%08X lo=%08X",
                    label, off, hi, lo or 0))
            end
        end
    end
    return mod, kptrs
end

-- Get module handles via dynlib_get_list(593 mode=1 equivalent)
-- Actually use sys 592 to get handle list
local handles = {}
local list_buf = memory.alloc(0x200)
local count_buf = memory.alloc(8)

-- Try getting handles from dynlib_get_info on known handles
-- Handle 0 = self/eboot, handle 1+ = loaded modules
-- 593 with mode 1 returns handle list
zero_buf(list_buf, 0x200)
wd(N(count_buf), 64)
local ok_gl, rv_gl = pcall(function()
    return mk(592)(list_buf, uint64(64), count_buf)
end)
local gl_ret = ok_gl and N(rv_gl) or -999
local gl_count = rd(N(count_buf)) or 0
print(string.format("dynlib_get_list(592): ret=%d count=%d", gl_ret, gl_count))

if gl_ret == 0 and gl_count > 0 then
    local max_h = gl_count
    if max_h > 8 then max_h = 8 end
    for i = 0, max_h - 1 do
        local h = rd(N(list_buf) + i * 4) or 0
        if h ~= 0 then
            handles[#handles + 1] = h
        end
    end
end

-- Always include handle 0 (self) and 0xFFFF
if #handles == 0 then handles = {0, 1, 2} end
table.insert(handles, 0)
table.insert(handles, 0xFFFF)

print(string.format("Testing %d handles", #handles))
if not alive() then print("DEAD [setup]"); return end
print("")

-- ===================================================================
-- [A] Layout 1: (handle, type, outbuf, outlen, flags)
-- Like 593/649 pattern
-- ===================================================================
print("[A] layout: (handle, type, buf, len, 0)")

local out = memory.alloc(0x400)
local types_hit = 0

for _, h in ipairs(handles) do
    if not alive() then break end
    for t = 0, 20 do
        if not alive() then break end
        fill_sent(out, 0x400)
        local ok_a, rv_a = pcall(function()
            return mk(604)(uint64(h), uint64(t), out, uint64(0x400), uint64(0))
        end)
        local ret = ok_a and N(rv_a) or -999
        if ret >= 0 then
            local m, k = scan_kptrs(out, 0x400, string.format("h%d/t%d", h, t))
            print(string.format("  604(h=%d, t=%d): ret=%d mod=%d kptrs=%d",
                h, t, ret, m, k))
            types_hit = types_hit + 1
            -- Print first 32 bytes if data returned
            if m > 0 then
                local hex = "   "
                for off = 0, 28, 4 do
                    local d = rd(N(out) + off)
                    if d then hex = hex .. string.format(" %08X", d) end
                end
                print(hex)
            end
        end
    end
    -- Only report first non-responding handle once
    if types_hit == 0 and h == handles[1] then
        print(string.format("  h=%d: all types 0-20 returned <0", h))
    end
end

if types_hit == 0 then print("  Layout A: all -1") end
if not alive() then print("DEAD [A]"); return end
print("")

-- ===================================================================
-- [B] Layout 2: (type, handle, outbuf, outlen, flags)
-- Reversed handle/type
-- ===================================================================
print("[B] layout: (type, handle, buf, len, 0)")

local types_hit_b = 0
for t = 0, 8 do
    if not alive() then break end
    for _, h in ipairs({0, 1, handles[1] or 0}) do
        if not alive() then break end
        fill_sent(out, 0x400)
        local ok_b, rv_b = pcall(function()
            return mk(604)(uint64(t), uint64(h), out, uint64(0x400), uint64(0))
        end)
        local ret = ok_b and N(rv_b) or -999
        if ret >= 0 then
            local m, k = scan_kptrs(out, 0x400, string.format("t%d/h%d", t, h))
            print(string.format("  604(t=%d, h=%d): ret=%d mod=%d kptrs=%d",
                t, h, ret, m, k))
            types_hit_b = types_hit_b + 1
        end
    end
end

if types_hit_b == 0 then print("  Layout B: all -1") end
if not alive() then print("DEAD [B]"); return end
print("")

-- ===================================================================
-- [C] Layout 3: (handle, outbuf, outlen, type, flags)
-- buf before type
-- ===================================================================
print("[C] layout: (handle, buf, len, type, 0)")

local types_hit_c = 0
for _, h in ipairs({0, 1, handles[1] or 0}) do
    if not alive() then break end
    for t = 0, 8 do
        if not alive() then break end
        fill_sent(out, 0x400)
        local ok_c, rv_c = pcall(function()
            return mk(604)(uint64(h), out, uint64(0x400), uint64(t), uint64(0))
        end)
        local ret = ok_c and N(rv_c) or -999
        if ret >= 0 then
            local m, k = scan_kptrs(out, 0x400, string.format("h%d/t%d", h, t))
            print(string.format("  604(h=%d, buf, len, t=%d): ret=%d mod=%d kptrs=%d",
                h, t, ret, m, k))
            types_hit_c = types_hit_c + 1
        end
    end
end

if types_hit_c == 0 then print("  Layout C: all -1") end
if not alive() then print("DEAD [C]"); return end
print("")

-- ===================================================================
-- [D] Layout 4: pointer-to-struct pattern
-- Some Sony calls take a pointer to a struct with size at +0
-- ===================================================================
print("[D] struct pattern")

local stbuf = memory.alloc(0x200)
local types_hit_d = 0

for _, h in ipairs({0, 1, handles[1] or 0}) do
    if not alive() then break end

    -- Pattern: arg0=handle, arg1=ptr_to_struct with size at +0
    zero_buf(stbuf, 0x200)
    wd(N(stbuf), 0x200)  -- size field
    fill_sent(out, 0x400)

    local ok_d, rv_d = pcall(function()
        return mk(604)(uint64(h), stbuf, out, uint64(0x400), uint64(0))
    end)
    local ret = ok_d and N(rv_d) or -999
    if ret >= 0 then
        local m, k = scan_kptrs(out, 0x400, string.format("struct/h%d", h))
        print(string.format("  604(h=%d, struct, buf): ret=%d mod=%d kptrs=%d",
            h, ret, m, k))
        types_hit_d = types_hit_d + 1
    end

    -- Pattern: arg0=ptr with size at +0, everything else
    zero_buf(stbuf, 0x200)
    wd(N(stbuf), 0x160)  -- dynlib_info size
    fill_sent(out, 0x400)

    local ok_d2, rv_d2 = pcall(function()
        return mk(604)(stbuf, uint64(h), out, uint64(0x400), uint64(0))
    end)
    local ret2 = ok_d2 and N(rv_d2) or -999
    if ret2 >= 0 then
        local m, k = scan_kptrs(out, 0x400, string.format("struct2/h%d", h))
        print(string.format("  604(struct, h=%d, buf): ret=%d mod=%d kptrs=%d",
            h, ret2, m, k))
        types_hit_d = types_hit_d + 1
    end
end

if types_hit_d == 0 then print("  Layout D: all -1") end
if not alive() then print("DEAD [D]"); return end
print("")

-- ===================================================================
-- [E] Bare args — what does 604 do with simple scalars?
-- ===================================================================
print("[E] scalar sweep")

local scalars = {
    {0, 0, 0, 0, 0},
    {1, 0, 0, 0, 0},
    {0, 1, 0, 0, 0},
    {0, 0, 1, 0, 0},
    {0, 0, 0, 1, 0},
    {0, 0, 0, 0, 1},
    {pid_val, 0, 0, 0, 0},
    {0, pid_val, 0, 0, 0},
}

for _, args in ipairs(scalars) do
    if not alive() then break end
    local ok_e, rv_e = pcall(function()
        return mk(604)(uint64(args[1]), uint64(args[2]),
            uint64(args[3]), uint64(args[4]), uint64(args[5]))
    end)
    local ret = ok_e and N(rv_e) or -999
    if ret ~= -1 then
        print(string.format("  604(%d,%d,%d,%d,%d): ret=%d",
            args[1], args[2], args[3], args[4], args[5], ret))
    end
end

-- Check if ALL returned -1
local any_hit = false
for _, args in ipairs(scalars) do
    if not alive() then break end
    local ok_e2, rv_e2 = pcall(function()
        return mk(604)(uint64(args[1]), uint64(args[2]),
            uint64(args[3]), uint64(args[4]), uint64(args[5]))
    end)
    if ok_e2 and N(rv_e2) >= 0 then any_hit = true end
end
if not any_hit then print("  all scalar combos: -1") end

if not alive() then print("DEAD [E]"); return end
print("")

-- ===================================================================
-- [F] debug_init follow-up: 560(1) returns 0, what's unlocked?
-- Try 604 after debug_init, and also try sys 561/562/656 post-init
-- ===================================================================
print("[F] post-debug_init")

local ok_di, rv_di = pcall(function() return mk(560)(uint64(1)) end)
print(string.format("  debug_init(1): ret=%d", ok_di and N(rv_di) or -999))

if (ok_di and N(rv_di) or -1) == 0 then
    -- Retry 604 after debug_init
    fill_sent(out, 0x400)
    local ok_f, rv_f = pcall(function()
        return mk(604)(uint64(0), uint64(0), out, uint64(0x400), uint64(0))
    end)
    local ret_f = ok_f and N(rv_f) or -999
    print(string.format("  604 post-init: ret=%d", ret_f))
    if ret_f >= 0 then
        local m, k = scan_kptrs(out, 0x400, "post-init")
        print(string.format("    mod=%d kptrs=%d", m, k))
    end

    -- Try 656 (debug read?) post-init
    fill_sent(out, 0x400)
    local ok_656, rv_656 = pcall(function()
        return mk(656)(uint64(0), out, uint64(0x400))
    end)
    print(string.format("  656 post-init: ret=%d", ok_656 and N(rv_656) or -999))
    if (ok_656 and N(rv_656) or -1) >= 0 then
        local m, k = scan_kptrs(out, 0x400, "656")
        print(string.format("    mod=%d kptrs=%d", m, k))
    end

    -- Try reading process info post-init
    fill_sent(out, 0x400)
    local ok_601, rv_601 = pcall(function()
        return mk(601)(uint64(0x10), out, uint64(0x400))
    end)
    print(string.format("  601(0x10) post-init: ret=%d", ok_601 and N(rv_601) or -999))
end

if not alive() then print("DEAD [F]"); return end
print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 393a COMPLETE ===")
