-- CRASH_CLASS: MODERATE
-- PROBE 122a: Clean physhm mapping hex dump + write test
--
-- ng643's 315a-321a probes had two bugs:
--   1. sgn() truncated 64-bit mmap addresses to 32 bits (315a/316a/318a)
--   2. tostring(uint64) produces binary output, not hex (all probes)
-- 321a fixed #1 but still suffered from #2.
--
-- This probe: open physhm fd, mmap it, dump content as clean hex,
-- test write + readback, and check if the data looks like kernel state.

print("=== PROBE 122a: PHYSHM HEXDUMP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt_q(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end
local function full_addr(v)
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return uint64(string.format("0x%X%08X", h, l))
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local sc629 = mk(629)
local sc_mmap = mk(477)
local sc_munmap = mk(73)
local sc_close = mk(6)

-- [A] Open physhm fd
print("[A] physhm_open(1, 2, 0, 0)")
local fd_raw = sc629(uint64(1), uint64(2), uint64(0), uint64(0))
local fd_h, fd_l = get_hi_lo(fd_raw)
if fd_h < 0 then fd_h = fd_h + 0x100000000 end
if fd_l < 0 then fd_l = fd_l + 0x100000000 end
local fd = fd_l
if fd_h == 0xFFFFFFFF or fd >= 0x80000000 then
    print("  FAILED: " .. fmt_q(fd_raw))
    return
end
print("  fd=" .. fd)

-- [B] mmap MAP_SHARED
print("")
print("[B] mmap(0x4000, PROT_RW, MAP_SHARED, fd, 0)")
local map_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
local map_h, map_l = get_hi_lo(map_raw)
if map_h < 0 then map_h = map_h + 0x100000000 end
if map_l < 0 then map_l = map_l + 0x100000000 end
if map_h >= 0xFFFF8000 then
    print("  FAILED: " .. fmt_q(map_raw))
    sc_close(uint64(fd))
    return
end
local base = full_addr(map_raw)
print("  base=" .. fmt_q(map_raw))

-- [C] Hex dump first 512 bytes (0x200)
print("")
print("[C] hex dump (first 0x200 bytes)")
for off = 0, 0x1F0, 0x10 do
    local line = string.format("  +%03X:", off)
    for w = 0, 12, 4 do
        local addr = base + uint64(off + w)
        local v = rd(addr)
        if v == nil then
            line = line .. " ????????"
        else
            if v < 0 then v = v + 0x100000000 end
            line = line .. string.format(" %08X", v)
        end
    end
    print(line)
end

-- Canary check
local c = N(native.fcall_with_rax(stub, 20))
if c ~= pid then print("DIED after read!") return end

-- [D] Check for kernel pointers in the mapping
print("")
print("[D] kernel pointer scan (first 0x1000)")
local kptr_count = 0
for off = 0, 0xFF8, 8 do
    local v = rq(base + uint64(off))
    if v ~= nil then
        local vh, vl = get_hi_lo(v)
        if vh < 0 then vh = vh + 0x100000000 end
        if vh >= 0xFFFF8000 and vh < 0xFFFFFFFF then
            kptr_count = kptr_count + 1
            if kptr_count <= 16 then
                print(string.format("  +%03X: %s", off, fmt_q(v)))
            end
        end
    end
end
print("  total kernel-range qwords: " .. kptr_count)

-- [E] Write test: save original, write pattern, readback, restore
print("")
print("[E] write test at +0x800")
local test_addr = base + uint64(0x800)
local orig_q = rq(test_addr)
print("  original: " .. fmt_q(orig_q))

local ok_w = pcall(function() memory.write_qword(test_addr, uint64(0xDEADBEEFCAFE1337)) end)
print("  write ok: " .. tostring(ok_w))

if ok_w then
    local readback = rq(test_addr)
    print("  readback: " .. fmt_q(readback))

    -- Restore
    if orig_q ~= nil then
        pcall(function() memory.write_qword(test_addr, orig_q) end)
        local restored = rq(test_addr)
        print("  restored: " .. fmt_q(restored))
    end
end

-- [F] Check arg3 variants: does arg3 select a different region?
print("")
print("[F] arg3 variants")
for _, a3 in ipairs({0, 1, 2, 3}) do
    local ok2, fd2_raw = pcall(function() return sc629(uint64(1), uint64(2), uint64(0), uint64(a3)) end)
    if ok2 then
        local fh2, fl2 = get_hi_lo(fd2_raw)
        if fh2 < 0 then fh2 = fh2 + 0x100000000 end
        if fl2 < 0 then fl2 = fl2 + 0x100000000 end
        if fh2 == 0xFFFFFFFF then
            print(string.format("  arg3=%d: FAILED", a3))
        else
            local fd2 = fl2
            local m2_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd2), uint64(0))
            local m2h, m2l = get_hi_lo(m2_raw)
            if m2h < 0 then m2h = m2h + 0x100000000 end
            if m2h >= 0xFFFF8000 then
                print(string.format("  arg3=%d: fd=%d mmap=FAILED", a3, fd2))
            else
                local b2 = full_addr(m2_raw)
                local d0 = rd(b2)
                local d4 = rd(b2 + uint64(4))
                if d0 == nil then d0 = -1 end
                if d4 == nil then d4 = -1 end
                if d0 < 0 then d0 = d0 + 0x100000000 end
                if d4 < 0 then d4 = d4 + 0x100000000 end
                print(string.format("  arg3=%d: fd=%d base=%s [0]=%08X [4]=%08X",
                    a3, fd2, fmt_q(m2_raw), d0, d4))
                sc_munmap(full_addr(m2_raw), uint64(0x4000))
            end
            sc_close(uint64(fd2))
        end
    else
        print(string.format("  arg3=%d: PCALL_FAIL", a3))
    end
end

-- [G] Try different mmap offsets on the same fd to see total mapping size
print("")
print("[G] mmap offset scan")
for _, off in ipairs({0, 0x4000, 0x8000, 0x10000, 0x40000, 0x100000}) do
    local m_raw = sc_mmap(uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(off))
    local mh, ml = get_hi_lo(m_raw)
    if mh < 0 then mh = mh + 0x100000000 end
    if mh >= 0xFFFF8000 then
        print(string.format("  off=0x%X: FAILED", off))
    else
        local mb = full_addr(m_raw)
        local v0 = rd(mb)
        if v0 ~= nil and v0 < 0 then v0 = v0 + 0x100000000 end
        print(string.format("  off=0x%X: base=%s [0]=%s", off, fmt_q(m_raw),
            v0 ~= nil and string.format("%08X", v0) or "DEAD"))
        sc_munmap(mb, uint64(0x4000))
    end
end

-- Cleanup
sc_munmap(base, uint64(0x4000))
sc_close(uint64(fd))

print("")
c = N(native.fcall_with_rax(stub, 20))
print(string.format("canary=%s", c == pid and "OK" or "FAIL"))
print("=== 122a COMPLETE ===")
