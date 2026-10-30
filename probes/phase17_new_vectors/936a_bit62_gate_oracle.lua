-- CRASH_CLASS: LOW
-- PROBE 936a: capability-bit-62 gate oracle
--
-- Context: static read of docs/dumps_13.60 (kernel_text.bin, base
-- 0xffffffff8a9c0000) found one shared privilege helper at 0x8afc8f90:
--
--     mov rax, [rdi + 0x60]     ; rdi = td->td_ucred (loaded as [td+0x140])
--     shr rax, 0x3e             ; >> 62
--     and eax, 1
--     ret
--
-- Sixteen Sony handlers call it somewhere in their body (600, 601, 610, 611,
-- 613, 618, 623, 627, 636, 641, 642, 646, 647, 652, 667, 671).  sys 600 and
-- 636 call it as their very first act and return 1 when it fails, so their
-- return value is a direct read of that capability bit from userland:
--
--   636(uap): gate(cred) == 0 -> return 1
--             arg2 must be 1..0x200 (arg2-0x201 unsigned < 0xfffffe00 is EINVAL)
--             copyin(user arg1, kernel global, arg2*0x10)   ; <= 0x2000 bytes
--             then arms a 0x10-byte callback with arg2 as the count
--             -> return 0 on success, 22 (EINVAL) on a bad count, 14 (EFAULT)
--                on a bad user pointer
--
-- So 636(ptr, 4) returning 0 means both "we hold bit 62" and "the kernel
-- copied 0x40 bytes of ours into a global table that gets used later".
--
-- What we measure:
--   A. sys 587 credential dump (0x88 bytes) -- is bit 62 of +0x60 already set?
--   B. 600(name)  -- gate read, returns 1 when closed
--   C. 636(buf, 4) / 636(buf, 1) / bad counts / bad pointer -- gate + arg checks
--   D. the remaining gated handlers with zero args, one print per call so a
--      death is attributable; the historically noisy ones (652, 667) go last

print("=== PROBE 936a: BIT-62 GATE ORACLE ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wb(addr, val)
    local ok = pcall(function() memory.write_byte(addr, val) end)
    return ok
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function show(tag, ok, rv)
    if not ok then
        print(string.format("  [%s] PCALL-FAIL", tag))
        return
    end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X (lo=%d)", tag, h, l, l))
end
local function call(num, a, b, c, d, e, f)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a or 0), uint64(b or 0), uint64(c or 0),
                  uint64(d or 0), uint64(e or 0), uint64(f or 0))
    end)
    return ok, rv
end

-- canary
local okc, pid = pcall(function() return to_num(make_syscall(20)(uint64(0))) end)
print(string.format("[0] canary pid ok=%s pid=%s", tostring(okc), tostring(pid)))

-- A. credential dump
print("")
print("[A] sys 587 credential dump")
local cred = memory.alloc(0x100)
if cred == nil then
    print("  alloc failed")
else
    for i = 0, 0x100 - 8, 8 do safe_wd(cred + i, 0) end
    local okA, rvA = call(587, to_num(pid), to_num(cred))
    show("587", okA, rvA)
    for i = 0, 0x88 - 8, 8 do
        local q = safe_rq(cred + i)
        if q ~= nil then
            local h, l = get_hi_lo(q)
            local note = ""
            if i == 0x60 then
                -- bit 62 of the qword is bit 30 of the high dword
                local bit = 0
                if math.floor(h / 0x40000000) % 2 == 1 then bit = 1 end
                note = string.format("   <-- cred+0x60 bit62=%d", bit)
            end
            print(string.format("    +0x%02X = 0x%08X_%08X%s", i, h, l, note))
        end
    end
end

-- B. sys 600 (set-name shaped, gate first)
print("")
print("[B] sys 600 gate probe")
local name = memory.alloc(0x100)
if name ~= nil then
    safe_wd(name, 0)
    for i = 0, 7 do safe_wb(name + i, 0x41 + i) end
    safe_wb(name + 8, 0)
    local okB, rvB = call(600, to_num(name))
    show("600(name)", okB, rvB)
end

-- C. sys 636 (upload shaped, gate first)
print("")
print("[C] sys 636 gate probe")
local up = memory.alloc(0x2000)
if up ~= nil then
    for i = 0, 0x2000 - 8, 8 do safe_wd(up + i, 0) end
    -- 4 entries of 16 bytes: 0, 1, 2, 3
    for i = 0, 3 do safe_wd(up + i * 0x10, i) end

    local okC1, rvC1 = call(636, to_num(up), 4)
    show("636(buf,4)", okC1, rvC1)

    local okC2, rvC2 = call(636, to_num(up), 0)
    show("636(buf,0)", okC2, rvC2)

    local okC3, rvC3 = call(636, to_num(up), 0x201)
    show("636(buf,0x201)", okC3, rvC3)

    local okC4, rvC4 = call(636, 0, 4)
    show("636(0,4)", okC4, rvC4)

    local okC5, rvC5 = call(636, to_num(up), 1)
    show("636(buf,1)", okC5, rvC5)
end

-- D. the rest of the gated set, zero args
print("")
print("[D] other bit-62 handlers, zero args")
local list = { 610, 611, 613, 618, 623, 641, 642, 646, 647, 652, 667 }
for _, n in ipairs(list) do
    print(string.format("  -> sys %d", n))
    local okD, rvD = call(n, 0, 0, 0, 0, 0, 0)
    show(string.format("%d zeros", n), okD, rvD)
end

print("")
print("=== PROBE 936a COMPLETE ===")
