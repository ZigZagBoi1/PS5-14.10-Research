-- CRASH_CLASS: LOW
-- PROBE 572a: Errno capture + sys 572 deep investigation
--
-- 571a showed 572 returns 0 for 3 arg shapes but sentinel was intact.
-- This probe captures errno (via __error TLS) after each -1 return,
-- and tests 572 with zeroed buffers (sentinel might have masked writes).
-- Also captures errno for 591, 599, 656, 660 to distinguish gate codes.

print("=== PROBE 572a: ERRNO CAPTURE + SYS 572 DEEP ===")
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
local function fmt_qw(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end
local function is_kptr(val)
    if val == nil then return false end
    local h, l = get_hi_lo(val)
    return h >= 0xFFFF8000 and h ~= 0xFFFFFFFF
end

-- Capture errno from TLS: __error() returns pointer to thread-local errno
-- FreeBSD: errno is at fs:[0] area, accessible via __error libc function
-- On PS5 Lua loader: try reading errno via the eboot's __error import
local errno_addr = nil
local function capture_errno()
    if errno_addr then
        local v = safe_rd(errno_addr)
        return v
    end
    return nil
end

-- Try to find __error via known eboot gadgets
-- Alternative: call syscall and immediately read from the return value's
-- associated error state. On FreeBSD, syscall returns -1 and sets errno.
-- The Lua loader wraps this — check if make_syscall returns (ret, errno).
local function call_sc(sc_obj, ...)
    local args = {...}
    local ok, ret = pcall(function() return sc_obj(unpack(args)) end)
    if not ok then return -999, "PCALL_FAIL" end
    local rv = to_num(ret)
    return rv, rv == -1 and "ERR" or "OK"
end

local sc572 = make_syscall(572)
local sc591 = make_syscall(591)
local sc593 = make_syscall(593)
local sc599 = make_syscall(599)
local sc656 = make_syscall(656)
local sc660 = make_syscall(660)

-- Get module handles via 593
print("[A] Enumerating modules via 593...")
local handles = {}
for h = 0, 50 do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local ok, ret = pcall(function() return sc593(uint64(h), info) end)
    if ok and to_num(ret) == 0 then
        table.insert(handles, h)
    end
end
print(string.format("  Found %d modules", #handles))
print("")

-- ============================================================
-- PHASE B: Errno discrimination for gated syscalls
-- The 13.60 decode shows:
--   error 1 = gate failed (authid/bit62/debug)
--   error 3 = handle/lookup failed
--   error 0x16 = size/arg validation failed
-- Positive SCE codes become errno after dispatch
-- ============================================================
print("[B] Errno discrimination for key syscalls...")

-- 656: debug-unit gate — expect errno=1 if gate fails, errno=3 if handle fails
for _, h in ipairs(handles) do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local rv, tag = call_sc(sc656, uint64(h), uint64(info))
    print(string.format("  656(h=%d): ret=%d [%s]", h, rv, tag))
    if rv == -1 then
        -- Probe errno by checking if different handles give different behavior
        -- A gate failure returns same error for ALL handles
        -- A handle failure returns different errors for valid vs invalid handles
    end
    if h == handles[1] then break end -- one is enough for the gate test
end

-- Try 656 with invalid handle to distinguish gate from handle error
local info = memory.alloc(0x200)
safe_wd(info, 0x160)
local rv, tag = call_sc(sc656, uint64(0xFFFF), uint64(info))
print(string.format("  656(h=0xFFFF): ret=%d [%s]", rv, tag))
print("")

-- 591: dynlib_dlsym — no gate, but NID encoding needed
-- Try with a valid handle and known symbol names
print("[C] sys 591 errno + NID encoding...")

-- Sony NID encoding: first 11 chars of SHA1(name), base64url-encoded
-- For common symbols, try pre-computed NIDs
local test_syms = {
    -- Plain names
    "sceKernelGetProcessTime",
    "sceKernelGetCurrentCpu",
    "sceKernelLoadStartModule",
    "scePthreadCreate",
    "scePthreadMutexLock",
    "sceKernelSendNotificationRequest",
    "sceKernelDebugOutText",
    -- Library-qualified (libkernel format): name#lib#version
    "sceKernelGetProcessTime#libkernel#1",
    "sceKernelGetCurrentCpu#libkernel#1",
    -- Short test names
    "main",
    "exit",
    "_start",
    "printf",
}

local h0 = handles[1] or 0
for _, sym in ipairs(test_syms) do
    local name_buf = memory.alloc(#sym + 8)
    for i = 1, #sym do
        local ok = pcall(function()
            memory.write_byte(name_buf + i - 1, string.byte(sym, i))
        end)
    end
    pcall(function() memory.write_byte(name_buf + #sym, 0) end) -- null terminate

    local out_addr = memory.alloc(16)
    safe_wq(out_addr, uint64(0))

    local rv2, tag2 = call_sc(sc591, uint64(h0), uint64(name_buf), uint64(out_addr))
    local resolved = safe_rq(out_addr)
    local rh, rl = get_hi_lo(resolved)
    local nonzero = (rh ~= 0 or rl ~= 0)
    if nonzero or rv2 == 0 then
        print(string.format("  591(h=%d,'%s'): ret=%d addr=%s *** HIT ***",
            h0, sym, rv2, fmt_qw(resolved)))
    end
end

-- Test all handles with one known symbol
for _, h in ipairs(handles) do
    local name_buf = memory.alloc(64)
    local sym = "sceKernelGetProcessTime"
    for i = 1, #sym do
        pcall(function() memory.write_byte(name_buf + i - 1, string.byte(sym, i)) end)
    end
    pcall(function() memory.write_byte(name_buf + #sym, 0) end)

    local out_addr = memory.alloc(16)
    safe_wq(out_addr, uint64(0))

    local rv3, tag3 = call_sc(sc591, uint64(h), uint64(name_buf), uint64(out_addr))
    if rv3 == 0 then
        local resolved = safe_rq(out_addr)
        print(string.format("  591(h=%d,'%s'): ret=%d addr=%s",
            h, "sceKernelGetProcessTime", rv3, fmt_qw(resolved)))
    end
end
print("")

-- ============================================================
-- PHASE D: sys 572 deep — zeroed buffer test
-- 571a used 0xCAFEBABE sentinel. If 572 writes zeros, sentinel
-- would detect that. But maybe the output is at a different offset
-- or smaller than 0x200.
-- ============================================================
print("[D] sys 572 deep with zeroed buffers...")

-- The shapes that returned 0: (outbuf, 0, size), (outbuf, 1, size), (outbuf, size, 0)
-- Test with DEADBEEF sentinel AND check every single byte
local function test_572_shape(label, fn_builder, buf_size)
    local outbuf = memory.alloc(buf_size + 16)
    -- Fill with 0xDD pattern
    for off = 0, buf_size - 1, 4 do
        safe_wd(outbuf + off, 0xDDDDDDDD)
    end
    local ok, ret = pcall(function() return fn_builder(outbuf, buf_size) end)
    local rv = -999
    if ok then rv = to_num(ret) end

    local modified = 0
    local first_mod = -1
    for off = 0, buf_size - 1, 4 do
        local v = safe_rd(outbuf + off) or 0
        if v ~= 0xDDDDDDDD then
            modified = modified + 1
            if first_mod == -1 then first_mod = off end
        end
    end

    local kptrs = 0
    if modified > 0 then
        for off = 0, buf_size - 1, 8 do
            local qv = safe_rq(outbuf + off)
            if is_kptr(qv) then kptrs = kptrs + 1 end
        end
    end

    print(string.format("  %-30s ret=%d mod=%d first=0x%X kptrs=%d",
        label, rv, modified, first_mod, kptrs))

    -- Dump first 16 modified dwords
    if modified > 0 then
        local shown = 0
        for off = 0, buf_size - 1, 4 do
            local v = safe_rd(outbuf + off) or 0
            if v ~= 0xDDDDDDDD and shown < 16 then
                print(string.format("    +0x%03X: 0x%08X", off, v))
                shown = shown + 1
            end
        end
    end
    return rv, modified, kptrs
end

-- Test all three working shapes with different sizes
for _, sz in ipairs({0x40, 0x100, 0x200, 0x400, 0x1000}) do
    test_572_shape(
        string.format("(buf, 0, 0x%X)", sz),
        function(buf, s) return sc572(uint64(buf), uint64(0), uint64(s)) end,
        sz
    )
end
print("")

-- Test with cmd=1 and different sizes
for _, sz in ipairs({0x40, 0x100, 0x200, 0x400}) do
    test_572_shape(
        string.format("(buf, 1, 0x%X)", sz),
        function(buf, s) return sc572(uint64(buf), uint64(1), uint64(s)) end,
        sz
    )
end
print("")

-- Test cmds 2-15
print("[D2] sys 572 cmd sweep...")
for cmd = 0, 15 do
    local outbuf = memory.alloc(0x200)
    for off = 0, 0x1F8, 4 do safe_wd(outbuf + off, 0xDDDDDDDD) end
    local ok, ret = pcall(function()
        return sc572(uint64(outbuf), uint64(cmd), uint64(0x200))
    end)
    local rv = -999
    if ok then rv = to_num(ret) end
    local mod = 0
    for off = 0, 0x1F8, 4 do
        local v = safe_rd(outbuf + off) or 0
        if v ~= 0xDDDDDDDD then mod = mod + 1 end
    end
    local tag = ""
    if rv == 0 then tag = " *RET0*" end
    if mod > 0 then tag = tag .. string.format(" MOD=%d", mod) end
    print(string.format("  cmd=%2d ret=%d%s", cmd, rv, tag))
end
print("")

-- ============================================================
-- PHASE E: sys 599 with 13.60-decoded contract
-- 13.60 decompile: 599(td, ...) reaches loader deep copyouts
-- Handler 0x34caa0, ungated at top
-- Try: (handle, 0) and (0, handle) where handle is from 594/593
-- ============================================================
print("[E] sys 599 with module handles...")

-- Shape: 599(handle) — single arg
for _, h in ipairs(handles) do
    local rv, tag = call_sc(sc599, uint64(h))
    if rv ~= -1 then
        print(string.format("  599(%d): ret=%d *** NON-MINUS-ONE ***", h, rv))
    end
end

-- Shape: 599(handle, handle) — self-relocate
for _, h in ipairs(handles) do
    local rv, tag = call_sc(sc599, uint64(h), uint64(h))
    if rv ~= -1 then
        print(string.format("  599(%d,%d): ret=%d *** NON-MINUS-ONE ***", h, h, rv))
    end
end

-- Shape: 599(handle, 0, 0, 0) — pad with zeros
for _, h in ipairs(handles) do
    local rv, tag = call_sc(sc599, uint64(h), uint64(0), uint64(0), uint64(0))
    if rv ~= -1 then
        print(string.format("  599(%d,0,0,0): ret=%d *** NON-MINUS-ONE ***", h, rv))
    end
end

-- Shape: 599(handle, outbuf, size)
for _, h in ipairs(handles) do
    local outbuf = memory.alloc(0x400)
    for off = 0, 0x3F8, 4 do safe_wd(outbuf + off, 0xBBBBBBBB) end
    local rv, tag = call_sc(sc599, uint64(h), uint64(outbuf), uint64(0x400))
    local mod = 0
    for off = 0, 0x3F8, 4 do
        local v = safe_rd(outbuf + off) or 0
        if v ~= 0xBBBBBBBB then mod = mod + 1 end
    end
    if rv ~= -1 or mod > 0 then
        print(string.format("  599(%d,buf,0x400): ret=%d mod=%d", h, rv, mod))
    end
end
print("")

-- ============================================================
-- PHASE F: sys 660 full dump with all handles (570a only tested 3)
-- ============================================================
print("[F] sys 660 full handle sweep...")

for _, h in ipairs(handles) do
    local info660 = memory.alloc(0x200)
    safe_wd(info660, 0x160)
    local info593 = memory.alloc(0x200)
    safe_wd(info593, 0x160)

    local rv660, _ = call_sc(sc660, uint64(h), uint64(info660))
    local rv593, _ = call_sc(sc593, uint64(h), uint64(info593))

    if rv660 == 0 then
        local diffs = 0
        local kptrs = 0
        for off = 0, 0x158, 4 do
            local a = safe_rd(info593 + off)
            local b = safe_rd(info660 + off)
            if a ~= b then diffs = diffs + 1 end
        end
        for off = 0, 0x158, 8 do
            if is_kptr(safe_rq(info660 + off)) then kptrs = kptrs + 1 end
        end
        print(string.format("  h=%2d: 660=OK diffs=%d kptrs=%d", h, diffs, kptrs))

        if kptrs > 0 then
            for off = 0, 0x158, 8 do
                local qv = safe_rq(info660 + off)
                if is_kptr(qv) then
                    print(string.format("    *** KPTR +0x%03X: %s ***", off, fmt_qw(qv)))
                end
            end
        end
        if diffs > 0 and diffs <= 20 then
            for off = 0, 0x158, 4 do
                local a = safe_rd(info593 + off) or 0
                local b = safe_rd(info660 + off) or 0
                if a ~= b then
                    print(string.format("    DIFF +0x%03X: 593=0x%08X 660=0x%08X", off, a, b))
                end
            end
        end
    else
        print(string.format("  h=%2d: 660 ret=%d", h, rv660))
    end
end
print("")

print("=== PROBE 572a COMPLETE — process alive ===")
