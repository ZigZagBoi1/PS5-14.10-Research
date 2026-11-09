-- CRASH_CLASS: HIGH
-- PROBE 251a: jitshm and the dl_* calls, the last untested object surface
--
-- 533 jitshm_create hands out a shared-memory object as a descriptor, and
-- 534 jitshm_alias asks for a second handle on the same object. That is the one
-- place left in the Sony range where a single object legitimately has two
-- handles, so it is where a reference accounting mistake would show. 535
-- dl_get_list and 536 dl_get_info are the dynamic linker's list and record, the
-- same struct-with-size shape that 593 accepts.
--
-- Order matters: the calls most likely to kill the process run first, so a kill
-- still leaves the earlier answers on the wire.
--
--   A  533(size, flags) - the object itself, several sizes and flag values
--   B  534(fd, flags) on whatever fd A produced, and on a socket as a type check
--   C  535 and 536 with a zeroed struct and a size at +0
--
-- A negative fd from 533 means the call is absent or refused and B is skipped.

print("=== PROBE 251a: jitshm and dl ===")
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
local function q(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("0x%X", n)
end
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok and val ~= nil then return to_num(val) end
    return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end
local function pid()
    local ok, v = pcall(function() return make_syscall(20)() end)
    if ok then return to_num(v) end
    return nil
end
print("[0] canary pid=" .. tostring(pid()))

local function call(num, a, b, c)
    local sc = make_syscall(num)
    local ok, rv = pcall(function() return sc(a, b, c) end)
    if not ok then return nil end
    return rv
end

print("")
print("[A] 533 jitshm_create")
local fd = nil
local shapes = {
    { 0x4000, 0 },
    { 0x4000, 1 },
    { 0x1000, 0 },
    { 0x100000, 0 },
    { 0x0, 0 },
    { 0x4000, 0xFFFFFFFF },
}
for i = 1, #shapes do
    local rv = call(533, uint64(shapes[i][1]), uint64(shapes[i][2]), uint64(0))
    print(string.format("    533(0x%X, 0x%X) -> %s   pid=%s",
        shapes[i][1], shapes[i][2], q(rv), tostring(pid())))
    local n = to_num(rv)
    if fd == nil and rv ~= nil and n >= 0 and n < 4096 then fd = n end
end

print("")
print("[B] 534 jitshm_alias")
local alias = nil
if fd ~= nil then
    print("    fd from A = " .. tostring(fd))
    local shapes2 = { { fd, 0 }, { fd, 1 }, { fd, 0xFFFFFFFF } }
    for i = 1, #shapes2 do
        local rv = call(534, uint64(shapes2[i][1]), uint64(shapes2[i][2]), uint64(0))
        print(string.format("    534(%d, 0x%X) -> %s   pid=%s",
            shapes2[i][1], shapes2[i][2], q(rv), tostring(pid())))
        local n = to_num(rv)
        if alias == nil and rv ~= nil and n >= 0 and n < 4096 then alias = n end
    end
else
    print("    no fd from 533; skipping")
end

print("")
print("    type check: alias of a socket descriptor, then of a junk number")
local sok, sfd = pcall(function()
    return make_syscall(97)(uint64(2), uint64(1), uint64(0))
end)
print("    socket -> " .. (sok and q(sfd) or "raised"))
if sok and sfd ~= nil then
    local sn = to_num(sfd)
    print("    534(socket " .. sn .. ", 0) -> " .. q(call(534, uint64(sn), uint64(0), uint64(0))))
    print("    534(bad fd 0xFFFF, 0) -> " .. q(call(534, uint64(0xFFFF), uint64(0), uint64(0))))
end

print("")
print("[C] 535 dl_get_list and 536 dl_get_info with a sized struct")
local BUF = memory.alloc(0x1000)
local shapes3 = { { "535(0, BUF{s=0x160})", 535, uint64(0), uint64(BUF), 0x160 },
                  { "536(0, BUF{s=0x160})", 536, uint64(0), uint64(BUF), 0x160 },
                  { "536(BUF{s=0x160}, 0)", 536, uint64(BUF), uint64(0), 0x160 } }
for i = 1, #shapes3 do
    local label, num, a, b, size = shapes3[i][1], shapes3[i][2], shapes3[i][3], shapes3[i][4], shapes3[i][5]
    zero(BUF, 0x1000)
    wd(BUF, size)
    local rv = call(num, a, b, uint64(0))
    local wrote, first = 0, nil
    for off = 0, 0x1000 - 4, 4 do
        if off ~= 0 then
            local v = rd(BUF + off)
            if v ~= nil and v ~= 0 then wrote = wrote + 1; if first == nil then first = off end end
        end
    end
    print(string.format("    %-24s ret=%s wrote=%d%s  pid=%s", label, q(rv), wrote,
        first == nil and "" or (" first=+0x" .. string.format("%03X", first)), tostring(pid())))
end

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 251a COMPLETE ===")
