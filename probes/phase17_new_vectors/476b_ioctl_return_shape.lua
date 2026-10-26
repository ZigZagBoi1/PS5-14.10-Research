-- CRASH_CLASS: LOW
-- PROBE 476b: how a refused ioctl return is represented to Lua
--
-- Context: 476a classified every /dev/camera command as a hit because the
-- refuse value arrives as a table whose halves are -1 (or a full-width -1)
-- and the probe's "is this minus one" test compared against 0xFFFFFFFF only,
-- so it never matched. Print the raw shape once per device so the test can be
-- written against what the loader really returns.
--
-- Three calls per node: a command known to be refused (0xDEADBEEF), a command
-- that answers on gic (0xC0104701), and command 0. Nothing writes anything.

print("=== PROBE 476b: ioctl return shape ===")
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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" and v.h then h, l = v.h, v.l end
    if h ~= 0 or l >= 0x80000000 then return -1 end
    return l
end
local function put_str(s)
    local buf = memory.alloc(#s + 1)
    for i = 1, #s do pcall(function() memory.write_byte(buf + i - 1, string.byte(s, i)) end) end
    pcall(function() memory.write_byte(buf + #s, 0) end)
    return buf
end

local sc_open = make_syscall(5)
local sc_close = make_syscall(6)
local sc_ioctl = make_syscall(54)

local page = memory.alloc(0x1000)
for off = 0, 0xFFC, 4 do pcall(function() memory.write_dword(page + off, 0) end) end
local arg = uint64(page)

local function show(tag, v)
    local t = type(v)
    local out = tag .. " type=" .. t .. " tostring=" .. tostring(v)
    if t == "table" then
        local h, l = v.h, v.l
        out = out .. string.format(" h=%s(%s) l=%s(%s)",
            tostring(h), type(h), tostring(l), type(l))
        out = out .. " tonumber=" .. tostring(to_num(v)) .. " sgn=" .. tostring(sgn(v))
    else
        out = out .. " sgn=" .. tostring(sgn(v))
    end
    print(out)
end

for _, node in ipairs({ "/dev/camera", "/dev/gic", "/dev/ajm" }) do
    print("[" .. node .. "]")
    local fd = sgn(sc_open(uint64(put_str(node)), uint64(2), uint64(0)))
    if fd < 0 then fd = sgn(sc_open(uint64(put_str(node)), uint64(0), uint64(0))) end
    print("  open=" .. fd)
    if fd >= 0 then
        for _, cmd in ipairs({ 0xDEADBEEF, 0xC0104701, 0 }) do
            local ok, r = pcall(function() return sc_ioctl(uint64(fd), uint64(cmd), arg) end)
            if ok then
                show(string.format("  cmd=0x%08X", cmd), r)
            else
                print(string.format("  cmd=0x%08X PCALL-FAIL", cmd))
            end
        end
        pcall(function() sc_close(uint64(fd)) end)
    end
    print("")
end

print("=== PROBE 476b COMPLETE ===")
