-- CRASH_CLASS: LOW
-- PROBE 246a: the libdbg and "2" dynlib calls with real buffers
--
-- Context: every dynlib call measured so far that returns module information
-- (593) hands back userland addresses only. Three neighbours were never called
-- with anything but six zeros: 656 dynlib_get_info_for_libdbg, 659
-- dynlib_get_list2 and 660 dynlib_get_info2. The "for_libdbg" variant is the
-- interesting one - libdbg is the debug library, and a debugger's module record
-- is where a kernel-side pointer would live if one lives anywhere in this
-- family. The "2" variants take a count-and-buffer shape in the PS4 headers.
--
-- Buffers are canary-filled and scanned two ways: any changed dword, and any
-- qword in the kernel halves (0xFFFF8000... and 0xFFFFFFFF8...). A count or a
-- status dword is reported as changed but not as a pointer.
--
--   A  656 with buffer in the second, first and third slot
--   B  659 the same three layouts
--   C  660 the same three layouts
--   D  593 as the control, which is known to fill a module record

print("=== PROBE 246a: libdbg and dynlib2 with real buffers ===")
print("")

local CANARY = 0xA5A5A5A5
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
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok and val ~= nil then return val end
    return nil
end
local function fill(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, CANARY) end
end
local function scan(buf, n)
    local changed, first, firstval = 0, nil, nil
    for off = 0, n - 4, 4 do
        local v = rd(buf + off)
        if v ~= nil and v ~= CANARY then
            changed = changed + 1
            if first == nil then first = off; firstval = v end
        end
    end
    return changed, first, firstval
end
local function kern(buf, n)
    local hits = 0
    local sample = nil
    for off = 0, n - 8, 8 do
        local hi = rd(buf + off + 4)
        if hi ~= nil and hi >= 0xFFFF8000 then
            hits = hits + 1
            if sample == nil then sample = off end
        end
    end
    return hits, sample
end

local function pid()
    local ok, v = pcall(function() return make_syscall(20)().tonumber() end)
    if ok then return v end
    return nil
end

local BUF = memory.alloc(0x1000)
local function trial(label, num, a, b, c)
    local sc = make_syscall(num)
    fill(BUF, 0x1000)
    local ok, rv = pcall(function() return sc(a, b, c) end)
    local ret = nil
    if ok then ret = rv end
    local changed, first, firstval = scan(BUF, 0x1000)
    local hits, sample = kern(BUF, 0x1000)
    print(string.format("  %-26s ret=%-12s changed=%-4d first=%s val=%s kern=%d%s  pid=%s",
        label, q(ret), changed,
        first == nil and "-" or string.format("+0x%03X", first),
        first == nil and "-" or q(firstval),
        hits, sample == nil and "" or (" @+" .. string.format("0x%03X", sample)),
        tostring(pid())))
    return ret
end

local B = uint64(BUF)
local Z = uint64(0)
local H = uint64(0x1000)
local L = uint64(0x100)

print("[0] control: 593 with a module handle and a buffer")
trial("593(0, BUF)", 593, Z, B, Z)
trial("593(1, BUF)", 593, uint64(1), B, Z)

print("")
print("[A] 656 dynlib_get_info_for_libdbg")
trial("656(0, BUF)", 656, Z, B, Z)
trial("656(0, BUF, 0x100)", 656, Z, B, L)
trial("656(0, BUF, 0x1000)", 656, Z, B, H)
trial("656(BUF, 0)", 656, B, Z, Z)
trial("656(BUF, 0x100)", 656, B, L, Z)
trial("656(1, BUF, 0x100)", 656, uint64(1), B, L)

print("")
print("[B] 659 dynlib_get_list2")
trial("659(0, BUF)", 659, Z, B, Z)
trial("659(0, BUF, 0x100)", 659, Z, B, L)
trial("659(BUF, 0)", 659, B, Z, Z)
trial("659(BUF, 0x100)", 659, B, L, Z)

print("")
print("[C] 660 dynlib_get_info2")
trial("660(0, BUF)", 660, Z, B, Z)
trial("660(0, BUF, 0x100)", 660, Z, B, L)
trial("660(BUF, 0)", 660, B, Z, Z)
trial("660(BUF, 0x100)", 660, B, L, Z)
trial("660(1, BUF, 0x100)", 660, uint64(1), B, L)

print("")
print("    pid -> " .. tostring(pid()))
print("")
print("=== PROBE 246a COMPLETE ===")
