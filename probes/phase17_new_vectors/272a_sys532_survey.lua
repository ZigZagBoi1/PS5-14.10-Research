-- CRASH_CLASS: LOW
-- PROBE 272a: syscall 532 survey (13.60 handler-derived argument shapes)
--
-- Context: PR #72 left syscalls 530-532/537 unmeasured. Offline analysis of the
-- 13.60 capture (docs/dumps_13.60) shows 528-531 and 537 are nosys slots
-- (same handler as sysent[0]), but 532 is real (narg 5). Handler at rva
-- 0xaf0040: args (u32 type, u32 id, ptr, ptr, ptr); a permission gate with id
-- 0x2aa (682) plus a credential check; type must be in {1..7, 0x18..0x1E,
-- 0x20, 0x2f, 31} (bitmask 0x800003d4 / 0x2a / range checks); walks a table of
-- 0x28-byte entries comparing arg1 against entry+0x18; Sony error 0x800d0203
-- on lookup miss. This probe tries every accepted type with id 0 and three
-- zeroed 0x100 buffers and records raw returns plus whether any buffer was
-- written.

print("=== PROBE 272a: syscall 532 survey ===")
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
local function n(v)
    local t = to_num(v)
    if t > 0x7FFFFFFFFFFFFFFF then t = t - 18446744073709551616 end
    return t
end
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end

local sc532 = make_syscall(532)
local types = { 1, 2, 3, 4, 5, 6, 7, 31, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x20, 0x2F }
local bufs = { memory.alloc(0x100), memory.alloc(0x100), memory.alloc(0x100) }
local function zerobufs()
    for b = 1, 3 do
        for i = 0, 0xFF do
            pcall(function() memory.write_byte(bufs[b] + i, 0) end)
        end
    end
end
local function first_written()
    for b = 1, 3 do
        for i = 0, 0x3F, 4 do
            local ok, v = pcall(function() return memory.read_dword(bufs[b] + i) end)
            if ok and v ~= nil and to_num(v) ~= 0 then
                return string.format("buf%d+%02X=0x%08X", b, i, to_num(v))
            end
        end
    end
    return nil
end

print("[A] one call per accepted type, id=0")
for i = 1, #types do
    local ty = types[i]
    zerobufs()
    local ok, rv = pcall(function()
        return sc532(uint64(ty), uint64(0), uint64(bufs[1]), uint64(bufs[2]), uint64(bufs[3]))
    end)
    local w = first_written()
    print(string.format("    type=0x%02X ret=%s %s", ty, raw(rv), w or ""))
end
print("")

print("[B] type=1, id sweep 0..7")
for id = 0, 7 do
    zerobufs()
    local ok, rv = pcall(function()
        return sc532(uint64(1), uint64(id), uint64(bufs[1]), uint64(bufs[2]), uint64(bufs[3]))
    end)
    local w = first_written()
    print(string.format("    id=%d ret=%s %s", id, raw(rv), w or ""))
end
print("")
print("=== END 272a ===")
