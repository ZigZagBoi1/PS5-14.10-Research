-- CRASH_CLASS: HIGH
-- PROBE 793b: mdbg 601 argument layout, both orders
--
-- Context: the 13.60 dispatcher (results/kernel_handlers/asm/sys_601_deep.asm)
-- loads the user arguments as
--     r15 = uap[1]     (arg 2 in Lua)
--     r12 = uap[2]     (arg 3 in Lua)
-- and the copyout-shaped case at 0xca0d6c does malloc(0x1000) then
-- `mov rdi,r15; mov rsi,buf; mov edx,0x1000; call 0x259900` — i.e. the
-- destination is uap[1]. Our previous sweeps always passed uap[1] = page,
-- uap[2] = 0, so a handler that reads its pointer from uap[2] would see NULL.
-- 793a showed cmd 0x10 returns -1 with the (page, 0) layout.
--
-- This probe calls every non-lethal command with BOTH layouts and reports the
-- return plus how much of the page the kernel filled.
-- Skipped: 0x00 (control only), 0x03/0x04 (lethal), 0x08 (blocks), 0x0c
-- (blocks), 0x12 (needs a process pointer). 0x09 is last: it killed the
-- process in the earlier sweep.

print("=== PROBE 793b: mdbg argument layout ===")
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

local Z = uint64(0)
local f = make_syscall(601)

local function page(words)
    local p = to_num(memory.alloc(words * 4))
    for i = 0, words - 1 do wd(p + i * 4, 0) end
    return p
end

local function report(tag, p, words)
    local nz, kern, shown = 0, 0, 0
    for i = 0, words - 1 do
        local v = rd(p + i * 4) % 4294967296
        if v ~= 0 then
            nz = nz + 1
            if v >= 0xFFFF8000 then kern = kern + 1
            elseif shown < 4 then
                print(string.format("    %s +%03X=%08X", tag, i * 4, v))
                shown = shown + 1
            end
        end
    end
    print(string.format("    %s nonzero=%s kern=%s", tag, nz, kern))
end

local function both(cmd, words)
    local a = page(words)
    local ra = sgn(f(U(cmd), U(a), Z, Z, Z, Z))
    print(string.format("  cmd %02X A(uap1=page) ret=%s", cmd, ra))
    report("A", a, words)
    local b = page(words)
    local rb = sgn(f(U(cmd), Z, U(b), Z, Z, Z))
    print(string.format("  cmd %02X B(uap2=page) ret=%s", cmd, rb))
    report("B", b, words)
end

for _, cmd in ipairs({ 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x10, 0x13 }) do
    both(cmd, 0x100)
end

print("[Z] cmd 0x09 last")
both(0x09, 0x100)

print("")
print("[Y] control cmd 0x00")
both(0x00, 0x10)
print("=== PROBE 793b END ===")
