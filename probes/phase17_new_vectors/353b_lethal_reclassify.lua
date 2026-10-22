-- CRASH_CLASS: MODERATE
-- PROBE 353b: reclassify the death-on-touch syscalls - nosys or a faulting handler
--
-- 353a showed that 561, 562, 631, 650, 651, 661, 665 and 668 all terminate the
-- process only because the shared nosys trampoline raises SIGSYS, and that with
-- SIGSYS ignored every one of them returns -1 instead. The kill said nothing
-- about the slot: it was the signal disposition.
--
-- Every other number recorded as lethal on this firmware is worth the same test.
-- If it returns, the slot is the nosys trampoline and there is nothing to call.
-- If the process still dies, the handler is real and faults on the argument -
-- that is the short list worth shaping arguments for.
--
-- Order is by how likely a return is; the process dies at the first real fault,
-- so the last surviving line names the next slot to work on.

print("=== PROBE 353b: LETHAL SLOTS UNDER SIG_IGN ===")
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
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local Z = uint64(0)
local function wd(addr, value)
    pcall(function() memory.write_dword(addr, value) end)
end
local function wq(addr, value)
    pcall(function() memory.write_qword(addr, value) end)
end

local new_sa = memory.alloc(0x80)
local old_sa = memory.alloc(0x80)
for i = 0, 0x70, 8 do
    wq(new_sa + i, 0)
    wq(old_sa + i, 0)
end
wq(new_sa + 0, 1)   -- SIG_IGN
wd(new_sa + 8, 0)
local okI, rvI = pcall(function()
    return make_syscall(416)(uint64(12), uint64(new_sa), uint64(old_sa))
end)
print(string.format("[A] sigaction(12, SIG_IGN) -> %s", okI and tostring(sgn(rvI)) or "EXC"))
if not (okI and sgn(rvI) == 0) then
    print("    SIGSYS could not be ignored; stopping so the console is not spent")
    print("=== 353b DONE ===")
    return
end

local list = {189, 306, 307, 308, 337, 570, 573}

print("[B] each slot with six zero arguments")
for _, num in ipairs(list) do
    local ok, rv = pcall(function()
        return make_syscall(num)(Z, Z, Z, Z, Z, Z)
    end)
    if ok then
        print(string.format("  sys %3d = %d        (returned: the slot is nosys)", num, sgn(rv)))
    else
        print(string.format("  sys %3d = EXC", num))
    end
end

print("[C] restoring the previous disposition")
pcall(function()
    return make_syscall(416)(uint64(12), uint64(old_sa), Z)
end)

print("")
print("=== 353b DONE ===")
