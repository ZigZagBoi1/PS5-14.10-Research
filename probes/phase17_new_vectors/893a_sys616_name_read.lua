-- CRASH_CLASS: MODERATE
-- PROBE 893a: sys 616 with a real out pointer
--
-- 13.60 body (results/kernel_handlers/decompiled/sys_616.c:18, :53-66):
--   struct args616 { int32 id_00; void *user_out_08; }
--   target = lookup(id, caller scope); if (!target) { if (!cap_bit62) return 3;
--            target = lookup(id, ANY); }
--   ... copies target->name (0x20 bytes) -> user_out.
-- Our earlier 891a calls passed out=0/1/0x40000000, so every one failed in the
-- copyout, not in the gate. This run passes a real buffer.

print("=== PROBE 893a: SYS 616 NAME READ ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function show(tag, ok, rv)
    if not ok then print(string.format("  [%s] PCALL-FAIL", tag)) return end
    local h, l = get_hi_lo(rv)
    print(string.format("  [%s] ret=0x%08X_%08X", tag, h, l))
end
local function zeros(buf, n)
    for i = 0, n - 1, 4 do pcall(function() memory.write_dword(buf + i, 0) end) end
end
local function dumpstr(buf, n)
    local s = ""
    for i = 0, n - 1 do
        local ok, d = pcall(function() return to_num(memory.read_byte(buf + i)) end)
        if not ok or d == 0 then break end
        if d >= 32 and d < 127 then s = s .. string.char(d) else s = s .. "." end
    end
    return s
end

local sc20 = make_syscall(20)
local pid = 0
repeat
    local ok, rv = pcall(function() return sc20() end)
    if ok then pid = to_num(rv) end
until true
print(string.format("[A] self pid = %u", pid))

local sc616 = make_syscall(616)
local buf = memory.alloc(0x40)
print("[B] 616(id, outbuf):")
for _, target in ipairs({ pid, 0, 1, 2, 10 }) do
    zeros(buf, 0x40)
    local ok, rv = pcall(function() return sc616(uint64(target), uint64(buf)) end)
    show(string.format("616(%d, buf)", target), ok, rv)
    print(string.format("    name='%s'", dumpstr(buf, 0x20)))
end

print("")
print("=== PROBE 893a DONE ===")
