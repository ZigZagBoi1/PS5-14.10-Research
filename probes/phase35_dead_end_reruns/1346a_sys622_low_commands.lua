-- CRASH_CLASS: MODERATE
-- PROBE 1346a: the 622 commands below 0x100, and the two direct-call commands
--
-- Context: sys 622's dispatch was read out of the 13.60 handler body
-- (results/kernel_handlers/asm/sys_622_deep.asm:79-90). The order is:
--
--   7dcdf5  cmp  r14d,0x270          ; command <= 0x270 ?
--   7dce02  lea  eax,[r14-0x100]     ; 0x100..0x133 ?
--   7dce09  cmp  eax,0x33 ; ja 7dce4f
--   ...
--   7dceca  cmp  r14d,0x133 ; ja 7dcf70   ; <- the low table
--   7dced7  mov  ecx,r14d                  ; index = the command itself
--   7dceda  lea  rdx,[rip+0xfa369b]        ; table at 0x178057c
--   7dcee1  movsxd rcx,[rdx+rcx*4] ; add rcx,rdx ; jmp rcx
--
-- The index is the raw command, with no 0x100 subtraction, and the path that
-- reaches 7dceca is taken for EVERY command <= 0x270 that is not in
-- 0x100..0x133 or 0x201..0x271. So a command of 0x00..0xFF indexes the same
-- 52-entry table the 0x100 group uses, at a much lower offset, and nothing has
-- ever called that range. Probe 305a covered only the fifteen unauthenticated
-- commands inside 0x100..0x133 (all returned 0 with 0xFFFFFFFF in buf[0]);
-- 241a/242a/243a/244a covered 0x200..0x270, 0x302..0x320, 0x400..0x493, 0x813
-- and one call each of 0x100/0x133/0x12D/0x271/0x272. Command 0x520 is a
-- different shape: 7dd081 calls 0x29a570 with (thread, arg1, &status) and never
-- reads arg2/arg3/arg4, so it cannot fault on the buffer; 0x372 likewise calls
-- 0xc02050 at 7dd077. Neither has been called with a non-zero arg1.
--
-- -- prior art:
--   results/kernel_handlers/analysis/sys_622_deep.md (dispatch, tables, sub-handlers)
--   results/kernel_handlers/asm/sys_622_deep.asm:79-200 (the four jump tables)
--   probes/phase17_new_vectors/241a_sys622_layout.lua (size gate, one cmd per table)
--   probes/phase17_new_vectors/305a_sys622_unauth.lua (the 15 unauthenticated cmds)
--   probes/phase17_new_vectors/306a (the same cmds, index 0..15)
--   docs/ATTACK_SURFACE.md:98 and :325 (0x400 group kills after a successful copyin)
--
-- What it asks, safest first:
--   [A] cmd 0x00..0xFF with arg3 null, so a handler that needs a copyin fails
--       before doing anything else and returns -1. Any command that answers
--       without a copyin is a handler reachable with no buffer at all.
--   [B] 0x372 and 0x520 with arg1 = 0..31: no copyin, no buffer, so any answer
--       is a real dispatch.
--   [C] the phase-A survivors again with a mapped arg3 page, to see whether a
--       valid secondary address changes them.
--
-- Every call prints its own line before the next one, so a death names the
-- command that caused it.

print("=== PROBE 1346a: 622 LOW COMMANDS ===")
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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(val)
    if val == nil then return "nil" end
    local text = tostring(val)
    if text == "-1" then return "-1" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return text
end

local sc622 = make_syscall(622)
local sc477 = make_syscall(477)
local buf = memory.alloc(0x200)

local page = sc477(uint64(0), uint64(0x4000), uint64(0x33), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
local ph, pl = get_hi_lo(page)
local page_valid = not (ph == 0xFFFFFFFF and pl == 0xFFFFFFFF) and pl ~= 0 and to_num(page) ~= 0
print(string.format("page=%s valid=%s", sgn(page), tostring(page_valid)))

-- Canary the output buffer, call, and report what changed.
local function fill()
    for i = 0, 0x1F do safe_wd(buf + i * 4, 0xDEADBEEF) end
end
local function changed()
    local n = 0
    for i = 0, 0x1F do
        if safe_rd(buf + i * 4) ~= 0xDEADBEEF then n = n + 1 end
    end
    return n
end
local function call622(cmd, sub, addr, size)
    fill()
    local ok, ret = pcall(function()
        return sc622(uint64(cmd), uint64(sub), uint64(buf), addr, uint64(size), uint64(0))
    end)
    return (ok and sgn(ret) or "PCALL-FAIL"), changed(),
        sgn(safe_rd(buf)), sgn(safe_rd(buf + 4)), sgn(safe_rd(buf + 8))
end

-- ============================================================
-- [A] cmd 0x00..0xFF, arg3 null
-- ============================================================
print("")
print("[A] cmd 0x00..0xFF, arg3 null, size 0x40")
local survivors = {}
local silent = 0
for cmd = 0x00, 0xFF do
    local ret, nch, d0, d1, d2 = call622(cmd, 0, uint64(0), 0x40)
    if ret ~= "-1" then
        print(string.format("  cmd=0x%03X ret=%-20s changed=%d buf=%s %s %s", cmd, ret, nch, d0, d1, d2))
        survivors[#survivors + 1] = cmd
    else
        silent = silent + 1
    end
end
print(string.format("[A] done: 256 commands, %d answered, %d returned -1", #survivors, silent))

-- ============================================================
-- [B] 0x372 and 0x520, arg1 = 0..31, arg3 null
-- ============================================================
print("")
print("[B] cmd 0x372 and 0x520, sub 0..31")
for _, cmd in ipairs({ 0x372, 0x520 }) do
    local line = {}
    for sub = 0, 31 do
        local ret = call622(cmd, sub, uint64(0), 0x40)
        line[#line + 1] = string.format("%d:%s", sub, tostring(ret))
    end
    print(string.format("  cmd=0x%03X %s", cmd, table.concat(line, " ")))
end

-- ============================================================
-- [C] the phase-A survivors with a mapped arg3 page
-- ============================================================
print("")
print("[C] phase-A survivors, arg3 = mapped page")
if page_valid then
    for _, cmd in ipairs(survivors) do
        local ret, nch, d0, d1, d2 = call622(cmd, 0, page, 0x40)
        print(string.format("  cmd=0x%03X ret=%-20s changed=%d buf=%s %s %s", cmd, ret, nch, d0, d1, d2))
    end
else
    print("  page not mapped, skipped")
end

print("")
print("=== PROBE 1346a COMPLETE ===")
