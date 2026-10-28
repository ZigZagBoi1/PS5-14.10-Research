-- CRASH_CLASS: MODERATE
-- PROBE 552e: MapDirectMemory via fcall (6-arg test)
--
-- 552d CONFIRMED: SROP-to-wrapper works (AllocateDirectMemory rv=0).
-- 552c CRASHED: MapDirectMemory via child SROP killed process.
--
-- Question: is MapDirectMemory 6-arg or 7-arg?
-- PS4 SDK: sceKernelMapDirectMemory(void **addr, size_t len, int prot,
--          int flags, off_t physAddr, size_t alignment)  — 6 args
-- CLAUDE.md claims 7-arg but that might be wrong.
--
-- If 6-arg → fcall should work (forwards 6 regs)
-- If it crashes via fcall too → the function itself is blocked/gated
--
-- Tests several flag values: 0x0, 0x1, 0x2, 0x412

print("=== PROBE 552e: MapDirectMemory via fcall (6-arg) ===")
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

local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid end

-- Ignore SIGSYS/SIGPIPE
local sa_buf = memory.alloc(0x20)
wq(N(sa_buf), uint64(1))
pcall(function() mk(416)(uint64(12), sa_buf, uint64(0)) end)
pcall(function() mk(416)(uint64(13), sa_buf, uint64(0)) end)

-- libkernel
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local lk_lo = rd(N(ib) + 0x108) or 0
local lk_hi = rd(N(ib) + 0x10C) or 0
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
local lk = uint64(string.format("0x%X%08X", lk_hi, lk_lo))
print(string.format("libkernel=0x%X%08X", lk_hi, lk_lo))

local alloc_fn = lk + uint64(0x17EF0)
local map_fn   = lk + uint64(0x15020)
print("AllocateDirectMemory=" .. fmt(alloc_fn))
print("MapDirectMemory=" .. fmt(map_fn))

-- Step 1: Allocate physical memory
local phys_out = memory.alloc(8)
wq(N(phys_out), uint64(0))
local ok_a, rv_a = pcall(function()
    return native.fcall_with_rax(alloc_fn, 0,
        uint64(0), uint64("0x150000000"), uint64(0x4000),
        uint64(0x4000), uint64(0), uint64(N(phys_out)))
end)
local phys = rq(N(phys_out))
print("")
print("[ALLOC] rv=" .. (ok_a and tostring(N(rv_a)) or "crash") ..
    " phys=" .. fmt(phys))
if not ok_a or N(rv_a) ~= 0 then print("AllocateDirectMemory FAIL"); return end
if not alive() then print("DIED after alloc"); return end

-- Step 2: Try MapDirectMemory via fcall with various flags
-- sceKernelMapDirectMemory(void **addr, size_t len, int prot, int flags,
--                          off_t physAddr, size_t alignment)
-- fcall: fn, rax, rdi(addr), rsi(len), rdx(prot), rcx(flags), r8(phys), r9(align)

local flags_to_try = {0x0, 0x1, 0x2, 0x10, 0x412, 0x40, 0x440, 0x442}

for fi, flags in ipairs(flags_to_try) do
    if not alive() then print("DIED before flags=" .. string.format("0x%X", flags)); break end

    local virt_out = memory.alloc(8)
    wq(N(virt_out), uint64(0))

    print(string.format("\n[MAP %d] flags=0x%X", fi, flags))
    io.flush()

    local ok_m, rv_m = pcall(function()
        return native.fcall_with_rax(map_fn, 0,
            uint64(N(virt_out)), uint64(0x4000), uint64(3),
            uint64(flags), phys, uint64(0x4000))
    end)

    if not alive() then
        print("  PROCESS KILLED")
        break
    end

    if not ok_m then
        print("  pcall FAIL")
    else
        local rv = N(rv_m)
        local vaddr = rq(N(virt_out))
        print("  rv=" .. rv .. " vaddr=" .. (vaddr and fmt(vaddr) or "nil"))

        if rv == 0 and vaddr then
            print("  *** MapDirectMemory SUCCEEDED ***")
            -- Test R/W
            local test_ok = pcall(function()
                memory.write_dword(N(vaddr), 0xDEADBEEF)
            end)
            if test_ok then
                local readback = rd(N(vaddr))
                print("  R/W test: wrote 0xDEADBEEF, read 0x" ..
                    string.format("%X", readback or 0))
                if readback == 0xDEADBEEF then
                    print("  *** DIRECT MEMORY R/W CONFIRMED ***")
                end
            else
                print("  R/W test: write FAILED")
            end
            break
        end
    end
end

print("")
print("alive=" .. tostring(alive()))
print("DONE")
