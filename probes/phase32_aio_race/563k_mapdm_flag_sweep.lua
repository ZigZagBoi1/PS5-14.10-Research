-- CRASH_CLASS: LOW
-- PROBE 563k: MapDM flag sweep — does any flag create trace-free PTEs?
--
-- Context: 563j proved trace is on mapping type (MapDM phys=0 kills,
-- dmem0 phys=0 reads fine). But [D] flag sweep never ran because [B]
-- killed the process first. This probe tests 13 flag values via copyin
-- only (no userland read → no trace kill).

print("=== PROBE 563k: MAPDM FLAG SWEEP ===")
print("")

local function N(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}; for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n; setmetatable(t, getmetatable(syscall.pipe)); return t
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if not ok then return nil end
    local n = N(v); if n < 0 then n = n + 0x100000000 end; return n
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local stub = syscall.pipe.fn_addr
local pid = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid)

local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rb(N(ib) + 0x108) or 0; local lhi = rb(N(ib) + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)
print(string.format("lk=0x%X%08X", lhi, llo))

local PAGE = 0x4000
local va_d = uint64("0x890000000")

-- Flag values to test: standard mmap flags, Sony-specific candidates
local flags = {
    0, 1, 2, 3, 4, 5, 6, 7, 8,
    0x10, 0x20, 0x40, 0x80,
    0x100, 0x200, 0x400, 0x800,
    0x1000, 0x2000, 0x4000, 0x8000,
    0x10000, 0x20000, 0x40000,
}

print(string.format("testing %d flag values via copyin (no userland read)", #flags))
print("")
io.flush()

local any_ok = false

for _, fl in ipairs(flags) do
    -- Reserve VA
    pcall(function()
        native.fcall_with_rax(stub, 477,
            va_d, uint64(PAGE), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), Z)
    end)

    -- MapDM with this flag
    local ok_m, rv_m = pcall(function()
        return native.fcall_with_rax(mapdm_fn, 0,
            va_d, uint64(PAGE), uint64(3), uint64(fl),
            Z, uint64(PAGE))
    end)
    local r = ok_m and N(rv_m) or -999
    local status = "rv=" .. r

    if r == 0 then
        -- copyin test via socketpair write
        local sp = memory.alloc(16)
        wq(N(sp), Z)
        pcall(function()
            native.fcall_with_rax(stub, 135,
                uint64(1), uint64(2), uint64(0), sp)
        end)
        local fa = rb(N(sp)) or -1
        local fb = rb(N(sp) + 4) or -1
        if fa >= 0 then
            local ok_w, rv_w = pcall(function()
                return native.fcall_with_rax(stub, 4,
                    uint64(fa), va_d, uint64(8))
            end)
            local w = ok_w and N(rv_w) or -999
            if w > 0 then
                local rbuf = memory.alloc(16)
                pcall(function()
                    native.fcall_with_rax(stub, 3, uint64(fb), rbuf, uint64(8))
                end)
                local q0 = rb(N(rbuf)) or 0
                local q4 = rb(N(rbuf) + 4) or 0
                status = string.format("rv=0 COPYIN_OK! data=%08X_%08X", q4, q0)
                any_ok = true
            else
                status = "rv=0 copyin=EFAULT"
            end
            pcall(function() native.fcall_with_rax(stub, 6, uint64(fa)) end)
            pcall(function() native.fcall_with_rax(stub, 6, uint64(fb)) end)
        else
            status = "rv=0 socketpair_fail"
        end
    end

    -- Unmap
    pcall(function()
        native.fcall_with_rax(stub, 73, va_d, uint64(PAGE))
    end)

    print(string.format("  flags=0x%05X: %s", fl, status))
end

io.flush()
print("")
if any_ok then
    print("*** FOUND FLAG THAT BYPASSES TRACE! ***")
else
    print("ALL flags → EFAULT or fail. MapDM PTE type is unconditional.")
end

local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563k DONE ===")
