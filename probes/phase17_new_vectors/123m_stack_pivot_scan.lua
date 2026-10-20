-- CRASH_CLASS: LOW
-- PROBE 123m: Stack pivot gadget scan across full eboot
--
-- No leave;ret found in eboot. Scan for alternative pivots:
--   xchg rax,rsp; ret  = 48 94 C3
--   xchg rdi,rsp; ret  = 48 87 FC C3 (REX.W xchg rsp,rdi)
--   xchg rsi,rsp; ret  = 48 87 F4 C3
--   xchg rcx,rsp; ret  = 48 87 CC C3
--   xchg rdx,rsp; ret  = 48 87 D4 C3
--   xchg rbx,rsp; ret  = 48 87 DC C3
--   xchg rbp,rsp; ret  = 48 87 EC C3
--   mov rsp,[rax]; ...  = 48 8B 20 (mov rsp,[rax])
--   mov rsp,[rdi]; ...  = 48 8B 24 3F (mov rsp,[rdi]) — SIB
--   mov rsp,rax; ret   = 48 89 C4 C3
--   mov rsp,rbp; ret   = 48 89 EC C3 (same as leave without pop)
--   mov rsp,rdi; ret   = 48 89 FC C3
--   push rax; ... ret  patterns
--   jmp rax = FF E0
--   jmp [rax] = FF 20
--   call rax = FF D0
--   Also: leave;ret = C9 C3 (recheck, maybe missed unaligned)
-- Scan full 4.5MB, print live.

print("=== PROBE 123m: STACK PIVOT SCAN ===")
print("")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end

local function get_eboot_base()
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    local sc_info = make_syscall(593)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108)
    local hi = safe_rd(info + 0x10C)
    if lo and hi then
        return uint64(string.format("0x%X%08X", hi, lo)), hi, lo
    end
    return nil, 0, 0
end

collectgarbage("stop")

local eboot_base, eboot_hi, eboot_lo = get_eboot_base()
print(string.format("[*] eboot: 0x%08X_%08X", eboot_hi, eboot_lo))
if not eboot_base then print("ABORT") return end

local function ea(off)
    local lo = eboot_lo + off
    local hi = eboot_hi
    if lo >= 0x100000000 then hi = hi + 1; lo = lo - 0x100000000 end
    return uint64(string.format("0x%X%08X", hi, lo))
end

-- Scan in two halves to avoid timeout: 0-0x240000 first
-- Each half is ~2.25MB = ~576K dwords with safe_rd ~8s

local HALF1_END = 0x240000
local HALF2_END = 0x480000
local read_fail = nil

print("--- Phase 1: 0x000000-0x240000 ---")

for off = 0, HALF1_END - 4, 4 do
    local dw = safe_rd(ea(off))
    if dw == nil then read_fail = off; break end

    local b0 = dw % 256
    local b1 = math.floor(dw / 256) % 256
    local b2 = math.floor(dw / 65536) % 256
    local b3 = math.floor(dw / 16777216) % 256

    -- 3-byte patterns ending with C3 at aligned+0: XX XX C3 in b0-b2
    -- xchg rax,rsp;ret = 48 94 C3 → b0=48 b1=94 b2=C3
    if b0 == 0x48 and b1 == 0x94 and b2 == 0xC3 then
        print(string.format("  XCHG_RAX_RSP_RET: +0x%06X", off))
    end

    -- mov rsp,rax;ret = 48 89 C4 C3 → b0=48 b1=89 b2=C4 b3=C3
    if b0 == 0x48 and b1 == 0x89 and b2 == 0xC4 and b3 == 0xC3 then
        print(string.format("  MOV_RSP_RAX_RET: +0x%06X", off))
    end
    -- mov rsp,rbp;ret = 48 89 EC C3
    if b0 == 0x48 and b1 == 0x89 and b2 == 0xEC and b3 == 0xC3 then
        print(string.format("  MOV_RSP_RBP_RET: +0x%06X", off))
    end
    -- mov rsp,rdi;ret = 48 89 FC C3
    if b0 == 0x48 and b1 == 0x89 and b2 == 0xFC and b3 == 0xC3 then
        print(string.format("  MOV_RSP_RDI_RET: +0x%06X", off))
    end
    -- mov rsp,rsi;ret = 48 89 F4 C3
    if b0 == 0x48 and b1 == 0x89 and b2 == 0xF4 and b3 == 0xC3 then
        print(string.format("  MOV_RSP_RSI_RET: +0x%06X", off))
    end

    -- xchg REG,rsp;ret = 48 87 XX C3 where XX encodes the register
    if b0 == 0x48 and b1 == 0x87 and b3 == 0xC3 then
        local reg_names = {[0xCC]="rcx", [0xD4]="rdx", [0xDC]="rbx",
            [0xEC]="rbp", [0xF4]="rsi", [0xFC]="rdi"}
        if reg_names[b2] then
            print(string.format("  XCHG_%s_RSP_RET: +0x%06X", string.upper(reg_names[b2]), off))
        end
    end

    -- mov rsp,[rax] = 48 8B 20 (no ret required, just find it)
    if b0 == 0x48 and b1 == 0x8B and b2 == 0x20 then
        print(string.format("  MOV_RSP_[RAX]: +0x%06X (next: %02X)", off, b3))
    end

    -- leave;ret at any byte boundary
    if b0 == 0xC9 and b1 == 0xC3 then
        print(string.format("  LEAVE_RET: +0x%06X", off))
    end
    if b1 == 0xC9 and b2 == 0xC3 then
        print(string.format("  LEAVE_RET: +0x%06X", off+1))
    end
    if b2 == 0xC9 and b3 == 0xC3 then
        print(string.format("  LEAVE_RET: +0x%06X", off+2))
    end

    -- jmp rax = FF E0
    if b0 == 0xFF and b1 == 0xE0 then
        print(string.format("  JMP_RAX: +0x%06X", off))
    end
    -- jmp [rax] = FF 20
    if b0 == 0xFF and b1 == 0x20 then
        print(string.format("  JMP_[RAX]: +0x%06X", off))
    end
    -- call rax = FF D0
    if b0 == 0xFF and b1 == 0xD0 then
        print(string.format("  CALL_RAX: +0x%06X", off))
    end
    -- jmp rdi = FF E7, jmp [rdi] = FF 27
    if b0 == 0xFF and b1 == 0xE7 then
        print(string.format("  JMP_RDI: +0x%06X", off))
    end
    if b0 == 0xFF and b1 == 0x27 then
        print(string.format("  JMP_[RDI]: +0x%06X", off))
    end

    -- push rax;ret = 50 C3
    if b0 == 0x50 and b1 == 0xC3 then
        print(string.format("  PUSH_RAX_RET: +0x%06X", off))
    end
    -- push rdi;ret = 57 C3
    if b0 == 0x57 and b1 == 0xC3 then
        print(string.format("  PUSH_RDI_RET: +0x%06X", off))
    end
end

if read_fail then
    print(string.format("[!] Read failed at +0x%X", read_fail))
end

print("")
print("=== PROBE 123m PHASE 1 COMPLETE ===")
