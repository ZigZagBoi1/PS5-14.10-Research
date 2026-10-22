-- CRASH_CLASS: HIGH
-- PROBE 424b: ask mmap for RWX, one candidate, written before execution
--
-- 423a walked all 65536 mprotect protection values: 32768 return 0, and the accepted set
-- is exactly the values with bit 2 clear. Bit 2 (0x4) is the execute bit, so mprotect is
-- not blocked - it refuses execute specifically, after the fact.
--
-- mmap is a different check. If a fresh mapping can be created with the execute bit in its
-- protection, there is no need to reprotect anything. Each candidate is verified by
-- execution, not by the return value: the page is filled with `mov [rdi],rax; ret`, a
-- child starts at the page with RAX = marker and RDI = marker page, and the marker is read
-- afterwards. A marker that changed means the page really executed.

print("=== PROBE 424c: MMAP GPU PROT ===")

local MARKER = 0x1234ABCD

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
local function call(num, a1, a2, a3, a4, a5, a6)
    local sc = make_syscall(num)
    local ok, rv = pcall(function()
        return sc(uint64(a1 or 0), uint64(a2 or 0), uint64(a3 or 0), uint64(a4 or 0), uint64(a5 or 0), uint64(a6 or 0))
    end)
    if not ok then return -999 end
    if type(rv) == "table" and rv.h then
        local h, l = to_num(rv.h), to_num(rv.l)
        if h >= 2147483648 then h = h - 4294967296 end
        if l >= 2147483648 then l = l - 4294967296 end
        if h == -1 and l == -1 then return -1 end
        return h * 4294967296 + l
    end
    local n = to_num(rv)
    if n >= 9223372036854775808 then n = n - 18446744073709551616 end
    return n
end
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end
local function u64(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end
local function u64v(v) return u64(math.floor(v / 4294967296), v % 4294967296) end
local function rdq(a)
    local q = memory.read_qword(a)
    if type(q) == "table" then return to_num(q.l) end
    return to_num(q)
end

-- park address from eboot, only used as the child's landing pad after the gadget
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
call(593, 0, sgn(info), 0, 0, 0, 0)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
if size > 0x600000 then size = 0x600000 end
local buf
do
    local ok, b = pcall(function() return memory.read_buffer(base, size) end)
    if not ok or type(b) ~= "string" then print("=== 424c DONE ===") return end
    buf = b
end
local park = 0
do
    local i = 1
    while i < #buf - 1 do
        local x, y = buf:byte(i, i + 1)
        if x == 0xEB and y == 0xFE then park = base + i - 1; break end
        i = i + 1
    end
end
print(string.format("[A] base=0x%X park=0x%X", base, park))
if park <= 0 then print("=== 424c DONE ===") return end

-- One candidate only. 424a tried R|X first and the fill could not write the page (R|X is
-- not writable, and the loader's write path swallows a failed store), so the child executed
-- zeroed memory and the loader entered its fault-dump loop: 257 dumps, then the process
-- died. RWX is the case that can both hold the gadget bytes and be executable.
local cands = {0x33}
local marker = memory.alloc(0x40)

local idx = 1
while idx <= #cands do
    local prot = cands[idx]
    local m = call(477, 0, 0x4000, prot, 0x1002, 0xFFFFFFFF, 0)
    if m <= 0 then
        print(string.format("[B] prot=0x%X mmap rv=%d (refused)", prot, m))
    else
        -- fill the page with mov [rdi],rax; ret
        local off = 0
        while off < 0x100 do
            memory.write_byte(m + off + 0, 0x48)
            memory.write_byte(m + off + 1, 0x89)
            memory.write_byte(m + off + 2, 0x07)
            memory.write_byte(m + off + 3, 0xC3)
            off = off + 4
        end
        memory.write_qword(marker, u64(0, 0))
        local stack = call(477, 0, 0x200000, 3, 0x1002, 0xFFFFFFFF, 0)
        local rsp = stack + 0x100000
        memory.write_qword(rsp, u64v(park))
        local ctx = memory.alloc(0x500)
        local k = 0
        while k < 0x500 do memory.write_dword(ctx + k, 0); k = k + 4 end
        memory.write_qword(ctx + 0x108, u64(0, 0x480))
        memory.write_qword(ctx + 0x110, u64(0, 0x10000))
        memory.write_qword(ctx + 0x0c0, u64(0, 0x43))
        memory.write_qword(ctx + 0x0e0, u64v(m))
        memory.write_qword(ctx + 0x0f0, u64(0, 0x202))
        memory.write_qword(ctx + 0x0f8, u64v(rsp))
        memory.write_qword(ctx + 0x100, u64(0, 0x3b))
        memory.write_qword(ctx + 0x048, u64v(sgn(marker)))
        memory.write_qword(ctx + 0x078, u64(0, MARKER))
        local out = memory.alloc(0x20)
        memory.write_qword(out, u64(0, 0))
        local rv = call(430, sgn(ctx), sgn(out), 0)
        local t = 0
        while t < 4000000 do t = t + 1 end
        local got = rdq(marker)
        print(string.format("[B] prot=0x%X map=0x%X child=%d marker=0x%X %s",
            prot, m, rv, got, (got == MARKER and "EXECUTED" or "not executable")))
    end
    idx = idx + 1
end
print("=== 424c DONE ===")
