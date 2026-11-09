-- CRASH_CLASS: LOW
-- PROBE 85g: Safe kernel pointer hunt - no blocking calls

print("=== PROBE 85g ===")

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

local pid = to_num(syscall.getpid())
print("pid=" .. pid)

-- 1: kinfo_proc full scan
print("--- KINFO_PROC SCAN ---")
local mib = memory.alloc(16)
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 1)
memory.write_dword(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
memory.write_qword(oldlenp, uint64(0x800))
local ret = make_syscall(202)(uint64(mib), uint64(4), uint64(outbuf),
    uint64(oldlenp), uint64(0), uint64(0))
print("ret=" .. tostring(ret))
local rlen = to_num(memory.read_qword(oldlenp))
print("len=" .. rlen)
local kptr_count = 0
for off = 0, math.min(rlen - 1, 0x7FF), 8 do
    local q = memory.read_qword(outbuf + off)
    local h, l = get_hi_lo(q)
    if h >= 0xFFFF8000 then
        kptr_count = kptr_count + 1
        print(string.format("KPTR +0x%03X: %s", off, tostring(q)))
    end
end
print("kptr_count=" .. kptr_count)

-- 2: kqueue
print("")
print("--- KQUEUE ---")
local kq = to_num(make_syscall(362)())
print("kq=" .. kq)
if kq > 0 then
    syscall.close(uint64(kq))
end

-- 3: Try kern.proc.args
print("")
print("--- KERN_PROC_ARGS ---")
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 7)  -- KERN_PROC_ARGS
memory.write_dword(mib + 12, pid)
memory.write_qword(oldlenp, uint64(0x800))
for i = 0, 0x7FC, 4 do memory.write_dword(outbuf + i, 0) end
local ok3, ret3 = pcall(function()
    return make_syscall(202)(uint64(mib), uint64(4), uint64(outbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
print("args ok=" .. tostring(ok3) .. " ret=" .. tostring(ret3))
if ok3 and to_num(ret3) == 0 then
    local alen = to_num(memory.read_qword(oldlenp))
    print("len=" .. alen)
    -- Print as string
    local s = ""
    for i = 0, math.min(alen - 1, 255) do
        local b = to_num(memory.read_byte(outbuf + i))
        if b >= 32 and b <= 126 then s = s .. string.char(b)
        elseif b == 0 then s = s .. " "
        end
    end
    if #s > 0 then print("args=" .. s) end
end

-- 4: Try SCE-specific sysctl
print("")
print("--- SCE SYSCTL ---")
-- Try machdep.tsc_freq (MIB 7.0 ?)
memory.write_dword(mib, 7)  -- CTL_MACHDEP
memory.write_dword(mib + 4, 0)
memory.write_qword(oldlenp, uint64(0x100))
for i = 0, 0xFC, 4 do memory.write_dword(outbuf + i, 0) end
local ok4, ret4 = pcall(function()
    return make_syscall(202)(uint64(mib), uint64(2), uint64(outbuf),
        uint64(oldlenp), uint64(0), uint64(0))
end)
print("machdep.0 ok=" .. tostring(ok4) .. " ret=" .. tostring(ret4))
if ok4 and to_num(ret4) == 0 then
    local mlen = to_num(memory.read_qword(oldlenp))
    print("len=" .. mlen)
    for off = 0, math.min(mlen - 1, 0x1F), 8 do
        local q = memory.read_qword(outbuf + off)
        local h, l = get_hi_lo(q)
        if h ~= 0 or l ~= 0 then
            print(string.format("+0x%02X=%s", off, tostring(q)))
        end
    end
end

-- 5: Try to get process file descriptor info via fstat(2)
-- fstat = 551 (FreeBSD)
print("")
print("--- FSTAT ---")
local statbuf = memory.alloc(0x100)
for i = 0, 0xFC, 4 do memory.write_dword(statbuf + i, 0) end
-- fstat on our kqueue fd or socket fd
local tfd = to_num(syscall.socket(uint64(28), uint64(2), uint64(17)))
print("test_fd=" .. tfd)
local ok5, ret5 = pcall(function()
    return make_syscall(551)(uint64(tfd), uint64(statbuf))
end)
print("fstat ok=" .. tostring(ok5) .. " ret=" .. tostring(ret5))
if ok5 and to_num(ret5) == 0 then
    for off = 0, 0x78, 8 do
        local q = memory.read_qword(statbuf + off)
        local h, l = get_hi_lo(q)
        if h >= 0xFFFF8000 then
            print(string.format("KPTR +0x%02X: %s", off, tostring(q)))
        end
    end
end
syscall.close(uint64(tfd))

print("=== PROBE 85g COMPLETE ===")
