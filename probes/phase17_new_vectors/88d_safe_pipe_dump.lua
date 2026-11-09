-- CRASH_CLASS: LOW
-- PROBE 88d: Safe pipe/native dump - NO native.read_buffer calls

print("=== PROBE 88d ===")

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

print("pid=" .. to_num(syscall.getpid()))

-- Dump pipe string
print("pipe=" .. tostring(syscall.pipe))

-- Dump all pipe fields
print("--- PIPE FIELDS ---")
for k, v in pairs(syscall.pipe) do
    print("  " .. tostring(k) .. " = " .. tostring(v) .. " [" .. type(v) .. "]")
end

-- Dump native fields (no functions)
print("--- NATIVE ---")
for k, v in pairs(native) do
    if type(v) ~= "function" then
        print("  " .. tostring(k) .. " = " .. tostring(v) .. " [" .. type(v) .. "]")
    else
        print("  " .. tostring(k) .. " = function")
    end
end

-- Try storage.list to see if there's data
print("--- STORAGE LIST ---")
local ok_sl, sl = pcall(storage.list)
print("list ok=" .. tostring(ok_sl))
if ok_sl and sl then
    if type(sl) == "table" then
        for k, v in pairs(sl) do
            print("  " .. tostring(k) .. "=" .. tostring(v))
        end
    else
        print("  val=" .. tostring(sl))
    end
end

-- Storage data table
print("--- STORAGE DATA ---")
if type(storage.data) == "table" then
    local cnt = 0
    for k, v in pairs(storage.data) do
        cnt = cnt + 1
        print("  " .. tostring(k) .. "=" .. tostring(v))
    end
    print("count=" .. cnt)
end

-- Try kinfo_proc to get proc address via kstack
print("")
print("--- KINFO_PROC KSTACK ---")
local pid = to_num(syscall.getpid())
local sc_sysctl = make_syscall(202)
local mib = memory.alloc(16)
memory.write_dword(mib, 1)     -- CTL_KERN
memory.write_dword(mib + 4, 14) -- KERN_PROC
memory.write_dword(mib + 8, 1)  -- KERN_PROC_PID
memory.write_dword(mib + 12, pid)
local outbuf = memory.alloc(0x800)
local oldlenp = memory.alloc(8)
memory.write_dword(oldlenp, 0x800)
local ok_s, ret_s = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
end)
local outlen = to_num(memory.read_dword(oldlenp))
print("sysctl ok=" .. tostring(ok_s) .. " ret=" .. tostring(ret_s) .. " len=" .. outlen)

-- Check specific offsets that might have kernel pointers
-- ki_kstack at offset 0x1B0 (FreeBSD kinfo_proc)
local check_offsets = {0x1B0, 0x1B8, 0x30, 0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68,
    0x100, 0x108, 0x110, 0x118, 0x120, 0x128, 0x130, 0x138, 0x140, 0x148,
    0x150, 0x158, 0x160, 0x168, 0x170, 0x178, 0x180, 0x188, 0x190, 0x198,
    0x1A0, 0x1A8, 0x1C0, 0x1C8, 0x1D0, 0x1D8, 0x1E0, 0x1E8, 0x1F0, 0x1F8,
    0x200, 0x208, 0x210, 0x218, 0x220, 0x228, 0x238, 0x240, 0x248, 0x250,
    0x260, 0x268, 0x270, 0x278, 0x300, 0x308, 0x310, 0x318, 0x320, 0x380,
    0x388, 0x390, 0x398, 0x3A0, 0x3A8, 0x3B0, 0x3B8, 0x400, 0x408, 0x410, 0x418, 0x420, 0x428}
for _, off in ipairs(check_offsets) do
    if off < outlen then
        local lo = to_num(memory.read_dword(outbuf + off))
        local hi = to_num(memory.read_dword(outbuf + off + 4))
        if hi >= 0xFFFF8000 and hi < 0xFFFFFFFF then
            print(string.format("  +0x%03X: 0x%08X%08X KPTR!", off, hi, lo))
        end
    end
end
print("kinfo scan done")

-- Try sysctl kern.proc.kstack (MIB 1.14.11.pid)
print("")
print("--- KSTACK ---")
memory.write_dword(mib, 1)
memory.write_dword(mib + 4, 14)
memory.write_dword(mib + 8, 11)  -- KERN_PROC_KSTACK
memory.write_dword(mib + 12, pid)
memory.write_dword(oldlenp, 0x800)
for i = 0, 0x7FC, 4 do memory.write_dword(outbuf + i, 0) end
local ok_k, ret_k = pcall(function()
    return sc_sysctl(uint64(mib), uint64(4), uint64(outbuf), uint64(oldlenp), uint64(0), uint64(0))
end)
local klen = to_num(memory.read_dword(oldlenp))
print("kstack ok=" .. tostring(ok_k) .. " ret=" .. tostring(ret_k) .. " len=" .. klen)

print("=== PROBE 88d COMPLETE ===")
