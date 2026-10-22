-- CRASH_CLASS: HIGH
-- PROBE 179a: find which argument positions sys 619 (test_debug_rwmem) validates
--
-- Context: the 601-660 presence sweep shows 619 has a handler (returns -1 for six
-- zero args) while 622 kills on the same shape even though 55c got ret=0 from it
-- with real arguments. So -1 is the interesting answer here: the handler runs and
-- rejects. This probe moves one argument at a time to a valid pointer, the calling
-- pid, and small integers, and records where the return changes.
--
-- Pointers are passed as the raw memory.alloc value (that is what
-- dynlib_get_info(593) calls do); integers go through uint64(string.format(...)).

print("=== PROBE 179a: SYS 619 test_debug_rwmem ARGUMENTS ===")
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
local function u64(v)
    return uint64(string.format("0x%08X", v))
end
local function hex(v)
    local ok, s = pcall(function() return tostring(v) end)
    if ok then return s end
    return "?"
end
local function dq(addr)
    local ok, v = pcall(function() return memory.read_qword(addr) end)
    if ok then return hex(v) end
    return "(fault)"
end
local function dd(addr)
    local ok, v = pcall(function() return memory.read_dword(addr) end)
    if ok then return string.format("0x%08X", to_num(v)) end
    return "(fault)"
end

local sc619 = make_syscall(619)
local sc20 = make_syscall(20)
local pid = to_num(sc20())

local src = memory.alloc(0x1000)
local dst = memory.alloc(0x1000)
for off = 0, 0xFFF, 8 do
    pcall(function() memory.write_qword(src + off, u64(0x41414141)) end)
    pcall(function() memory.write_qword(dst + off, u64(0x42424242)) end)
end
pcall(function() memory.write_qword(src, uint64("0x1122334455667788")) end)
pcall(function() memory.write_qword(dst, uint64("0x9999888877776666")) end)

print("[0] pid=" .. tostring(pid) .. " src=" .. hex(src) .. " dst=" .. hex(dst))
print("[0] src[0]=" .. dq(src) .. " dst[0]=" .. dq(dst))
print("")

local function attempt(label, a1, a2, a3, a4, a5, a6)
    print("[*] " .. label)
    local ok, ret = pcall(function() return sc619(a1, a2, a3, a4, a5, a6) end)
    if not ok then
        print("[!] pcall failed")
        return
    end
    print(string.format("    ret=0x%08X  src[0]=%s dst[0]=%s dword=%s",
        to_num(ret), dq(src), dq(dst), dd(dst)))
end

local zero = u64(0)
attempt("all zero", zero, zero, zero, zero, zero, zero)
attempt("arg1=pid", u64(pid % 0x100000000), zero, zero, zero, zero, zero)
attempt("arg1=1", u64(1), zero, zero, zero, zero, zero)
attempt("arg1=dst", dst, zero, zero, zero, zero, zero)
attempt("arg2=dst", zero, dst, zero, zero, zero, zero)
attempt("arg3=dst", zero, zero, dst, zero, zero, zero)
attempt("arg4=16", zero, zero, zero, u64(16), zero, zero)
attempt("arg5=16", zero, zero, zero, zero, u64(16), zero)
attempt("arg6=1", zero, zero, zero, zero, zero, u64(1))
print("")

-- whole-request shapes: (pid, addr, buf, size, write, ?)
attempt("pid,src,dst,16,0", u64(pid % 0x100000000), src, dst, u64(16), zero, zero)
attempt("pid,src,dst,16,1", u64(pid % 0x100000000), src, dst, u64(16), u64(1), zero)
attempt("pid,dst,src,16,1", u64(pid % 0x100000000), dst, src, u64(16), u64(1), zero)
attempt("src,dst,16,0", src, dst, u64(16), zero, zero, zero)
attempt("src,dst,16,1", src, dst, u64(16), u64(1), zero, zero)
attempt("src,8,0", src, u64(8), zero, zero, zero, zero)

print("")
print("[*] done")
