-- CRASH_CLASS: HIGH (725 killed zero-args callers in the 14.10 sweep; real args
-- are this probe's point - one connection at risk)
-- PROBE 277a: mmap2(725) real-args survey (alternate mapping entry point)
--
-- Context: 13.60 handler at rva 0xab8430 (docs/SYSENT_PRESENCE_14_10.md):
--   arg0 addr, arg1 len, arg2 prot u32, arg3 flags u32 (r12d), arg4 qword
--   (mapping type / object), arg5 offset.
--   Reads the proc+0xc81 gate byte first; flags have an extended form
--   (high byte 0x01 kept when gate set); flag 0x200000 takes a separate path.
--   477-mmap's known-good shapes on 14.10: (0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0).
-- If 725 is alive with real args, it is a second mapping entry point whose
-- protection policy has never been measured - the W^X wall (mmap RWX->RW,
-- mprotect EXEC fails) has only ever been tested through 477 and 74.

print("=== PROBE 277a: mmap2 real args ===")
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
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(addr, n)
    for off = 0, n - 1, 8 do wq(addr + off, uint64(0)) end
end

local sc725 = make_syscall(725)
local function m2(label, addr, len, prot, flags, arg4, off)
    local ok, rv = pcall(function()
        return sc725(uint64(addr), uint64(len), uint64(prot), uint64(flags), uint64(arg4), uint64(off))
    end)
    print(string.format("    %-52s ret=%s", label, raw(rv)))
    return ok, rv
end

print("[A] baseline: 477-known-good shape through 725")
m2("(0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)", 0, 0x4000, 3, 0x1002, 0xFFFFFFFF, 0)
m2("(0, 0x4000, 0, 0x1002, 0xFFFFFFFF, 0) prot=0", 0, 0x4000, 0, 0x1002, 0xFFFFFFFF, 0)
m2("(0, 0x4000, 1, 0x1002, 0xFFFFFFFF, 0) prot=R", 0, 0x4000, 1, 0x1002, 0xFFFFFFFF, 0)

print("[B] exec-protection probes (the W^X question)")
m2("(0, 0x4000, 5, 0x1002, 0xFFFFFFFF, 0) prot=RX", 0, 0x4000, 5, 0x1002, 0xFFFFFFFF, 0)
m2("(0, 0x4000, 7, 0x1002, 0xFFFFFFFF, 0) prot=RWX", 0, 0x4000, 7, 0x1002, 0xFFFFFFFF, 0)
m2("(0, 0x4000, 4, 0x1002, 0xFFFFFFFF, 0) prot=X only", 0, 0x4000, 4, 0x1002, 0xFFFFFFFF, 0)

print("[C] extended flags and special bit 0x200000")
m2("(0, 0x4000, 3, 0x3002, 0xFFFFFFFF, 0)", 0, 0x4000, 3, 0x3002, 0xFFFFFFFF, 0)
m2("(0, 0x4000, 3, 0x210002, 0xFFFFFFFF, 0) bit0x200000", 0, 0x4000, 3, 0x210002, 0xFFFFFFFF, 0)
m2("(0, 0x4000, 3, 0x1000000, 0xFFFFFFFF, 0) ext-hi", 0, 0x4000, 3, 0x1000000, 0xFFFFFFFF, 0)

print("[D] arg4 variants (mapping type?)")
m2("(0, 0x4000, 3, 0x1002, 0x33, 0) gpu-type", 0, 0x4000, 3, 0x1002, 0x33, 0)
m2("(0, 0x4000, 3, 0x1002, 0, 0)", 0, 0x4000, 3, 0x1002, 0, 0)
m2("(0, 0x4000, 3, 0x1002, 1, 0)", 0, 0x4000, 3, 0x1002, 1, 0)

local okp, pid = pcall(function() return make_syscall(20)():tonumber() end)
print("")
print("[E] canary: ok=" .. tostring(okp) .. " pid=" .. tostring(pid))
print("=== END 277a ===")
