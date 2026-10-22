-- CRASH_CLASS: LOW
-- PROBE 426a: can dlsym resolve the JIT and memory API names
--
-- The loader resolves syscall 0x24f as `dlsym` itself (main.lua:283), so a symbol lookup is
-- one call away. Games that generate code at runtime need an executable mapping, and the
-- JIT helpers are the ones that hand it out. If any of these names resolve, the address is
-- a userland function this process can call - 129b already proved arbitrary userland calls
-- work - and the next step would be asking it for executable memory.
--
-- Handles tried: RTLD_DEFAULT (-2) and 0, then a module handle if the dynlib query gives one.

print("=== PROBE 426a: DLSYM JIT ===")

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
local function cstr(s)
    local b = memory.alloc(0x80)
    local i = 1
    while i <= #s do memory.write_byte(b + i - 1, s:byte(i)); i = i + 1 end
    memory.write_byte(b + #s, 0)
    return b
end

local handles = {}
handles[1] = { "RTLD_DEFAULT (-2)", 0xFFFFFFFFFFFFFFFE }
handles[2] = { "zero", 0 }
handles[3] = { "one", 1 }
handles[4] = { "minus1", 0xFFFFFFFFFFFFFFFF }

local names = {
    "sceKernelJitCreateSharedMemory",
    "sceKernelJitCreateAliasOfSharedMemory",
    "sceKernelJitMapSharedMemory",
    "sceKernelMapFlexibleMemory",
    "sceKernelMapDirectMemory",
    "sceKernelAllocateDirectMemory",
    "sceKernelMprotect",
    "mmap",
    "mprotect",
    "sceKernelGetDirectMemorySize",
}

local h = 1
while h <= #handles do
    local label = handles[h][1]
    local hv = handles[h][2]
    local hits = 0
    local i = 1
    while i <= #names do
        local np = cstr(names[i])
        local rv = call(0x24f, hv, sgn(np), 0, 0, 0, 0)
        if rv ~= 0 and rv ~= -1 and rv ~= -999 then
            print(string.format("[A] %s  %-38s -> 0x%X", label, names[i], rv))
            hits = hits + 1
        end
        i = i + 1
    end
    print(string.format("[A] %s: %d of %d resolved", label, hits, #names))
    h = h + 1
end

-- [B] a module handle from the dynlib query, if one is exposed
local info = memory.alloc(0x200)
memory.write_dword(info, 0x160)
local rv = call(593, 0, sgn(info), 0, 0, 0, 0)
print(string.format("[B] dynlib query rv=%d", rv))
local candidates = {}
local off = 0
while off < 0x180 do
    local v = to_num(memory.read_dword(info + off))
    if v > 0 and v < 0x100000 then candidates[#candidates + 1] = v end
    off = off + 4
end
print(string.format("[B] first dwords: %s", table.concat(candidates, ",")))
print("=== 426a DONE ===")
