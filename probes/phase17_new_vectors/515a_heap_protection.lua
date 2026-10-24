-- CRASH_CLASS: LOW
-- PROBE 515a: is the loader's fcall target in executable memory?
--
-- 514b: every other pointer in the loader block carries the 0x3 heap tag, but
-- fn_addr carries 0x9FE5 in bits 32-47 over the same low 32 bits.  If the loader
-- calls into that address, the region containing it must be executable.  This
-- asks sys 674 for the region list and prints the protection of the regions
-- holding the chain, the fn slot, and the candidate address.

print("=== PROBE 515a: HEAP PROTECTION ===")
local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "string" then return #v == 1 and string.byte(v) or 0 end
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
    if type(val) == "table" and val.h then return to_num(val.h), to_num(val.l) end
    return 0, tonumber(val) or 0
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(a, v) end)
    return ok
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = rd(a + i) or 0
        b = b % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end
local function hexq(v)
    if v == nil then return "nil" end
    local h, l = get_hi_lo(v)
    return string.format("0x%08X_%08X", h, l)
end

local sc_getpid = make_syscall(20)
local sc674 = make_syscall(674)
pcall(function() return sc_getpid() end)
local ps = tostring(syscall.pipe)
local rop_str = ps:match("ropchain @ (0x[0-9a-fA-F]+)")
local fn_str = ps:match("fcall_stub%.fn_addr: (0x[0-9a-fA-F]+)")
local rop = uint64(rop_str)
local fn_slot = uint64(fn_str)
local fv = rq(fn_slot)
local fh, fl = get_hi_lo(fv)
local cand = 0x300000000 + fl
print(string.format("[0] rop=%s slot=%s", rop_str, fn_str))
print(string.format("[0] fn=0x%08X_%08X candidate=0x%X", fh, fl, cand))
print(string.format("[0] dword at candidate=%s +16=%s",
    tostring(rd(cand)), tostring(rd(cand + 16))))

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(buf + i, 0) end
local countp = memory.alloc(16)
wq(countp, uint64(0))
local ok, ret = pcall(function()
    return sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
end)
print(string.format("[1] 674 ret=%s", ok and tostring(to_num(ret)) or "pcall-fail"))
local count = rd(countp) or 0
print("[1] regions=" .. count)
if count > MAX then count = MAX end

local targets = {
    {"rop", to_num(rop)},
    {"slot", to_num(fn_slot)},
    {"cand", cand},
    {"chain2", 0x300000000 + (to_num(rq(rop + 0x10)) % 0x100000000)},
}
for t = 1, #targets do
    local name, addr = targets[t][1], targets[t][2]
    local found = false
    for i = 0, count - 1 do
        local base = buf + i * STRIDE
        local lo = rd(base)
        local lo2 = rd(base + 4)
        local hi = rd(base + 8)
        local hi2 = rd(base + 12)
        if lo and hi then
            local start_a = lo + lo2 * 4294967296
            local end_a = hi + hi2 * 4294967296
            if addr >= start_a and addr < end_a then
                local prot = rd(base + 0x18) or 0
                print(string.format("[2] %-6s %08X in [%X,%X) prot=%08X name=%s",
                    name, addr, start_a, end_a, prot, ascii(base + 0x20, 0x18)))
                found = true
                break
            end
        end
    end
    if not found then print(string.format("[2] %-6s %08X not in any region", name, addr)) end
end

-- list every region with an executable bit, capped
print("[3] regions with prot bit 1 or 4 set (first 20):")
local shown = 0
for i = 0, count - 1 do
    local base = buf + i * STRIDE
    local prot = rd(base + 0x18) or 0
    if (prot % 8) ~= 0 and shown < 20 then
        local lo = (rd(base) or 0) + (rd(base + 4) or 0) * 4294967296
        local hi = (rd(base + 8) or 0) + (rd(base + 12) or 0) * 4294967296
        print(string.format("    [%X,%X) prot=%08X name=%s", lo, hi, prot, ascii(base + 0x20, 0x18)))
        shown = shown + 1
    end
end
print("=== DONE ===")
