-- CRASH_CLASS: LOW
-- PROBE 937a: wide gadget scan for a five-argument child chain
--
-- Context: the aio delete race needs a child thread that can issue TWO
-- syscalls in one chain -- 662(ids,count,status) to free the target, then a
-- create to put a new object back in the same slot (669(flags,data,count,mode,out),
-- five arguments).  884a/883b showed a straight-line chain works, so the only
-- open question is whether eboot contains the pops for the extra registers:
--   pop r8;ret   = 41 58 C3
--   pop r9;ret   = 41 59 C3
--   pop rcx;ret  = 59 C3      (904b showed the 2-byte form found by pattern
--                              matching broke every spawn -- likely mid-instruction)
-- Nothing is executed here; this only reads eboot's RX text and prints hit
-- addresses plus 12 bytes of context so a false match can be spotted.

print("=== PROBE 937a: WIDE GADGET SCAN ===")
print("")

local function to_num(v)
    if type(v) == "table" then
        if v.tonumber then local n = v:tonumber() if n then return n end end
        if v.h then return v.h * 4294967296 + v.l end
    end
    return tonumber(v) or 0
end
local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a) local o, v = pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a, v) pcall(function() memory.write_dword(a, v) end) end
local function hexs(s)
    local out = {}
    for i = 1, #s do out[#out + 1] = string.format("%02X", string.byte(s, i)) end
    return table.concat(out, " ")
end

print("[0] pid=" .. tostring(to_num(native.fcall_with_rax(syscall.pipe.fn_addr, 20))))

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info + 0x10C) or 0) * 4294967296 + (rd(info + 0x108) or 0)
print(string.format("[0] eboot text base = 0x%X", ebase))

local LIMIT = 0x494000

local function find_all(pat, maxhits)
    local hits = {}
    local off = 0
    while off < LIMIT and #hits < (maxhits or 8) do
        local want = LIMIT - off
        if want > 0x2000 then want = 0x2000 end
        local ok, s = pcall(function() return memory.read_buffer(ebase + off, want) end)
        if not ok or type(s) ~= "string" or #s == 0 then break end
        local pos = 1
        while true do
            local i = string.find(s, pat, pos, true)
            if not i then break end
            hits[#hits + 1] = ebase + off + i - 1
            if #hits >= (maxhits or 8) then break end
            pos = i + 1
        end
        off = off + want
    end
    return hits
end

local function context(addr, before, after)
    local ok, s = pcall(function() return memory.read_buffer(addr - before, before + after) end)
    if ok and type(s) == "string" then return hexs(s) end
    return "<read failed>"
end

local pats = {
    { name = "pop r8;ret",  pat = string.char(0x41, 0x58, 0xC3) },
    { name = "pop r9;ret",  pat = string.char(0x41, 0x59, 0xC3) },
    { name = "pop rcx;ret", pat = string.char(0x59, 0xC3) },
    { name = "pop rdx;ret", pat = string.char(0x5A, 0xC3) },
    { name = "pop rsi;ret", pat = string.char(0x5E, 0xC3) },
    { name = "pop rdi;ret", pat = string.char(0x5F, 0xC3) },
    { name = "pop rax;ret", pat = string.char(0x58, 0xC3) },
    { name = "mov [rdi],rax;ret", pat = string.char(0x48, 0x89, 0x07, 0xC3) },
}

for _, p in ipairs(pats) do
    local hits = find_all(p.pat, 4)
    print(string.format("[G] %-16s hits=%d", p.name, #hits))
    for i = 1, math.min(#hits, 2) do
        local a = hits[i]
        print(string.format("      %X  ctx: %s", a, context(a, 4, 8)))
    end
end

print("")
print("=== PROBE 937a COMPLETE ===")
