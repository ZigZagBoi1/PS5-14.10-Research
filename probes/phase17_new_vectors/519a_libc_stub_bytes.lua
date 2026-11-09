-- CRASH_CLASS: LOW
-- PROBE 519a: bytes of libc's most-used syscall helper.
--
-- 518a ranked call targets for mov-eax-immediate wrappers.  0x103230108
-- (34 sites, sample number 7) is the top one and sits on libc's first page,
-- which is where a PLT-style trampoline lives.  This dumps the area and follows
-- any `FF 25` (jmp [rip+disp]) through its GOT slot, which should be the
-- libkernel syscall entry.

print("=== PROBE 519a: LIBC STUB BYTES ===")
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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok then return to_num(v) end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(a) end)
    if ok then return v end
    return nil
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(a, v) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return to_num(val.h), to_num(val.l) end
    return 0, tonumber(val) or 0
end
local function hexline(a, n)
    local s = ""
    for i = 0, n - 1 do
        local d = rd(a + i)
        if d then s = s .. string.format("%02X ", d % 256) else s = s .. "?? " end
    end
    return s
end
local function sext32(x)
    if x >= 2147483648 then return x - 4294967296 end
    return x
end

local sc_getpid = make_syscall(20)
pcall(function() return sc_getpid() end)

local base = 0x103230000
print(string.format("[0] hexdump around the top target %08X", base + 0x108))
for off = 0xF0, 0x180, 16 do
    print(string.format("    %08X  %s", base + off, hexline(base + off, 16)))
end

print("[1] FF 25 / FF 15 sites on the first page:")
for off = 0, 0x400, 1 do
    local d = rd(base + off)
    if d then
        local op = d % 256
        local op2 = math.floor(d / 256) % 256
        if op == 0xFF and (op2 == 0x25 or op2 == 0x15) then
            local disp = rd(base + off + 2)
            if disp then
                local slot = (base + off + 6 + sext32(disp)) % 0x1000000000000
                local q = rq(uint64(slot))
                local qh, ql = 0, 0
                if q ~= nil then qh, ql = get_hi_lo(q) end
                print(string.format("    %08X %s -> slot %08X = 0x%08X_%08X",
                    base + off, op2 == 0x25 and "jmp" or "call", slot, qh, ql))
            end
        end
    end
end

print("[2] qwords at the top target:")
for i = 0, 7 do
    local q = rq(base + 0x100 + i * 8)
    if q ~= nil then
        local qh, ql = get_hi_lo(q)
        print(string.format("    %08X 0x%08X_%08X", base + 0x100 + i * 8, qh, ql))
    end
end
print("=== DONE ===")
