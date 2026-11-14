-- CRASH_CLASS: LOW
-- PROBE 1213d: wide tails for every r10 / syscall hit in eboot .text.
--
-- 1213c found 15 "mov r10, rcx" and 18 "0f 05" sites across the 0x494000-byte image but only
-- printed 24 bytes each, which is not enough to tell a register-only shim from arithmetic.
-- This run re-scans and prints 96 bytes per r10 hit and 48 per syscall hit, and flags any r10
-- hit that reaches a c3 within 48 bytes. It reads eboot only.

print("=== PROBE 1213d: wide tails for r10 and syscall sites ===")
local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local eb = N(eboot_base)
local SIZE, CH = 0x494000, 0x8000
print(string.format("[0] eboot=0x%X", eb))

local function hex(buf, pos, n)
    local s = {}
    for k = 0, n - 1 do
        local b = string.byte(buf, pos + k)
        if not b then break end
        s[#s + 1] = string.format("%02X", b)
    end
    return table.concat(s, " ")
end

local r10 = string.char(0x49,0x89,0xca)
local sc  = string.char(0x0f,0x05)
local off = 0
while off < SIZE do
    local want = math.min(CH, SIZE - off)
    local ok, buf = pcall(function() return memory.read_buffer(eb + off, want) end)
    if not ok then print(string.format("[!] read failed at +0x%X", off)) break end
    local i = 1
    while true do
        local a, b = string.find(buf, r10, i, true)
        if not a then break end
        local ret_at = nil
        for k = 0, 48 do
            local v = string.byte(buf, a + 3 + k)
            if v == 0xC3 then ret_at = 3 + k break end
        end
        print(string.format("[R] eboot+0x%X ret_in=%s | %s", off + a - 1, tostring(ret_at), hex(buf, a, 96)))
        i = b + 1
    end
    i = 1
    while true do
        local a, b = string.find(buf, sc, i, true)
        if not a then break end
        print(string.format("[S] eboot+0x%X | %s", off + a - 1, hex(buf, a, 48)))
        i = b + 1
    end
    off = off + want
end
print("=== DONE ===")
