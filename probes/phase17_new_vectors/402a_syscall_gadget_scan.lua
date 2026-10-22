-- CRASH_CLASS: LOW
-- PROBE 402a: find a syscall gadget that reloads RAX
--
-- 401a ran the syscall gadget once and parked: the process survived. 400a chained 64
-- returns through the same gadget and died inside thr_create. The reason is now
-- obvious: `syscall` returns a value in RAX, and the next `syscall` in the chain uses
-- that value as its syscall number, so the second call is not 432 any more - it is
-- whatever thr_self returned, which is out of range and fatal.
--
-- A chain therefore needs a gadget that reloads RAX from the stack each time. This
-- scans eboot's readable RX text for the patterns that would do it and reports what
-- exists:
--   0F 05 C3        syscall; ret
--   58 0F 05 C3     pop rax; syscall; ret
--   58 0F 05        pop rax; syscall
--   48 8B 04 24 0F 05 C3   mov rax,[rsp]; syscall; ret
-- Prints up to eight addresses per pattern, then a match count.

print("=== PROBE 402a: SYSCALL GADGET SCAN ===")

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
local function sgn(v)
    local h, l = 0, to_num(v)
    if type(v) == "table" then h = v.h or 0; l = v.l and to_num(v.l) or 0 end
    local x = h * 4294967296 + l
    if x >= 9223372036854775808 then x = x - 18446744073709551616 end
    return x
end

local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
pcall(function() memory.write_dword(info, 0x160) end)
local rv = -999
pcall(function() rv = sgn(sc_info(uint64(0), uint64(info), uint64(0), uint64(0), uint64(0), uint64(0))) end)
local base = to_num(memory.read_dword(info + 0x10C)) * 4294967296 + to_num(memory.read_dword(info + 0x108))
local size = to_num(memory.read_dword(info + 0x110))
print(string.format("[A] base=0x%X size=0x%X", base, size))
if base <= 0 or size <= 0 then print("=== 402a DONE ===") return end
if size > 0x600000 then size = 0x600000 end

local patterns = {
    { name = "syscall; ret",        bytes = "\15\5\195" },
    { name = "pop rax; syscall; ret", bytes = "\88\15\5\195" },
    { name = "pop rax; syscall",    bytes = "\88\15\5" },
}

local hits = {}
for i = 1, #patterns do hits[i] = {} end

local CHUNK = 0x40000
local off = 0
while off < size do
    local n = CHUNK
    if off + n > size then n = size - off end
    local ok, buf = pcall(function() return memory.read_buffer(base + off, n) end)
    if not ok or type(buf) ~= "string" or #buf < 3 then break end
    for pi = 1, #patterns do
        local pat = patterns[pi].bytes
        local pos = 1
        while #hits[pi] < 8 do
            local s = buf:find(pat, pos, true)
            if not s then break end
            hits[pi][#hits[pi] + 1] = base + off + s - 1
            pos = s + 1
        end
    end
    off = off + n
end

for pi = 1, #patterns do
    print(string.format("[%s] found=%d", patterns[pi].name, #hits[pi]))
    for _, a in ipairs(hits[pi]) do print(string.format("    0x%X", a)) end
end

print("=== 402a DONE ===")
