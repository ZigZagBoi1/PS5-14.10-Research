-- CRASH_CLASS: LOW
-- PROBE 510b: gadget survey for the child ROP syscall loop.
--
-- 510a found pop rax;ret and pop rsp;ret in the first 1 MB of the eboot text
-- map but no `syscall;ret` and no counter gadget, so the chain could not run.
-- This scans the same map further and reports:
--   * every 0F 05 hit with the 8 bytes that follow it
--   * store gadgets (mov [rdi]/[rsi]/[rdx], rax; ret)
--   * counter gadgets (inc rax / inc [rdi] / add [rdi], 1)
-- Read-only; creates no thread.

print("=== PROBE 510b: gadget survey ===")
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

local sc_info = make_syscall(593)
local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local text_lo, text_hi = rd(info + 0x108), rd(info + 0x10C)
local size = rd(info + 0x118)
if not text_lo then print("module query empty"); print("=== DONE ==="); return end
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] text base=" .. q(eboot) .. " size field(+0x118)=" .. tostring(size))

-- bytes helper: read 16 bytes at addr into a table
local function bytes_at(addr, n)
    local t = {}
    for i = 0, n - 1 do t[i + 1] = rb(addr + i) or -1 end
    return t
end
local function hex(t)
    local s = ""
    for i = 1, #t do s = s .. string.format("%02X ", t[i]) end
    return s
end

local LIMIT = 0x400000
local hit = { pop_rax = nil, pop_rsp = nil, mov_rdi = nil, mov_rsi = nil, mov_rdx = nil,
              inc_rdi = nil, incq_rdi = nil, inc_rax = nil, add_rdi1 = nil }
local syscalls = {}
local counts = { n05 = 0 }
local off = 0
while off < LIMIT do
    local v = rd(eboot + off)
    if not v then break end
    local v2 = rd(eboot + off + 4)
    if v2 then
        local b = {}
        b[1] = v % 0x100
        b[2] = math.floor(v / 0x100) % 0x100
        b[3] = math.floor(v / 0x10000) % 0x100
        b[4] = math.floor(v / 0x1000000) % 0x100
        b[5] = v2 % 0x100
        b[6] = math.floor(v2 / 0x100) % 0x100
        b[7] = math.floor(v2 / 0x10000) % 0x100
        b[8] = math.floor(v2 / 0x1000000) % 0x100
        for k = 1, 4 do
            local a = eboot + off + k - 1
            if not hit.pop_rax and b[k] == 0x58 and b[k + 1] == 0xC3 then hit.pop_rax = a end
            if not hit.pop_rsp and b[k] == 0x5C and b[k + 1] == 0xC3 then hit.pop_rsp = a end
            if not hit.mov_rdi and b[k] == 0x48 and b[k + 1] == 0x89 and b[k + 2] == 0x07 and b[k + 3] == 0xC3 then hit.mov_rdi = a end
            if not hit.mov_rsi and b[k] == 0x48 and b[k + 1] == 0x89 and b[k + 2] == 0x06 and b[k + 3] == 0xC3 then hit.mov_rsi = a end
            if not hit.mov_rdx and b[k] == 0x48 and b[k + 1] == 0x89 and b[k + 2] == 0x02 and b[k + 3] == 0xC3 then hit.mov_rdx = a end
            if not hit.incq_rdi and b[k] == 0x48 and b[k + 1] == 0xFF and b[k + 2] == 0x07 and b[k + 3] == 0xC3 then hit.incq_rdi = a end
            if not hit.inc_rdi and b[k] == 0xFF and b[k + 1] == 0x07 and b[k + 2] == 0xC3 then hit.inc_rdi = a end
            if not hit.inc_rax and b[k] == 0x48 and b[k + 1] == 0xFF and b[k + 2] == 0xC0 then hit.inc_rax = a end
            if not hit.add_rdi1 and b[k] == 0x48 and b[k + 1] == 0x83 and b[k + 2] == 0x07 and b[k + 3] == 0x01 then hit.add_rdi1 = a end
            if b[k] == 0x0F and b[k + 1] == 0x05 then
                counts.n05 = counts.n05 + 1
                if #syscalls < 12 then
                    syscalls[#syscalls + 1] = { addr = a, after = bytes_at(a + 2, 8) }
                end
            end
        end
    end
    off = off + 4
end
print(string.format("[1] scanned 0x%X bytes; 0F05 hits=%d", off, counts.n05))
for name, a in pairs(hit) do
    if a then
        print(string.format("    %-10s %s  bytes %s", name, q(a), hex(bytes_at(a, 8))))
    else
        print("    " .. string.format("%-10s NOT FOUND", name))
    end
end
for i = 1, #syscalls do
    print(string.format("[2] 0F05 at %s -> %s", q(syscalls[i].addr), hex(syscalls[i].after)))
end
print("=== DONE ===")
