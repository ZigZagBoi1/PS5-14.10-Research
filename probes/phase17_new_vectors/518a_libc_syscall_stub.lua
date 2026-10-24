-- CRASH_CLASS: LOW
-- PROBE 518a: find libc's syscall dispatcher through its call sites.
--
-- libc.prx has no `syscall` instruction of its own (517a: one 0F 05 byte, in
-- data), so its wrappers must jump into libkernel's exported syscall entry.
-- FreeBSD amd64 wrappers look like `mov eax, <number>` followed by
-- `call __syscall` / `jmp __syscall` / `call [rip+got]`.  This scans libc text
-- for mov-eax-immediate with a plausible syscall number and records the call
-- target that follows, then ranks targets by frequency.  The top target is the
-- syscall dispatcher, and its address is a libkernel code address we can call
-- from a thr_create child.

print("=== PROBE 518a: LIBC SYSCALL STUB ===")
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
local function wd(a, v)
    local ok = pcall(function() memory.write_dword(a, v) end)
    return ok
end
local function wq(a, v)
    local ok = pcall(function() memory.write_qword(a, v) end)
    return ok
end
local function ascii(a, n)
    local out = ""
    for i = 0, n - 1 do
        local b = (rd(a + i) or 0) % 256
        if b == 0 then break end
        if b >= 32 and b < 127 then out = out .. string.char(b) else out = out .. "." end
    end
    return out
end
local function sext32(x)
    if x >= 2147483648 then return x - 4294967296 end
    return x
end

local sc_getpid = make_syscall(20)
local sc674 = make_syscall(674)
pcall(function() return sc_getpid() end)

local STRIDE, MAX = 72, 512
local buf = memory.alloc(STRIDE * MAX + 0x100)
for i = 0, 0x400, 4 do wd(buf + i, 0) end
local countp = memory.alloc(16)
wq(countp, uint64(0))
local ok = pcall(function()
    return sc674(uint64(buf), uint64(STRIDE), uint64(MAX), uint64(countp), uint64(0x40000000))
end)
local count = rd(countp) or 0
if count > MAX then count = MAX end

local libc_lo, libc_hi, k_lo, k_hi = nil, nil, nil, nil
for i = 0, count - 1 do
    local base = buf + i * STRIDE
    local prot = rd(base + 0x18) or 0
    local name = ascii(base + 0x20, 0x20)
    local lo = (rd(base) or 0) + (rd(base + 4) or 0) * 4294967296
    local hi = (rd(base + 8) or 0) + (rd(base + 12) or 0) * 4294967296
    if name:find("libc") and (prot % 4) ~= 0 and (prot % 8) >= 4 then
        libc_lo, libc_hi = lo, hi
    end
    if name:find("libkernel") then
        if k_lo == nil or lo < k_lo then k_lo = lo end
        if k_hi == nil or hi > k_hi then k_hi = hi end
    end
end
print(string.format("[0] libc=[%s] libkernel=[%s]", tostring(libc_lo) .. "," .. tostring(libc_hi),
    tostring(k_lo) .. "," .. tostring(k_hi)))
if not libc_lo then print("no libc"); print("=== DONE ==="); return end

local targets, order = {}, {}
local movs, calls = 0, 0
local t0 = os.clock()
for a = libc_lo, libc_hi - 0x40, 1 do
    local d = rd(a)
    if d and (d % 256) == 0xB8 then
        local num = rd(a + 1)
        if num and num >= 1 and num <= 0x2C0 then
            movs = movs + 1
            -- look ahead 4..40 bytes for E8 rel32 or FF 15 disp32
            local hit = nil
            for k = 5, 40, 1 do
                local b = rd(a + k)
                if b then
                    local op = b % 256
                    if op == 0xE8 then
                        local disp = rd(a + k + 1)
                        if disp then
                            hit = (a + k + 5 + sext32(disp)) % 0x1000000000000
                        end
                    elseif op == 0xFF then
                        local b2 = rd(a + k + 1)
                        if b2 and (b2 % 256) == 0x15 then
                            local disp = rd(a + k + 2)
                            if disp then
                                local slot = (a + k + 6 + sext32(disp)) % 0x1000000000000
                                local p = nil
                                local okq = pcall(function() p = memory.read_qword(uint64(slot)) end)
                                if okq and p then
                                    local ph = to_num(p.h)
                                    local pl = to_num(p.l)
                                    if ph == 0 then hit = pl end
                                end
                            end
                        end
                    end
                    if hit then break end
                end
            end
            if hit then
                calls = calls + 1
                if targets[hit] == nil then
                    targets[hit] = {n = 0, sample = num}
                    order[#order + 1] = hit
                end
                targets[hit].n = targets[hit].n + 1
            end
        end
    end
end
print(string.format("[1] mov-eax hits=%d with-call=%d distinct=%d in %.1fs", movs, calls, #order, os.clock() - t0))

table.sort(order, function(x, y) return targets[x].n > targets[y].n end)
for i = 1, math.min(12, #order) do
    local a = order[i]
    local in_k = (k_lo and a >= k_lo and a < k_hi)
    print(string.format("    target=%08X count=%d sample_num=%d in_libkernel=%s",
        a, targets[a].n, targets[a].sample, tostring(in_k or false)))
end
print("=== DONE ===")
