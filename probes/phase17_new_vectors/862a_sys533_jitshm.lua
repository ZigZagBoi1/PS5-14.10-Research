-- CRASH_CLASS: HIGH
-- PROBE 862a: 533 / 534 (JITSHM-SHAPED PAIR)
--
-- Context: 533 (narg 3) and 534 (narg 2) gate on ctx = [thread+0x140] with
--     0x7058ad call 0x6095c0(ctx)  /  0x7058bd call 0x609620(ctx)
-- and 533 then validates
--     0x7058d3 test r12d,0x3fff  / jne EINVAL     ; arg2 must be 0x4000-aligned
--     0x7058e4 test r15d,0xffffffc8 / jne EINVAL  ; arg3 subset of 0x37
--     0x7058ff mov edi,1 ; xor esi,esi ; mov rdx,r12 ; xor r8d,r8d
-- i.e. a create(size, flags) call. 534 allocates a 0x18 record, copies
-- [uap+8] into [record+0x10] and calls 0x72c3d0(thread, arg1, 0, &out).
--
-- If 533 returns an fd, mapping it may bypass the generic mmap X-strip that
-- blocks every other route to executable memory (probes 803c-803i, 835a-838a).

print("=== PROBE 862a: 533 / 534 JITSHM-SHAPED PAIR ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    if type(v) == "table" and v.h then return v.h * 4294967296 + v.l end
    return tonumber(v) or 0
end
local function make_syscall(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function U(a)
    a = to_num(a)
    return uint64(string.format("0x%08X%08X",
        math.floor(a / 4294967296), a % 4294967296))
end
local function hex(v)
    local n = to_num(v)
    if n < 0 then n = n + 18446744073709551616 end
    return string.format("%016X", n)
end
local function d(p, i) return to_num(memory.read_dword(p + i * 4)) end

local sc533 = make_syscall(533)
local sc534 = make_syscall(534)
local sc477 = make_syscall(477)
local sc674 = make_syscall(674)
local sc549 = make_syscall(549)
local sc550 = make_syscall(550)

local regs = to_num(memory.alloc(0x1000))
local cntp = to_num(memory.alloc(0x40))

local function try(fn)
    local ok, rv = pcall(fn)
    if not ok then return nil end
    return to_num(rv)
end

print(string.format("[0] pid=%s", tostring(make_syscall(20)())))
print("")

print("[A] 533(size, flags)")
local fds = {}
for _, size in ipairs({0x4000, 0x8000, 0x10000}) do
    for _, flags in ipairs({0, 1, 2, 3, 4, 5, 7, 0x10, 0x20, 0x37}) do
        local rv = try(function() return sc533(U(size), U(flags), U(0)) end)
        print(string.format("[A] size=%06X flags=%02X -> %s",
            size, flags, rv == nil and "PCALLFAIL" or hex(rv)))
        if rv and rv > 0 and rv < 0x10000 then fds[#fds + 1] = {rv, size, flags} end
    end
end
-- the same two shapes with a third argument pointing at a page
for _, size in ipairs({0x4000}) do
    for _, flags in ipairs({0, 3, 7}) do
        local rv = try(function() return sc533(U(size), U(flags), U(regs)) end)
        print(string.format("[A] size=%06X flags=%02X ptr -> %s",
            size, flags, rv == nil and "PCALLFAIL" or hex(rv)))
        if rv and rv > 0 and rv < 0x10000 then fds[#fds + 1] = {rv, size, flags} end
    end
end
print("")

print("[B] 534(id, flags) over plausible ids")
for _, id in ipairs({0, 1, 2, 3, 4, 5, 8, 16, 0x4000, 0x4205}) do
    for _, flags in ipairs({0, 1, 3}) do
        local rv = try(function() return sc534(U(id), U(flags)) end)
        print(string.format("[B] id=%06X flags=%02X -> %s",
            id, flags, rv == nil and "PCALLFAIL" or hex(rv)))
    end
end
print("")

if #fds == 0 then
    print("[C] no fd returned by 533, nothing to map")
else
    print(string.format("[C] %d candidate fd(s)", #fds))
    for i, e in ipairs(fds) do
        local fd, size, flags = e[1], e[2], e[3]
        -- request read|write|exec and see what the mapping really gets
        local m = try(function()
            return sc477(U(0), U(size), U(7), U(0x1002), U(fd), U(0))
        end)
        print(string.format("[C] fd=%s size=%06X flags=%02X mmap -> %s",
            tostring(fd), size, flags, m == nil and "PCALLFAIL" or hex(m)))
        if m and m > 0x1000 and m < 0x8000000000 then
            local np = memory.read_qword(regs + 0x18)
            dp = to_num(np)
            local okm = pcall(function()
                memory.write_dword(m, 0x41424344)
            end)
            local count = try(function()
                sc674(U(regs), U(72), U(64), U(cntp), U(0x40000000))
                return to_num(memory.read_dword(cntp))
            end)
            local found = "not-found"
            if count and count > 0 and count < 64 then
                for k = 0, count - 1 do
                    local base = regs + k * 72
                    local lo = d(base, 0)
                    local hi = d(base, 1)
                    local prot = d(base, 6)
                    if lo == (m % 4294967296) and hi == math.floor(m / 4294967296) then
                        found = string.format("prot=%X", prot)
                    end
                end
            end
            print(string.format("[C]   writable=%s map=%s",
                tostring(okm), found))
        end
    end
end
print("")

local function name_page(tag)
    local p = to_num(memory.alloc(0x40))
    for i = 0, 0x3F do memory.write_byte(p + i, 0) end
    local t = "h862" .. tag
    for i = 1, #t do memory.write_byte(p + i - 1, string.byte(t, i)) end
    return p
end
local okc, id = pcall(function() return sc549(U(name_page("a")), U(1), U(0), U(0x100)) end)
local okd, rvd = pcall(function() return sc550(U(to_num(id))) end)
print(string.format("[Z] create=%s destroy=%s alive=true",
    okc and hex(id) or "FAIL", okd and hex(rvd) or "FAIL"))
print("=== PROBE 862a COMPLETE ===")
