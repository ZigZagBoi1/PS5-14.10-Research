-- CRASH_CLASS: MODERATE (728 killed zero-args callers in the 14.10 sweep; this
-- probe is in the kill range, one connection at risk)
-- PROBE 275b: virtual_query_by_pid(728) real-args survey
--
-- Context: 13.60 handler at rva 0xabb660 (docs/SYSENT_PRESENCE_14_10.md):
--   arg0 u32 pid        -> pfind() at 0x8aefc170; NULL takes a second path
--   arg1 u64 addr       -> masked and bounds-checked against p_vmspace->[0x28]
--   arg2 u32 flags/mode -> byte at +0x12 must have bit 0x20000 set or EINVAL
--   arg3 ptr outbuf     -> written from [r13+0x18]
--   arg4 u32 count      -> read from [r13+0x20]
-- Two gates run first: sandbox checker 0x8b4c7920 and cred check 0x8afc8f90.
-- If 14.10 keeps the syscall and the gates pass for self, this returns VM
-- region info per pid - the same class of data as sys 674 but keyed by pid.

print("=== PROBE 275b: virtual_query_by_pid real args ===")
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
local function raw(v)
    if v == nil then return "nil" end
    if type(v) == "table" and v.h then return string.format("0x%08X_%08X", v.h, v.l) end
    return "0x" .. string.format("%X", to_num(v))
end
local function wq(addr, val) return pcall(function() memory.write_qword(addr, val) end) end
local function rq(addr)
    local ok, val = pcall(function() return memory.read_qword(addr) end)
    if ok then return val end
    return nil
end
local function zero(addr, n)
    for off = 0, n - 1, 8 do wq(addr + off, uint64(0)) end
end

local pid_ok, pid = pcall(function() return make_syscall(20)():tonumber() end)
print("[0] pid=" .. tostring(pid))

local heap = memory.alloc(0x400)
zero(heap, 0x400)
local out = memory.alloc(0x400)
local sc728 = make_syscall(728)

local function attempt(label, a0, a1, a2, a3, a4)
    zero(out, 0x400)
    local ok, rv = pcall(function()
        return sc728(uint64(a0), uint64(a1) or uint64(0), uint64(a2), uint64(a3) or uint64(out), uint64(a4) or uint64(1))
    end)
    local first = rq(out)
    print(string.format("    %-34s ret=%s out0=%s", label, raw(rv), first ~= nil and raw(first) or "-"))
    return ok, rv
end

print("[A] self pid, heap addr, flags variants")
attempt("pid=self addr=heap f=0x20000 c=1", pid, heap, 0x20000, out, 1)
attempt("pid=self addr=heap f=0x20001 c=1", pid, heap, 0x20001, out, 1)
attempt("pid=self addr=heap f=0x20000 c=8", pid, heap, 0x20000, out, 8)
attempt("pid=self addr=heap f=0x20003 c=4", pid, heap, 0x20003, out, 4)

print("[B] pid=0 path (pfind miss)")
attempt("pid=0 addr=heap f=0x20000 c=1", 0, heap, 0x20000, out, 1)
attempt("pid=0 addr=0 f=0x20000 c=1", 0, 0, 0x20000, out, 1)

print("[C] flag bit check (0x20000 absent -> expect EINVAL -1 fast)")
attempt("pid=self addr=heap f=0x1 c=1", pid, heap, 0x1, out, 1)

local pid_ok2, pid2 = pcall(function() return make_syscall(20)():tonumber() end)
print("")
print("[D] canary: ok=" .. tostring(pid_ok2) .. " pid=" .. tostring(pid2))
print("=== END 275b ===")
