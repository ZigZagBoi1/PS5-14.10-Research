-- CRASH_CLASS: MODERATE (nothing kernel-side is written; the only supervisor
--               addresses used are reads of the measured kernel image, and the
--               U pass deliberately includes calls already known to kill)
-- PROBE 1342a: arg1 pointer-class sweep, resumed at 589
--
-- prior art:
--   .local/1334a.lua + results/1334a_20261106_144023.txt  U/N survey 532..567, dies at 568 U
--   .local/1334b.lua + results/1334b_20261106_144105.txt  dies at 569 U, nothing else
--   .local/1334c.lua + results/1334c_20261106_145045.txt  U/N survey 574..588, dies at 589 U
--   .local/1332a.lua + results/1332a_20261106_143858.txt  K class for six calls (557/636/601/669/674/548),
--                                                        all EFAULT/EINVAL/EPERM -- no kernel read
--   docs/DEAD_ENDS.md  557 namedobj, 563-566 authid, 587 credential word, 547 query_memory_protection
--   docs/SYSCALL_ABSENT_VS_LETHAL.md  with SIGSYS ignored an absent slot answers ENOSYS
--
-- Classes:
--   U = mapped user page filled with 0x41
--   N = absent user address 0x00007FFF00000000
--   K = 0xFFFFFFFFC1000000, the kernel image base measured on this boot
--       (results/1331a_20261109_094441.txt: image 0xFFFFFFFFC1000000-0xFFFFFFFFC6C00000)
--
-- Coverage when this was written: U/N pairs exist for 532-567 (1334a) and 574-588
-- (1334c); 568 U, 569 U and 589 U each killed their run; 568 N also kills (1342a
-- run 1), so 568 is lethal on both classes; 570, 571, 573 and the SKIP list below
-- are known killers; 590-676 were never reached. The K class exists for six calls
-- only, all rejected.
--
-- Order is deliberate, safest first, so a death truncates the least:
--   [0] ignore SIGSYS first: with the default disposition the shared nosys
--       trampoline terminates the caller (353a/353b), which makes an absent slot
--       indistinguishable from a hostile handler -- rows 568 and 590 killed under
--       the default and have not been classified since
-- Run 3 (2026-11-09 10:12, results/.../1342a_arg1_sweep_589_plus_20261109_101208.txt)
-- installed SIG_IGN (rv=0) and swept 568..620: the numbers that killed under the
-- default disposition now answer ENOSYS -- 568, 569, 589, 590, 597, 610, 619, 620 --
-- so those kills were the nosys trampoline raising SIGSYS, not hostile handlers.
-- 574-584 also ENOSYS, 585 returns 1. Real handlers hold: 572 EACCES, 586-587
-- EPERM, 588 EFAULT, 591 EFAULT, 592 ENOMEM, 593/594 EFAULT, 595 ESRCH, 596 ret 0,
-- 598 EFAULT, 599/600 EPERM, 601 EFAULT, 602-604 EPERM, 605 EINVAL, 606 ret 0,
-- 607/608 EFAULT, 611 EPERM, 612 EFAULT, 613 EPERM, 615 EFAULT, 616 ESRCH,
-- 617 ret 0, 618 EPERM. The run died at 622, a real handler that faults on a bad
-- argument, so 622 is skipped from here on.
--   [A] N class, 623..676
--   [B] K class on the handlers whose U and N answers differ (538, 540, 547, 551,
--       557, 559, 563-566, 587) -- a handler that reads a supervisor address and
--       copies it back would be a kernel read; 1332a says the six it tested reject
--   [C] U class, 590..676 -- likely to die at the first dereferencing handler
--   [D] 572 and 589, N then U, last of all
--
-- Every call prints "CALL" first, so the line after it names the call that died.

print("=== PROBE 1342a: ARG1 POINTER-CLASS SWEEP, RESUMED AT 589 ===")

-- edit these two to resume after a death in [A] or [C]
local START_N = 623
local START_U = 568

local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function U(hi,lo) return uint64(string.format("0x%08X%08X",hi,lo)) end
local function A(v) return U(math.floor(v/4294967296), v%4294967296) end
local function ES() local o,e=pcall(function() return get_error_string() end) if o then return tostring(e) end return "?" end
local function wq(a,v) pcall(function() memory.write_qword(A(a),A(v)) end) end
local function rd(a) local ok,v=pcall(function() return memory.read_dword(A(a)) end) if ok then return to_num(v)%4294967296 end return nil end
local function page(n)
    local o,a=pcall(function() return mk(477)(uint64(0),A(n),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    if not o then return 0 end
    local v=to_num(a)
    if v==0 or v>=0x800000000000 then return 0 end
    for x=0,n-8,8 do wq(v+x,0x4141414141414141) end
    return v
end

local UMAP = page(0x4000)
if UMAP==0 then print("[!] mmap failed"); return end
local UABS = 0x00007FFF00000000
local KIMG = 0xFFFFFFFFC1000000
print(string.format("[0] user=0x%X absent=0x%X K=0x%X (image base measured 2026-11-09)", UMAP, UABS, KIMG))

-- ignore SIGSYS: after this an absent slot returns -1 instead of raising the
-- signal whose default action terminates the process (353a/353b)
local sa = memory.alloc(0x80)
for i = 0, 0x70, 8 do pcall(function() memory.write_qword(sa + i, uint64(0)) end) end
pcall(function() memory.write_qword(sa + 0, uint64(1)) end)
local h0 = nil
local okh, hv = pcall(function() return memory.read_qword(sa + 0) end)
if okh then h0 = tostring(hv) end
print("[0] sa[+0]=" .. tostring(h0))
local okI, rvI = pcall(function() return mk(416)(uint64(12), uint64(sa), uint64(0)) end)
print(string.format("[0] sigaction(12, SIG_IGN) -> %s", okI and tostring(to_num(rvI)) or "EXC"))
if not (okI and to_num(rvI) == 0) then
    print("[!] SIGSYS could not be ignored; not spending the console")
    print("=== PROBE 1342a STOPPED ===")
    return
end

local SKIP = {[561]=1,[562]=1,[570]=1,[571]=1,[573]=1,[622]=1,[609]=1,[614]=1,[621]=1,[631]=1,[650]=1,[651]=1,[668]=1,[673]=1}
local Z = U(0,0)

local function call(num, ptr, tag)
    print(string.format("CALL %d %s", num, tag))
    local ok, rv = pcall(function() return mk(num)(A(ptr), Z, Z, Z, Z, Z) end)
    if ok then
        print(string.format("[%03d] %s -> %s err=%s", num, tag, tostring(to_num(rv)), ES()))
        return
    end
    print(string.format("[%03d] %s -> CALL-FAILED", num, tag))
end

-- a page the caller cannot read: distinguishes "read it" from "did not"
local function nclass(num)
    call(num, UABS, "N")
end
local function uclass(num)
    call(num, UMAP, "U")
end
local function kclass(num)
    call(num, KIMG, "K")
end

print("")
print("[A] N class -- " .. START_N .. "..676")
for num = START_N, 676 do
    if not SKIP[num] then nclass(num) end
end
print("[A] canary " .. tostring(to_num(mk(20)())))

print("")
print("[B] K class -- handlers whose U and N answers differ")
for _, num in ipairs({538, 540, 547, 551, 557, 559, 563, 564, 565, 566, 587}) do
    kclass(num)
end
print("[B] canary " .. tostring(to_num(mk(20)())))

print("")
print("[C] U class -- " .. START_U .. "..676 (a death here names the first dereferencing handler)")
for num = START_U, 676 do
    if not SKIP[num] then uclass(num) end
end
print("[C] canary " .. tostring(to_num(mk(20)())))


print("")
print("[E] alive pid=" .. tostring(to_num(mk(20)())))
print("=== PROBE 1342a COMPLETE ===")
