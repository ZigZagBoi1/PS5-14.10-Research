-- CRASH_CLASS: LOW
-- PROBE 94a: sys 601 VM fingerprint — which cmds do kernel VM work?
--
-- Uses sys 624 (VM op counter) as oracle to detect which sys 601
-- accessible cmds allocate/free kernel objects. Only cmds that
-- move the VM counter are worth racing with threads.
--
-- Also tests: repeated calls to same cmd (accumulation), init-cmd-init
-- pattern (alloc-use-free?), different arg values.

print("=== PROBE 94a: SYS 601 VM FINGERPRINT ===")
print("")

local function N(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}; for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n; setmetatable(t,getmetatable(syscall.pipe)); return t
end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function rd(a)
    local ok,v=pcall(function() return memory.read_dword(a) end)
    if ok then return N(v) end return nil
end
local function z(b,n) for o=0,n-4,4 do wd(b+o,0) end end

local stub=syscall.pipe.fn_addr
local pid=N(native.fcall_with_rax(stub,20))
print("pid="..pid)

local c601=mk(601)
local c624=mk(624)

local function vmc()
    local ok,c=pcall(function() return c624(uint64(0),uint64(0),uint64(0)) end)
    return ok and N(c) or -1
end

-- Buffers for sys 601: arg1=cmd, arg2=outbuf, arg3=inbuf
local buf2=memory.alloc(0x200)
local buf3=memory.alloc(0x200)

local function call601(cmd)
    z(buf2, 0x200); z(buf3, 0x200)
    local ok,rv=pcall(function()
        return c601(uint64(cmd), uint64(buf2), uint64(buf3))
    end)
    if ok then return N(rv) else return -999 end
end

local function call601_with(cmd, arg2_val, arg3_val)
    z(buf2, 0x200); z(buf3, 0x200)
    if arg2_val then wd(buf2, arg2_val) end
    if arg3_val then wd(buf3, arg3_val) end
    local ok,rv=pcall(function()
        return c601(uint64(cmd), uint64(buf2), uint64(buf3))
    end)
    if ok then return N(rv) else return -999 end
end

-- Accessible cmds (from discovery)
local CMDS={0x00,0x07,0x09,0x0B,0x0D,0x0E,0x13,0x14,0x19,0x1A,0x1D,0x20}
local NAMES={
    [0x00]="init",[0x07]="07",[0x09]="09",[0x0B]="0B",
    [0x0D]="0D",[0x0E]="0E",[0x13]="13",[0x14]="14",
    [0x19]="19",[0x1A]="1A",[0x1D]="1D",[0x20]="20"
}

-- ============================================================
-- SECTION A: Single-call VM delta for each cmd
-- ============================================================
print("--- A: SINGLE CALL VM DELTA ---")

-- Baseline: measure VM jitter with no syscalls
local v0=vmc()
local v1=vmc()
print(string.format("baseline jitter: %d->%d d=%d", v0, v1, v1-v0))

for _,cmd in ipairs(CMDS) do
    local before=vmc()
    local rv=call601(cmd)
    local after=vmc()
    local d=after-before
    local b0=rd(buf2) or 0
    local tag=""
    if d~=0 then tag=" ***" end
    print(string.format("cmd 0x%02X %-4s: rv=%d vm=%d->%d d=%-4d buf[0]=0x%X%s",
        cmd, NAMES[cmd], rv, before, after, d, b0, tag))
end

-- ============================================================
-- SECTION B: 10x repeated calls — accumulation?
-- ============================================================
print("")
print("--- B: 10x REPEATED CALLS ---")

for _,cmd in ipairs(CMDS) do
    local before=vmc()
    for i=1,10 do call601(cmd) end
    local after=vmc()
    local d=after-before
    local tag=""
    if d~=0 then tag=" ***" end
    if d~=0 or cmd==0x00 then
        print(string.format("cmd 0x%02X x10: vm d=%-4d%s", cmd, d, tag))
    end
end

-- ============================================================
-- SECTION C: init → cmd → init pattern (alloc-use-free?)
-- ============================================================
print("")
print("--- C: INIT-CMD-INIT PATTERN ---")

for _,cmd in ipairs(CMDS) do
    if cmd~=0x00 then
        local v0=vmc()
        call601(0x00)  -- init
        local v1=vmc()
        call601(cmd)   -- use
        local v2=vmc()
        call601(0x00)  -- re-init (free+realloc?)
        local v3=vmc()

        local d_init=v1-v0
        local d_cmd=v2-v1
        local d_reinit=v3-v2
        local tag=""
        if d_cmd~=0 or d_reinit~=d_init then tag=" ***" end
        if tag~="" or cmd<=0x0E then
            print(string.format("cmd 0x%02X: init d=%d, cmd d=%d, reinit d=%d%s",
                cmd, d_init, d_cmd, d_reinit, tag))
        end
    end
end

-- ============================================================
-- SECTION D: Different arg values for interesting cmds
-- ============================================================
print("")
print("--- D: ARG SENSITIVITY ---")

-- Test each cmd with different values in buf2[0] and buf3[0]
local test_vals={0, 1, 0x100, 0xFFFF, 0x7FFFFFFF}
for _,cmd in ipairs(CMDS) do
    local results={}
    local any_diff=false
    for _,val in ipairs(test_vals) do
        local v0=vmc()
        local rv=call601_with(cmd, val, val)
        local v1=vmc()
        local b0=rd(buf2) or 0
        results[#results+1]={val=val, rv=rv, d=v1-v0, b0=b0}
        if rv~=results[1].rv or (v1-v0)~=results[1].d then any_diff=true end
    end
    if any_diff then
        print(string.format("cmd 0x%02X ARG SENSITIVE:", cmd))
        for _,r in ipairs(results) do
            print(string.format("  arg=0x%X: rv=%d vmd=%d buf=0x%X",
                r.val, r.rv, r.d, r.b0))
        end
    end
end

-- ============================================================
-- SECTION E: buf2 output dump for init (0x00) — what state exists?
-- ============================================================
print("")
print("--- E: INIT OUTPUT DEEP ---")

z(buf2, 0x200)
local rv=call601(0x00)
print("init rv="..rv)
local any_nonzero=false
for off=0,0x1F0,4 do
    local v=rd(buf2+off) or 0
    if v~=0 then
        print(string.format("  buf2+0x%03X = 0x%08X", off, v))
        any_nonzero=true
    end
end
if not any_nonzero then print("  (all zero)") end

-- After init, try auth-gated cmds to see if init changes anything
print("")
print("--- F: POST-INIT AUTH GATE ---")
local gated={0x01,0x02,0x05,0x06,0x0A,0x10,0x12}
for _,cmd in ipairs(gated) do
    local v0=vmc()
    local rv=call601(cmd)
    local v1=vmc()
    local b0=rd(buf2) or 0
    print(string.format("gated 0x%02X: rv=%d vmd=%d buf=0x%X", cmd, rv, v1-v0, b0))
end

-- ============================================================
-- SECTION G: Sequence — init, then all accessible cmds in order
-- ============================================================
print("")
print("--- G: FULL SEQUENCE ---")

call601(0x00)
local seq_v0=vmc()
for _,cmd in ipairs(CMDS) do
    if cmd~=0x00 then
        local rv=call601(cmd)
        local v=vmc()
        local b0=rd(buf2) or 0
        print(string.format("seq 0x%02X: rv=%d vm=%d buf=0x%X", cmd, rv, v, b0))
    end
end
local seq_v1=vmc()
print(string.format("sequence total vm: %d->%d d=%d", seq_v0, seq_v1, seq_v1-seq_v0))

print("")
print("canary="..N(native.fcall_with_rax(stub,20)))
print("=== 94a COMPLETE ===")
