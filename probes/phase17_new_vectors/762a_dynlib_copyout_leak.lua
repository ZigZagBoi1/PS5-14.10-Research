-- CRASH_CLASS: MODERATE
-- PROBE 762a: copyout leak sweep over the dynlib metadata getters
--
-- A static audit of the 13.60 capture ranked the copyout sites that carry
-- kernel pointers into a caller buffer. Four of them are dynlib metadata
-- getters whose fields come straight out of kernel objects:
--
--   604 dl_get_metadata      copyout of *(meta+0x88) len min(*(meta+0x90), 0xffffffff)
--   536 dl_get_info          array of linker-resolved symbol values at +0x1a0
--   608 dynlib_get_info_ex   +0x128/+0x130 from obj+0xe8/+0xf0, +0x160/+0x170 two-level deref
--   656/660 dynlib_info2     per-segment *(seg+8) into out+i*0x10
--
-- Each is gated by a Sony predicate, so the first question is simply whether
-- the call is allowed at all. Every call gets a freshly zeroed page, and the
-- whole page is scanned for a qword whose high half looks like kernel space
-- (0xFFFF8xxx). The handle list comes from 592, the same list 593 answers for.

print("=== PROBE 762a: DYNLIB COPYOUT LEAK SWEEP ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n)
    local t={}
    for k,v in pairs(syscall.pipe) do t[k]=v end
    t.syscall_no=n
    setmetatable(t,getmetatable(syscall.pipe))
    return t
end
local U = function(a) a=to_num(a); return uint64(string.format("0x%08X%08X", math.floor(a/4294967296), a%4294967296)) end
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function rq(a) local o,v=pcall(function() return memory.read_qword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function wq(a,v) pcall(function() memory.write_qword(a,v) end) end
local function zero(a,n) pcall(function() for i=0,n-4,4 do memory.write_dword(a+i,0) end end) end
local function call(sc, a1, a2, a3, a4, a5, a6)
    local ok, r = pcall(function() return sc(U(a1), U(a2), U(a3), U(a4), U(a5), U(a6)) end)
    if not ok then return "DEAD" end
    return to_num(r)
end
print("[A] tid="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))

-- handle list
local hl = to_num(memory.alloc(0x400)); wd(hl, 0)
local hc = to_num(memory.alloc(8)); wd(hc, 0)
local hr = call(mk(592), hl, 0x100, hc, 0, 0, 0)
local hn = rd(hc) or 0
print(string.format("[A] 592 ret=%s count=%s", tostring(hr), tostring(hn)))
local handles = {}
for i=0,math.min(hn,64)-1 do handles[#handles+1] = rd(hl + i*4) end
local shown = {}
for i=1,math.min(#handles,12) do shown[#shown+1] = string.format("%X", handles[i]) end
print("[A] handles: "..table.concat(shown, " "))

local page = 0x2000
local buf = to_num(memory.alloc(page))
local need = to_num(memory.alloc(16))

local function scan(tag, base, len, ret)
    local hits, n = {}, 0
    for off=0,len-8,8 do
        local v = rq(base+off)
        if v then
            local hi = math.floor(v / 4294967296)
            if hi >= 0xFFFF8000 and hi <= 0xFFFFFFFF and v ~= 0xFFFFFFFFFFFFFFFF then
                hits[#hits+1] = string.format("+%03X=%016X", off, v)
                n = n + 1
                if n >= 6 then break end
            end
        end
    end
    if n > 0 then
        print(string.format("  %s ret=%s KERNEL-DATA %s", tag, tostring(ret), table.concat(hits, " ")))
    end
    return n
end

local kernels = 0
local function run(tag, num, a1, a2, a3, a4, a5)
    zero(buf, page); wd(need, 0)
    local r = call(mk(num), a1, a2, a3, a4, a5, 0)
    local first = {}
    for i=0,3 do first[#first+1] = string.format("%08X", rd(buf + i*8) or 0) end
    print(string.format("  %s ret=%s head=%s", tag, tostring(r), table.concat(first, " ")))
    kernels = kernels + scan(tag, buf, 0x800, r)
    return r
end

print("[B] 536 dl_get_info: (handle, out, size)")
for i=1,math.min(#handles,6) do
    run(string.format("536 h=%X", handles[i]), 536, handles[i], buf, 0xa58, 0, 0)
end

print("[C] 604 dl_get_metadata: (handle, key, out, size, need)")
for i=1,math.min(#handles,4) do
    for key=0,3 do
        run(string.format("604 h=%X k=%d", handles[i], key), 604, handles[i], key, buf, 0x800, need)
    end
end

print("[D] 608 dynlib_get_info_ex: (handle, mode, buf) with buf[0]=size")
for i=1,math.min(#handles,6) do
    for mode=0,1 do
        zero(buf, page); wq(buf, uint64(0x1a8))
        local r = call(mk(608), handles[i], mode, buf, 0, 0, 0)
        local h = {}
        for k=0,3 do h[#h+1] = string.format("%08X", rd(buf + k*8) or 0) end
        print(string.format("  608 h=%X m=%d ret=%s head=%s", handles[i], mode, tostring(r), table.concat(h, " ")))
        kernels = kernels + scan("608", buf, 0x1a8, r)
    end
end

print("[E] 656/660 dynlib info2: (handle, buf)")
for i=1,math.min(#handles,6) do
    for _,num in ipairs({656, 660}) do
        zero(buf, page); wq(buf, uint64(0x160))
        local r = call(mk(num), handles[i], buf, 0x160, 0, 0, 0)
        local h = {}
        for k=0,3 do h[#h+1] = string.format("%08X", rd(buf + k*8) or 0) end
        print(string.format("  %d h=%X ret=%s head=%s", num, handles[i], tostring(r), table.concat(h, " ")))
        kernels = kernels + scan(tostring(num), buf, 0x160, r)
    end
end

print(string.format("[F] kernel-shaped qwords=%d", kernels))
print("[G] health="..tostring(call(syscall.pipe, 20,0,0,0,0,0,0)))
print("=== 762a DONE ===")
