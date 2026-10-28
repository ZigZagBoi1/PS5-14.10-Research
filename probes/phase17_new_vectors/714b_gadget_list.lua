-- CRASH_CLASS: LOW
-- PROBE 714b: which register-popping gadgets eboot actually has.
--
-- Context: a native child (712c) can run a syscall and return into a gadget
-- chain on its own stack. To chain calls it needs pop <reg>; ret gadgets. 510a
-- found pop rax;ret and 548a found pop rcx;ret; this lists the rest with a
-- read_buffer scan so the answer is one run.
print("=== PROBE 714b: eboot gadget list ===")
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
local function rd(a) local o,v=pcall(function() return memory.read_dword(a) end); if o then return to_num(v) end end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end

local info = memory.alloc(0x200)
wd(info, 0x160)
pcall(function() mk(593)(uint64(0), uint64(info)) end)
local ebase = (rd(info+0x10C) or 0)*4294967296 + (rd(info+0x108) or 0)
print(string.format("[A] eboot=0x%X", ebase))

local LIMIT = 0x494000
local CHUNK = 0x1000
local function scan_all(pat, hits)
    local off, n = 0, 0
    while off < LIMIT do
        local sz = math.min(CHUNK, LIMIT-off)
        local ok, s = pcall(function() return memory.read_buffer(ebase+off, sz) end)
        if not ok or type(s) ~= "string" then break end
        local i = 1
        while true do
            local pos = string.find(s, pat, i, true)
            if not pos then break end
            n = n + 1
            if n <= hits then
                print(string.format("    +0x%X", off+pos-1))
            end
            i = pos + 1
        end
        off = off + sz - (#pat-1)
        if sz < CHUNK then break end
    end
    return n
end

local gadgets = {
    {"pop rax;ret",      string.char(0x58,0xC3)},
    {"pop rdi;ret",      string.char(0x5F,0xC3)},
    {"pop rsi;ret",      string.char(0x5E,0xC3)},
    {"pop rdx;ret",      string.char(0x5A,0xC3)},
    {"pop rcx;ret",      string.char(0x59,0xC3)},
    {"pop rsp;ret",      string.char(0x5C,0xC3)},
    {"pop rdi;pop rsi;ret", string.char(0x5F,0x5E,0xC3)},
    {"pop rsi;pop r15;ret", string.char(0x5E,0x41,0x5F,0xC3)},
    {"syscall;ret",      string.char(0x0F,0x05,0xC3)},
    {"jmp $",            string.char(0xEB,0xFE)},
    {"mov [rdi],rax;ret",string.char(0x48,0x89,0x07,0xC3)},
    {"mov [rsi],rax;ret",string.char(0x48,0x89,0x06,0xC3)},
    {"mov [rdx],rax;ret",string.char(0x48,0x89,0x02,0xC3)},
}
for _, g in ipairs(gadgets) do
    local n = scan_all(g[2], 4)
    print(string.format("[B] %-22s count=%d", g[1], n))
end
print("[Z] done")
