-- CRASH_CLASS: LOW
-- PROBE 987a: the loader's own source is readable at fd 18 — extract the API surface
--
-- 977b showed read(3) on fd 18 returns the loader's main.lua. That makes the loader's
-- own capability list readable instead of inferred: the syscall.resolve table, the
-- signal handler registration, and the native call path are all in there. This reads
-- the stream sequentially and prints only lines that mention those mechanisms.

print("=== PROBE 987a: LOADER SOURCE EXTRACT (fd 18) ===")
print("")
local function to_num(v)
    if type(v)=="table" and v.tonumber then return v:tonumber() end
    if type(v)=="table" and v.h then return v.h*4294967296+v.l end
    return tonumber(v) or 0
end
local function mk(n) local t={} for k,v in pairs(syscall.pipe) do t[k]=v end t.syscall_no=n setmetatable(t,getmetatable(syscall.pipe)) return t end
local function hi_lo(v) if type(v)=="table" and v.h then return v.h,v.l end return 0,to_num(v) end
local function wd(a,v) pcall(function() memory.write_dword(a,v) end) end
local function addr_of(t) local s=tostring(t) local m=s:match("0x(%x+)") if m then return tonumber(m,16) end return to_num(t) end

local fd = 18
local buf = memory.alloc(0x2000)
local seen = 0
local total = 0
local keys = { "resolve", "sigaction", "signal", "native_invoke", "fcall", "thr_self",
               "dynlib", "dlsym", "kernel_offset", "eboot_base", "libc_base", "jmp",
               "closure", "CClosure", "fn_addr", "rop" }
local hits = 0

print("[A] sequential read, printing matching lines only")
repeat
    local ok, rv = pcall(function() return mk(3)(uint64(fd), uint64(addr_of(buf)), uint64(0x1FF0)) end)
    if not ok then print("  [read] PCALL-FAIL"); break end
    local h, l = hi_lo(rv)
    if l == 0 or l > 0x2000 or l == 0xFFFFFFFF then break end
    total = total + l
    -- gather the chunk as text through the Lua string API of the loader
    local chunk = ""
    local okc, s = pcall(function()
        local t = {}
        for i = 0, l-1 do
            local b = to_num(memory.read_byte(buf + i))
            t[#t+1] = string.char(b)
        end
        return table.concat(t)
    end)
    if not okc then print("  [bytes] PCALL-FAIL"); break end
    chunk = s
    for line in chunk:gmatch("[^\n]+") do
        local low = line:lower()
        for _, k in ipairs(keys) do
            if low:find(k:lower(), 1, true) then
                if #line > 220 then line = line:sub(1,220) .. "…" end
                hits = hits + 1
                if hits <= 120 then print("  | " .. line) end
                break
            end
        end
    end
    seen = seen + 1
until seen > 48

print(string.format("[Z] bytes=%d chunks=%d hits=%d", total, seen, hits))
print("=== COMPLETE ===")
