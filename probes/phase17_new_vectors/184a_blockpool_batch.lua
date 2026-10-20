-- CRASH_CLASS: MODERATE
-- PROBE 184a: sys 657 blockpool_batch writes through its third argument
--
-- Context: 183a opened blockpools (653 returned 22, then 23, 24, then -1) and
-- 657(handle, 0, buf) returned 0 while every other shape returned -1, and buf+0
-- came back zeroed. This opens one handle per run, then walks arg2 over 0..8 and
-- arg3 over a canary page and over NULL, dumping the page so the write is visible,
-- then tries a plausible request record in arg3.

print("=== PROBE 184a: SYS 657 blockpool_batch ===")
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
local function u64(v)
    return uint64(string.format("0x%08X", v))
end
local function hx(v)
    return tostring(v)
end
local zero = u64(0)

local sc653 = make_syscall(653)
local sc657 = make_syscall(657)
local sc655 = make_syscall(655)

local buf = memory.alloc(0x1000)
local function fill()
    for off = 0, 0xFF8, 8 do
        pcall(function() memory.write_qword(buf + off, u64(0xC1C1C1C1)) end)
    end
end
local function dump(n)
    local parts = {}
    for off = 0, (n or 0x30) - 8, 8 do
        local ok, v = pcall(function() return memory.read_qword(buf + off) end)
        parts[#parts + 1] = ok and hx(v) or "fault"
    end
    return table.concat(parts, " ")
end

local ok, ret = pcall(function() return sc653(zero, zero, zero, zero, zero, zero) end)
print("[0] 653 -> " .. (ok and hx(ret) or "killed"))
print("")

if ok then
    local h = to_num(ret)
    local hu = u64(h % 0x100000000)
    print("[0] arg2 sweep with the handle in arg1 and a canary page in arg3")
    for a2 = 0, 8 do
        fill()
        local ok2, r2 = pcall(function() return sc657(hu, u64(a2), buf, zero, zero, zero) end)
        if not ok2 then
            print(string.format("[!] arg2=%d killed", a2))
            break
        end
        print(string.format("[*] 657(h,%d,buf) -> %s | buf: %s", a2, hx(r2), dump(0x28)))
    end
    print("")

    print("[0] arg2=0 with arg3 NULL")
    local ok3, r3 = pcall(function() return sc657(hu, zero, zero, zero, zero, zero) end)
    print("[*] 657(h,0,NULL) -> " .. (ok3 and hx(r3) or "killed"))
    print("")

    print("[0] a request record in arg3: {count=1, op=0, size=0x10, src=dst}")
    fill()
    pcall(function() memory.write_qword(buf + 0x00, u64(1)) end)
    pcall(function() memory.write_qword(buf + 0x08, zero) end)
    pcall(function() memory.write_qword(buf + 0x10, u64(0x10)) end)
    pcall(function() memory.write_qword(buf + 0x18, u64(0x1234)) end)
    local ok4, r4 = pcall(function() return sc657(hu, zero, buf, zero, zero, zero) end)
    print("[*] 657(h,0,record) -> " .. (ok4 and hx(r4) or "killed") .. " | " .. dump(0x28))
    print("")

    print("[0] close: 655(h)")
    local ok5, r5 = pcall(function() return sc655(hu, zero, zero, zero, zero, zero) end)
    print("[*] 655(h) -> " .. (ok5 and hx(r5) or "killed"))
    print("[0] reopen after 655: 653")
    local ok6, r6 = pcall(function() return sc653(zero, zero, zero, zero, zero, zero) end)
    print("[*] 653 -> " .. (ok6 and hx(r6) or "killed"))
end

print("")
print("[*] done")
