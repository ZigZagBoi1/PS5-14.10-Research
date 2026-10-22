-- CRASH_CLASS: LOW
-- PROBE 143m: Read remaining loader modules + test MS_SYNC on GPU mmap
--
-- Context: 143l read kernel_offset.lua (no 14.10 entry) and offsets.lua.
-- Need gpu.lua (GPU exploit code), ropchain.lua (ROP builder), signal.lua (SROP),
-- and misc.lua (utility functions) to understand the full exploit infrastructure.
-- Also: 58a showed msync(MS_SYNC) kills on GPU mmap. Reproduce and characterize.

print("=== PROBE 143m: READ LOADER + GPU MSYNC ===")
print("")

--------------------------------------------------------------------
-- [A] Read gpu.lua — GPU exploitation primitives
--------------------------------------------------------------------
print("--- [A] gpu.lua ---")
local f = io.open("/savedata0/gpu.lua", "r")
if f then
    local c = f:read("*all")
    f:close()
    print("[A] size=" .. #c)
    local pos = 1
    while pos <= #c and pos <= 6000 do
        local nl = c:find("\n", pos) or math.min(pos + 200, #c + 1)
        print(c:sub(pos, nl - 1))
        pos = nl + 1
    end
    if #c > 6000 then print("... (truncated " .. (#c - 6000) .. " bytes)") end
else
    print("[A] io.open failed")
end

--------------------------------------------------------------------
-- [B] Read ropchain.lua — ROP chain builder
--------------------------------------------------------------------
print("")
print("--- [B] ropchain.lua ---")
f = io.open("/savedata0/ropchain.lua", "r")
if f then
    local c = f:read("*all")
    f:close()
    print("[B] size=" .. #c)
    local pos = 1
    while pos <= #c and pos <= 6000 do
        local nl = c:find("\n", pos) or math.min(pos + 200, #c + 1)
        print(c:sub(pos, nl - 1))
        pos = nl + 1
    end
    if #c > 6000 then print("... (truncated " .. (#c - 6000) .. " bytes)") end
else
    print("[B] io.open failed")
end

--------------------------------------------------------------------
-- [C] Read signal.lua — signal handling / SROP
--------------------------------------------------------------------
print("")
print("--- [C] signal.lua ---")
f = io.open("/savedata0/signal.lua", "r")
if f then
    local c = f:read("*all")
    f:close()
    print("[C] size=" .. #c)
    local pos = 1
    while pos <= #c do
        local nl = c:find("\n", pos) or math.min(pos + 200, #c + 1)
        print(c:sub(pos, nl - 1))
        pos = nl + 1
    end
else
    print("[C] io.open failed")
end

--------------------------------------------------------------------
-- [D] Read lua.lua — Lua helpers (look for exploit init)
--------------------------------------------------------------------
print("")
print("--- [D] lua.lua (first 4000) ---")
f = io.open("/savedata0/lua.lua", "r")
if f then
    local c = f:read("*all")
    f:close()
    print("[D] size=" .. #c)
    local pos = 1
    while pos <= #c and pos <= 4000 do
        local nl = c:find("\n", pos) or math.min(pos + 200, #c + 1)
        print(c:sub(pos, nl - 1))
        pos = nl + 1
    end
    if #c > 4000 then print("... (truncated " .. (#c - 4000) .. " bytes)") end
else
    print("[D] io.open failed")
end

--------------------------------------------------------------------
-- [E] Read misc.lua — utilities (look for kptr/KASLR helpers)
--------------------------------------------------------------------
print("")
print("--- [E] misc.lua (first 4000) ---")
f = io.open("/savedata0/misc.lua", "r")
if f then
    local c = f:read("*all")
    f:close()
    print("[E] size=" .. #c)
    local pos = 1
    while pos <= #c and pos <= 4000 do
        local nl = c:find("\n", pos) or math.min(pos + 200, #c + 1)
        print(c:sub(pos, nl - 1))
        pos = nl + 1
    end
    if #c > 4000 then print("... (truncated " .. (#c - 4000) .. " bytes)") end
else
    print("[E] io.open failed")
end

print("")
print("=== PROBE 143m COMPLETE ===")
