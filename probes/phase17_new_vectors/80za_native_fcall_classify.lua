-- CRASH_CLASS: LOW
-- Classify loader native.fcall_with_rax without dereferencing a closure pointer.
print("=== PROBE 80za: NATIVE FCALL CLASSIFY ===")
print("native_type=" .. type(native))
if type(native) == "table" then
    local f = native.fcall_with_rax
    print("fcall_type=" .. type(f))
    if type(f) == "function" then
        print("descriptor=" .. tostring(f))
        local ok, result = pcall(string.dump, f)
        print("string_dump_ok=" .. tostring(ok))
        if ok then print("bytecode_length=" .. tostring(#result)) end
    end
end
print("=== PROBE 80za COMPLETE ===")
