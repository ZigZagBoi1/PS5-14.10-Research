import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

// Force-disassemble + decompile orphan functions around 0x480-copyin sites
public class Ps5ForceAnalyze extends GhidraScript {
    static final long TEXT_BASE = 0xffffffff9e3f0000L;
    static final long[] SITES = {
        0x27af36L, 0x29dc95L, 0x29e732L, 0x29e959L, 0x29eab2L, 0x29ecd1L,
        0x29f001L, 0x29f20cL, 0x29f5beL, 0x29f6f1L, 0x29fb50L, 0x29fbbdL,
        0x29fc73L, 0x57a185L, 0x57a65aL
    };

    boolean isPrologue(Memory mem, long a) throws Exception {
        int b0 = mem.getByte(fo2addr(mem, a)) & 0xff;
        int b1 = mem.getByte(fo2addr(mem, a + 1)) & 0xff;
        if (b0 == 0xf3 && b1 == 0x0f) return true;              // endbr64
        if (b0 == 0x55 || b0 == 0x53 || b0 == 0x56 || b0 == 0x57) return true; // push rbp/rbx/rsi/rdi
        if (b0 == 0x41 && b1 >= 0x54 && b1 <= 0x57) return true; // push r12-r15
        if (b0 == 0x48 && b1 == 0x83) return true;               // sub rsp etc
        return false;
    }

    Address fo2addr(Memory mem, long fo) {
        return mem.getMinAddress().getAddressSpace().getAddress(fo);
    }

    public void run() throws Exception {
        Memory mem = currentProgram.getMemory();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        StringBuilder all = new StringBuilder();
        java.util.HashSet<Long> done = new java.util.HashSet<>();
        for (long site : SITES) {
            // scan backward for a boundary: prologue right after int3-padding or ret
            long boundary = -1;
            for (long i = site - 1; i >= site - 0x200 && boundary < 0; i--) {
                int prev = mem.getByte(fo2addr(mem, i - 1)) & 0xff;
                int cur  = mem.getByte(fo2addr(mem, i)) & 0xff;
                if ((prev == 0xcc || prev == 0xc3 || prev == 0x90 || prev == 0x00)
                        && isPrologue(mem, i)) {
                    boundary = i;
                }
            }
            if (boundary < 0) { println("no boundary for site 0x" + Long.toHexString(site)); continue; }
            if (done.contains(boundary)) { println("site 0x" + Long.toHexString(site)
                + " -> same func 0x" + Long.toHexString(boundary)); continue; }
            done.add(boundary);
            Address ba = fo2addr(mem, boundary);
            new DisassembleCommand(ba, null, true).applyTo(currentProgram);
            Function f = getFunctionAt(ba);
            if (f == null) {
                new CreateFunctionCmd(ba).applyTo(currentProgram);
                f = getFunctionAt(ba);
            }
            if (f == null) { println("no function at 0x" + Long.toHexString(boundary)); continue; }
            DecompileResults r = decomp.decompileFunction(f, 180, monitor);
            all.append("\n/* ===== site 0x").append(Long.toHexString(site))
               .append(" FUNC off 0x").append(Long.toHexString(boundary))
               .append(" VA 0x").append(Long.toHexString(boundary + TEXT_BASE))
               .append(" name ").append(f.getName()).append(" ===== */\n");
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                all.append(r.getDecompiledFunction().getC());
            else all.append("/* decompile failed */");
            println("dumped site 0x" + Long.toHexString(site) + " func 0x" + Long.toHexString(boundary));
        }
        java.io.File out = new java.io.File(System.getProperty("user.home")
            + "/ps5-diff/out/mcontext_forced.c");
        out.getParentFile().mkdirs();
        java.nio.file.Files.writeString(out.toPath(), all.toString());
        println("WROTE " + out.getAbsolutePath() + " funcs=" + done.size());
        decomp.dispose();
    }
}
