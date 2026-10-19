import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;

// Dump decompiled C for every function in the 0x480-copyin cluster (mcontext syscalls)
public class Ps5McontextDump extends GhidraScript {
    static final long TEXT_BASE = 0xffffffff9e3f0000L;

    public void run() throws Exception {
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        FunctionIterator fits = currentProgram.getFunctionManager().getFunctions(true);
        int n = 0;
        StringBuilder all = new StringBuilder();
        while (fits.hasNext()) {
            Function f = fits.next();
            long off = f.getEntryPoint().getOffset();
            if (off < 0x29d000 || off > 0x2a0500) continue;
            DecompileResults r = decomp.decompileFunction(f, 120, monitor);
            all.append("\n/* ===== FUNC off 0x").append(Long.toHexString(off))
               .append(" VA 0x").append(Long.toHexString(off + TEXT_BASE))
               .append(" name ").append(f.getName()).append(" ===== */\n");
            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null)
                all.append(r.getDecompiledFunction().getC());
            else
                all.append("/* decompile failed */");
            n++;
            println("dumped " + n + " off 0x" + Long.toHexString(off));
        }
        java.io.File out = new java.io.File(System.getProperty("user.home")
            + "/ps5-diff/out/mcontext_region.c");
        out.getParentFile().mkdirs();
        java.nio.file.Files.writeString(out.toPath(), all.toString());
        println("WROTE " + out.getAbsolutePath() + " functions=" + n);
        decomp.dispose();
    }
}
