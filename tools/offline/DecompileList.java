import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.*;

public class DecompileList extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String addrFile = args[0];
        String outDir = args[1];
        DecompInterface di = new DecompInterface();
        DecompileOptions opts = new DecompileOptions();
        di.setOptions(opts);
        di.openProgram(currentProgram);
        List<String> lines = new ArrayList<>();
        try (BufferedReader r = new BufferedReader(new FileReader(addrFile))) {
            String l;
            while ((l = r.readLine()) != null) {
                l = l.trim();
                if (!l.isEmpty() && !l.startsWith("#")) lines.add(l);
            }
        }
        for (String l : lines) {
            // each line: <hexaddr> [<label>]
            String[] p = l.split("\\s+", 2);
            Address a = currentProgram.getAddressFactory().getAddress(p[0]);
            Function f = getFunctionAt(a);
            if (f == null) {
                f = createFunction(a, p.length > 1 ? p[1] : "func_" + p[0]);
            }
            if (f == null) { println("no function at " + p[0]); continue; }
            DecompileResults res = di.decompileFunction(f, 120, monitor);
            String name = p.length > 1 ? p[1] : f.getName();
            try (PrintWriter w = new PrintWriter(outDir + "/" + name + ".c")) {
                if (res.decompileCompleted()) {
                    w.println("// " + f.getEntryPoint() + " " + f.getName());
                    w.println(res.getDecompiledFunction().getC());
                } else {
                    w.println("// DECOMPILE FAILED: " + res.getErrorMessage());
                }
            }
            println("decompiled " + name + " @ " + f.getEntryPoint());
        }
        di.dispose();
    }
}
