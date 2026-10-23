import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.PrintWriter;
import java.io.BufferedReader;
import java.io.FileReader;
import java.util.*;

public class CopyoutReach extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String addrFile = args[0];   // lines: <syscall_num> <thunk_rva_hex>
        String outFile = args[1];
        long base = currentProgram.getMemory().getBlocks()[0].getStart().getOffset();
        println("block base = " + Long.toHexString(base));
        Address copyout = toAddr(base + 0x2591d0);
        Listing listing = currentProgram.getListing();

        // 1. all call sites of copyout
        Map<Address, Function> siteFuncs = new LinkedHashMap<>();
        ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(copyout);
        while (it.hasNext()) {
            Reference r = it.next();
            if (r.getReferenceType().isCall()) {
                Function f = getFunctionContaining(r.getFromAddress());
                if (f != null) siteFuncs.put(r.getFromAddress(), f);
            }
        }
        println("copyout call sites: " + siteFuncs.size());

        // 2. call graph
        Map<Function, Set<Function>> cg = new HashMap<>();
        FunctionIterator fi = currentProgram.getFunctionManager().getFunctions(true);
        while (fi.hasNext()) {
            Function f = fi.next();
            Set<Function> callees = new HashSet<>();
            InstructionIterator ii = listing.getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                for (Reference ref : ii.next().getReferencesFrom()) {
                    if (ref.getReferenceType().isCall()) {
                        Function t = getFunctionAt(ref.getToAddress());
                        if (t != null && t != f) callees.add(t);
                    }
                }
            }
            cg.put(f, callees);
        }
        println("call graph functions: " + cg.size());

        // 3. handlers: resolve thunk jmp targets
        List<long[]> handlers = new ArrayList<>(); // [num, rva]
        try (BufferedReader r = new BufferedReader(new FileReader(addrFile))) {
            String l;
            while ((l = r.readLine()) != null) {
                String[] p = l.trim().split("\\s+");
                if (p.length < 2) continue;
                int num = Integer.parseInt(p[0]);
                long rva = Long.parseLong(p[1].replace("0x", ""), 16);
                handlers.add(new long[]{num, rva});
            }
        }
        Map<Function, Integer> handlerNum = new HashMap<>();
        for (long[] h : handlers) {
            Address tAddr = toAddr(base + h[1]);
            Instruction ins = listing.getInstructionAt(tAddr);
            if (ins == null) {
                disassemble(tAddr);
                ins = listing.getInstructionAt(tAddr);
            }
            if (ins == null) continue;
            for (Reference ref : ins.getReferencesFrom()) {
                if (ref.getReferenceType().isJump()) {
                    Address t = ref.getToAddress();
                    Function real = getFunctionAt(t);
                    if (real == null) real = getFunctionContaining(t);
                    if (real == null) real = createFunction(t, "sys" + h[0] + "_handler");
                    if (real != null) { handlerNum.put(real, (int) h[0]); break; }
                }
            }
        }
        println("handler functions resolved: " + handlerNum.size());

        // 4. one forward closure per handler (depth-capped), then map sites
        Map<Function, Map<Function, Integer>> closures = new HashMap<>();
        for (Function h : handlerNum.keySet()) {
            closures.put(h, closure(cg, h, 8));
        }
        try (PrintWriter w = new PrintWriter(outFile)) {
            for (Map.Entry<Address, Function> e : siteFuncs.entrySet()) {
                Function siteFn = e.getValue();
                int best = -1; Function bestH = null;
                for (Function h : handlerNum.keySet()) {
                    Integer d = closures.get(h).get(siteFn);
                    if (d != null && (best == -1 || d < best)) { best = d; bestH = h; }
                }
                String tag = (bestH == null) ? "-" :
                    String.format("%d(%s) dist=%d", handlerNum.get(bestH), bestH.getName(), best);
                w.println(String.format("site=%s fn=%s reach=%s",
                    e.getKey(), siteFn.getName() + "@" + siteFn.getEntryPoint(), tag));
            }
        }
        println("wrote " + outFile);
    }

    Map<Function, Integer> closure(Map<Function, Set<Function>> cg, Function start, int maxDepth) {
        Map<Function, Integer> dist = new HashMap<>();
        dist.put(start, 0);
        Set<Function> frontier = new HashSet<>(); frontier.add(start);
        for (int d = 1; d <= maxDepth; d++) {
            Set<Function> next = new HashSet<>();
            for (Function f : frontier) {
                for (Function c : cg.getOrDefault(f, Collections.emptySet())) {
                    if (!dist.containsKey(c)) { dist.put(c, d); next.add(c); }
                }
            }
            frontier = next;
            if (frontier.isEmpty()) break;
        }
        return dist;
    }
}
