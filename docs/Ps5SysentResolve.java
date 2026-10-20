// Ps5SysentResolve.java — find sysent[] adjacent to sysentnames[], resolve the
// thr_create(430) handler, decompile it, and anchor doreti/double-fault paths.
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.Reference;

public class Ps5SysentResolve extends GhidraScript {
    static final long TEXT_BASE = 0xffffffff9e3f0000L;
    static final long TEXT_END  = TEXT_BASE + 0xCC0000L;
    static final long DATA_BASE = 0xffffffff9f0b0000L;
    static final long DATA_OFF  = 0xCC0000L;

    static byte[] le(long v) {
        byte[] b = new byte[8];
        for (int i = 0; i < 8; i++) b[i] = (byte) ((v >>> (8 * i)) & 0xff);
        return b;
    }
    long off2va(long fo) { return fo < DATA_OFF ? fo + TEXT_BASE : fo - DATA_OFF + DATA_BASE; }
    long va2off(long va) {
        if (va >= TEXT_BASE && va < TEXT_END) return va - TEXT_BASE;
        if (va >= DATA_BASE) return va - DATA_BASE + DATA_OFF;
        return -1;
    }
    boolean isText(long v) { return v >= TEXT_BASE && v < TEXT_END; }

    Address fo2addr(Memory mem, long fo) {
        return mem.getMinAddress().getAddressSpace().getAddress(fo); // raw import: addr == file offset
    }

    public void run() throws Exception {
        Program p = currentProgram;
        Memory mem = p.getMemory();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(p);

        // names array base: thr_create name ptr sits at index 430
        long namesThrCreate = 0x254c880L;
        long namesBase = namesThrCreate - 430L * 8;
        println("names array base (file off) 0x" + Long.toHexString(namesBase)
            + " (VA 0x" + Long.toHexString(off2va(namesBase)) + ")");

        // deterministic: find sysentvec.sv_names pointer -> scan around it for sv_ent
        println("=== SYSENT VIA SYSENTVEC ===");
        long namesVA = off2va(namesBase);
        Address hv = find(mem.getMinAddress(), le(namesVA));
        while (hv != null) {
            println("  sv_names candidate at off 0x" + Long.toHexString(hv.getOffset()));
            for (long fieldOff = -64; fieldOff <= 64; fieldOff += 8) {
                if (fieldOff == 0) continue;
                long entPtr;
                try { entPtr = mem.getLong(hv.add(fieldOff)); } catch (Exception e) { continue; }
                long entOff = va2off(entPtr);
                if (entOff < 0) continue;
                for (long stride : new long[]{24, 32, 40, 48, 56, 64}) {
                    for (long callOff = 0; callOff < stride - 7; callOff += 8) {
                        try {
                            long v430 = mem.getLong(fo2addr(mem, entOff + 430 * stride + callOff));
                            long v20  = mem.getLong(fo2addr(mem, entOff + 20 * stride + callOff));
                            long v455 = mem.getLong(fo2addr(mem, entOff + 455 * stride + callOff));
                            long v3   = mem.getLong(fo2addr(mem, entOff + 3 * stride + callOff));
                            if (isText(v430) && isText(v20) && isText(v455) && isText(v3)) {
                                println("    HIT fieldOff=" + fieldOff + " stride=" + stride + " callOff=" + callOff
                                    + " table_off=0x" + Long.toHexString(entOff));
                                println("    thr_create VA 0x" + Long.toHexString(v430)
                                    + " off 0x" + Long.toHexString(va2off(v430))
                                    + " | getpid VA 0x" + Long.toHexString(v20)
                                    + " | thr_new VA 0x" + Long.toHexString(v455));
                                Address ha = fo2addr(mem, va2off(v430));
                                Function f = getFunctionAt(ha);
                                if (f == null) f = createFunction(ha, "sys_thr_create_430");
                                DecompileResults r = decomp.decompileFunction(f, 120, monitor);
                                if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                                    String c = r.getDecompiledFunction().getC();
                                    String[] lines = c.split("\n");
                                    for (int i = 0; i < Math.min(lines.length, 90); i++) println("    | " + lines[i]);
                                    if (lines.length > 90) println("    | ... " + lines.length + " lines total");
                                } else println("    decompile failed");
                                fieldOff = 1000; callOff = stride + 100; stride = 1000;
                            }
                        } catch (Exception e) {}
                    }
                }
            }
            hv = find(hv.add(8), le(namesVA));
        }

        // fallback: histogram data->text pointers; sys_nosys fan-out reveals sysent stride
        println("=== NOSYS FANOUT HISTOGRAM ===");
        java.util.HashMap<Long, java.util.ArrayList<Long>> hist = new java.util.HashMap<>();
        long dataStart = DATA_OFF, dataEnd = mem.getMaxAddress().getOffset();
        for (long fo = dataStart; fo + 8 < dataEnd; fo += 8) {
            long v;
            try { v = mem.getLong(fo2addr(mem, fo)); } catch (Exception e) { continue; }
            if (isText(v)) {
                hist.computeIfAbsent(v, k -> new java.util.ArrayList<>()).add(fo);
            }
        }
        java.util.ArrayList<Long> counts = new java.util.ArrayList<>(hist.keySet().stream()
            .filter(k -> hist.get(k).size() >= 20).map(k -> (long) hist.get(k).size()).toList());
        println("  text targets with >=20 data refs: " + counts.size());
        for (long tva : hist.keySet()) {
            java.util.ArrayList<Long> pos = hist.get(tva);
            if (pos.size() < 20) continue;
            java.util.Collections.sort(pos);
            long s0 = pos.get(1) - pos.get(0);
            if (s0 < 16 || s0 > 128) continue;
            boolean constStride = true;
            for (int i = 2; i < Math.min(pos.size(), 40); i++)
                if (pos.get(i) - pos.get(i - 1) != s0) { constStride = false; break; }
            println("  target VA 0x" + Long.toHexString(tva) + " count=" + pos.size()
                + " first_off=0x" + Long.toHexString(pos.get(0))
                + " first_deltas=" + (pos.size() > 6 ? "see constStride" : "?")
                + " constStride=" + constStride + " s0=" + s0);
            if (!constStride) continue;
            // score every alignment: how many key entries look like real handlers
            for (long base = pos.get(0) - 2100 * s0; base <= pos.get(0) + 64; base += s0) {
                try {
                    long[] h = new long[6];
                    int[] idx = { 3, 20, 430, 431, 433, 455 };
                    int score = 0;
                    for (int j = 0; j < 6; j++) {
                        h[j] = mem.getLong(fo2addr(mem, base + idx[j] * s0));
                        if (isText(h[j]) && h[j] != tva) {
                            boolean dup = false;
                            for (int k = 0; k < j; k++) if (h[k] == h[j]) dup = true;
                            if (!dup) score++;
                        }
                    }
                    if (score >= 5) {
                        println("    ALIGN base_off=0x" + Long.toHexString(base)
                            + " base_VA=0x" + Long.toHexString(off2va(base))
                            + " stride=" + s0 + " score=" + score);
                        for (int j = 0; j < 6; j++)
                            println("      " + idx[j] + " -> VA 0x" + Long.toHexString(h[j])
                                + (isText(h[j]) ? " off 0x" + Long.toHexString(va2off(h[j])) : ""));
                        if (isText(h[2]) && h[2] != tva) {
                            Address ha = fo2addr(mem, va2off(h[2]));
                            Function f = getFunctionAt(ha);
                            if (f == null) f = createFunction(ha, "sys_thr_create_430");
                            DecompileResults r = decomp.decompileFunction(f, 120, monitor);
                            if (r != null && r.decompileCompleted() && r.getDecompiledFunction() != null) {
                                String c = r.getDecompiledFunction().getC();
                                String[] lines = c.split("\n");
                                for (int i = 0; i < Math.min(lines.length, 90); i++) println("    | " + lines[i]);
                                if (lines.length > 90) println("    | ... " + lines.length + " lines total");
                            } else println("    decompile failed");
                        }
                        base = pos.get(0) + 100000; // stop at first strong alignment
                    }
                } catch (Exception e) {}
            }
        }

        // panic-string anchors via reference manager (LEA refs from analysis)
        println("=== PANIC STRING XREFS (reference manager) ===");
        String[] strs = { "Fatal double fault", "iret trap", "child curthread",
                          "Bad rip", "scheduling" };
        for (String s : strs) {
            Address a = findBytes(mem.getMinAddress(), s);
            if (a == null) { println("  '" + s + "': not found"); continue; }
            println("  '" + s + "' at off 0x" + Long.toHexString(a.getOffset()));
            java.util.Iterator<Reference> it = currentProgram.getReferenceManager().getReferencesTo(a).iterator();
            int n = 0;
            while (it.hasNext()) {
                Reference ref = it.next();
                if (n++ > 6) { println("    ..."); break; }
                Address from = ref.getFromAddress();
                Function fn = getFunctionContaining(from);
                println("    ref from off 0x" + Long.toHexString(from.getOffset())
                    + (fn != null ? " in FUNC " + fn.getName()
                       + " VA 0x" + Long.toHexString(fn.getEntryPoint().getOffset() + TEXT_BASE) : ""));
            }
            if (n == 0) println("    (no refs)");
        }

        // 0x480 immediate occurrences in text with context
        println("=== 0x480 IMMEDIATE OCCURRENCES IN TEXT ===");
        byte[] pat = { (byte) 0x80, 0x04, 0x00, 0x00 };
        Address hit = mem.getMinAddress();
        int n = 0;
        while (n < 40) {
            hit = find(hit, pat);
            if (hit == null) break;
            long off = hit.getOffset();
            if (off < DATA_OFF) {
                StringBuilder sb = new StringBuilder("  off 0x" + Long.toHexString(off) + " ctx:");
                for (int k = -6; k < 0; k++) {
                    try { sb.append(String.format(" %02x", mem.getByte(hit.add(k)))); }
                    catch (Exception e) { sb.append(" ??"); }
                }
                println(sb.toString());
                n++;
            }
            hit = hit.add(1);
        }
        decomp.dispose();
    }
}
