// Apply recorded syscall reference labels and optionally export selected pseudocode.
// @category PS5.Reference
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.math.BigInteger;
import java.util.*;

public class LabelRetainedSysent extends GhidraScript {
    private static final String QUAL = "13.60-labeled; acquisition authenticity unresolved";

    private Address offsetAddress(Address origin, String offset) throws Exception {
        BigInteger value = new BigInteger(offset.replaceFirst("^0[xX]", ""), 16);
        return origin.addNoWrap(value.longValueExact());
    }

    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            throw new IllegalArgumentException("TSV EXPORT_DIRECTORY TEXT_FILE_ORIGIN [FUNCTION_OFFSET ...]");
        }
        Path input = Paths.get(args[0]);
        Path output = Paths.get(args[1]);
        if (Files.exists(output)) throw new IllegalArgumentException("Export directory must be new");
        Address origin = toAddr(args[2]);
        List<String> lines = Files.readAllLines(input, StandardCharsets.UTF_8);
        Map<Address,List<String[]>> groups = new LinkedHashMap<>();
        Set<Integer> selectors = new HashSet<>();
        // Preflight all rows before changing the new analysis database.
        for (int i = 1; i < lines.size(); i++) {
            monitor.checkCancelled();
            String[] row = lines.get(i).split("\t", -1);
            if (row.length != 6) throw new IllegalArgumentException("Malformed TSV row " + i);
            int selector = Integer.parseInt(row[0]);
            if (selector < 0 || !selectors.add(selector)) throw new IllegalArgumentException("Repeated selector");
            Address target = offsetAddress(origin, row[3]);
            if (!currentProgram.getMemory().contains(target) ||
                !currentProgram.getMemory().getBlock(target).isInitialized()) {
                throw new IllegalArgumentException("Unmapped reference target: " + target);
            }
            groups.computeIfAbsent(target, key -> new ArrayList<>()).add(row);
        }
        Files.createDirectory(output);
        List<String> log = new ArrayList<>();
        log.add(QUAL);
        log.add("Coordinates: explicit text-file origin " + origin + "; no prototypes assigned.");
        for (Map.Entry<Address,List<String[]>> entry : groups.entrySet()) {
            Address address = entry.getKey();
            StringBuilder comment = new StringBuilder(QUAL + "\nRecorded entry targets; may be shared stubs.\n");
            for (String[] row : entry.getValue()) {
                String name = String.format("sc_ref_%03d", Integer.parseInt(row[0]));
                if (Arrays.stream(currentProgram.getSymbolTable().getSymbols(address))
                        .noneMatch(symbol -> symbol.getName().equals(name))) {
                    currentProgram.getSymbolTable().createLabel(address, name, SourceType.USER_DEFINED);
                }
                comment.append(String.join(" | ", row)).append('\n');
            }
            String old = currentProgram.getListing().getComment(CodeUnit.PLATE_COMMENT, address);
            currentProgram.getListing().setComment(address, CodeUnit.PLATE_COMMENT,
                (old == null ? "" : old + "\n") + comment);
        }
        int verified = 0;
        for (Map.Entry<Address,List<String[]>> entry : groups.entrySet()) {
            for (String[] row : entry.getValue()) {
                String name = String.format("sc_ref_%03d", Integer.parseInt(row[0]));
                if (Arrays.stream(currentProgram.getSymbolTable().getSymbols(entry.getKey()))
                    .noneMatch(symbol -> symbol.getName().equals(name))) {
                    throw new IllegalStateException("Label readback failed: " + name);
                }
                verified++;
            }
        }
        log.add("reference_labels=" + selectors.size() + " distinct_recorded_targets=" + groups.size());
        log.add("labels_verified_by_readback=" + verified);
        // Explicit selected functions only; labels are not 679 claimed implementations.
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new IllegalStateException("Decompiler open failed");
            for (int i = 3; i < args.length; i++) {
                monitor.checkCancelled();
                Address address = offsetAddress(origin, args[i]);
                if (!currentProgram.getMemory().contains(address)) throw new IllegalArgumentException("Unmapped selection");
                disassemble(address);
                Function function = getFunctionAt(address);
                if (function == null) function = createFunction(address, "ref_body_" + address);
                if (function == null) {
                    log.add("FUNCTION_UNRESOLVED " + address);
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 45, monitor);
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) {
                    log.add("DECOMPILE_UNRESOLVED " + address + " " + result.getErrorMessage());
                    continue;
                }
                String text = "/* " + QUAL + "; Ghidra pseudocode, not original source. */\n" +
                    result.getDecompiledFunction().getC();
                Files.writeString(output.resolve("function_" + address + ".c"), text, StandardCharsets.UTF_8);
                log.add("DECOMPILED " + address + " body=" + function.getBody());
            }
        } finally { decompiler.dispose(); }
        Files.write(output.resolve("ANNOTATION_LOG.txt"), log, StandardCharsets.UTF_8);
        println(String.join("\n", log));
    }
}
