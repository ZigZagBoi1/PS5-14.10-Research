// Import a separate retained data window into a NEW offline analysis project only.
// @category PS5.Reference
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.mem.MemoryBlock;
import java.nio.file.*;
import java.io.InputStream;

public class ImportRetainedData extends GhidraScript {
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length != 2) throw new IllegalArgumentException("DATA_FILE RECORDED_DATA_ORIGIN");
        Path path = Paths.get(args[0]);
        long length = Files.size(path);
        if (length <= 0) throw new IllegalArgumentException("Empty data window");
        Address start = toAddr(args[1]);
        Address end = start.addNoWrap(length - 1);
        if (currentProgram.getMemory().intersects(new AddressSet(start, end))) {
            throw new IllegalArgumentException("Data window overlaps existing mapping");
        }
        try (InputStream stream = Files.newInputStream(path)) {
            MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
                "retained_data_unverified", start, stream, length, monitor, false);
            block.setRead(true);
            block.setWrite(false);
            block.setExecute(false);
            block.setComment("13.60-labeled; acquisition authenticity unresolved. " +
                "Recorded window mapping; analysis permissions do not prove target permissions. " + path);
        }
        println("Imported retained data: " + start + ".." + end + "; bytes=" + length);
    }
}
