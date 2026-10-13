// Ghidra post-script that emits bounded function pseudocode as JSON.
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.File;
import java.io.FileWriter;
import java.io.Writer;

public class ExportFunctions extends GhidraScript {
    private String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
            .replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t");
    }

    @Override
    public void run() throws Exception {
        if (getScriptArgs().length < 1) throw new IllegalArgumentException("output path required");
        File output = new File(getScriptArgs()[0]);
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(currentProgram);
        int count = 0;
        try (Writer writer = new FileWriter(output)) {
            writer.write("[\n");
            FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext() && count < 500) {
                Function function = functions.next();
                DecompileResults result = decompiler.decompileFunction(function, 30, new ConsoleTaskMonitor());
                if (!result.decompileCompleted() || result.getDecompiledFunction() == null) continue;
                String pseudocode = result.getDecompiledFunction().getC();
                if (pseudocode == null || pseudocode.isBlank()) continue;
                if (count > 0) writer.write(",\n");
                writer.write("{\"address\":\"" + escape(function.getEntryPoint().toString())
                    + "\",\"name\":\"" + escape(function.getName())
                    + "\",\"pseudocode\":\"" + escape(pseudocode) + "\"}");
                count++;
            }
            writer.write("\n]\n");
        } finally {
            decompiler.dispose();
        }
    }
}
