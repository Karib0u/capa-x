// Development-only reference for explicit corpus addresses, using full analysis.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;

public class ExportSelectedFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Path.of(args[0]);
        Files.createDirectories(output);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) {
                throw new Exception(decompiler.getLastMessage());
            }
            for (int i = 1; i < args.length; i++) {
                Function function = getFunctionAt(toAddr(args[i]));
                if (function == null) {
                    Files.writeString(output.resolve(args[i] + ".error"), "No function at requested address");
                    continue;
                }
                DecompileResults result = decompiler.decompileFunction(function, 10, monitor);
                String text = result.decompileCompleted()
                    ? result.getDecompiledFunction().getC() : result.getErrorMessage();
                Files.writeString(output.resolve(args[i] + (result.decompileCompleted() ? ".c" : ".error")),
                    text, StandardCharsets.UTF_8);
            }
        } finally {
            decompiler.dispose();
        }
    }
}
