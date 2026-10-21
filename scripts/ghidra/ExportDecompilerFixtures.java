// Development-time reference generation only. Requires pinned Ghidra 11.4.2.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.util.Set;

public class ExportDecompilerFixtures extends GhidraScript {
    @Override
    public void run() throws Exception {
        Set<String> names = Set.of("arithmetic", "branches", "loops", "switches",
            "stack_variables", "imported_call", "nonreturn");
        Path directory = Path.of(getScriptArgs()[0]);
        Files.createDirectories(directory);
        DecompInterface decompiler = new DecompInterface();
        try {
            if (!decompiler.openProgram(currentProgram)) throw new Exception(decompiler.getLastMessage());
            for (Function function : currentProgram.getFunctionManager().getFunctions(true)) {
                if (!names.contains(function.getName())) continue;
                DecompileResults result = decompiler.decompileFunction(function, 10, monitor);
                if (!result.decompileCompleted()) throw new Exception(result.getErrorMessage());
                Files.writeString(directory.resolve(function.getName() + ".c"),
                    result.getDecompiledFunction().getC(), StandardCharsets.UTF_8);
            }
        } finally { decompiler.dispose(); }
    }
}
