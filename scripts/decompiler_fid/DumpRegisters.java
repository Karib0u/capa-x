// Development-only: dump register name/offset/bit-length of the loaded program's language.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.lang.Register;

public class DumpRegisters extends GhidraScript {
    @Override
    public void run() throws Exception {
        try (var w = new java.io.PrintWriter(getScriptArgs()[0])) {
            for (Register r : currentProgram.getLanguage().getRegisters()) {
                if (!r.getAddress().isRegisterAddress()) continue;
                w.println(r.getName() + "\t" + r.getOffset() + "\t" + r.getBitLength());
            }
        }
    }
}
