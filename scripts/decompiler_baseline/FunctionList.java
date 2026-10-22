// Development-only: list every function Ghidra recovers after default analysis.
// Used to measure function-set agreement (discovery) against capa-x recovery.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.nio.file.Files;
import java.nio.file.Path;

public class FunctionList extends GhidraScript {
    @Override
    public void run() throws Exception {
        Path output = Path.of(getScriptArgs()[0]);
        StringBuilder out = new StringBuilder("{\"ghidra\":\"" + ghidra.framework.Application.getApplicationVersion()
            + "\",\"image_base\":\"" + currentProgram.getImageBase() + "\",\"functions\":[");
        boolean first = true;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal()) continue;
            Address thunk = f.isThunk() && f.getThunkedFunction(false) != null
                ? f.getThunkedFunction(false).getEntryPoint() : null;
            if (!first) out.append(',');
            first = false;
            out.append("{\"entry\":").append(f.getEntryPoint().getOffset())
               .append(",\"size\":").append(f.getBody().getNumAddresses())
               .append(",\"ranges\":[");
            boolean firstRange = true;
            for (ghidra.program.model.address.AddressRange r : f.getBody()) {
                if (!firstRange) out.append(',');
                firstRange = false;
                out.append('[').append(r.getMinAddress().getOffset()).append(',').append(r.getMaxAddress().getOffset()).append(']');
            }
            out.append("]");
            // Incoming references show how Ghidra reached the entry: a call or
            // jump from code, or a data pointer, or nothing (pattern or table).
            java.util.TreeMap<String, Integer> kinds = new java.util.TreeMap<>();
            for (ghidra.program.model.symbol.Reference r : currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint()))
                kinds.merge(r.getReferenceType().getName(), 1, Integer::sum);
            out.append(",\"refs\":{");
            boolean firstKind = true;
            for (java.util.Map.Entry<String, Integer> k : kinds.entrySet()) {
                if (!firstKind) out.append(',');
                firstKind = false;
                out.append('"').append(k.getKey()).append("\":").append(k.getValue());
            }
            out.append("}");
            out.append(",\"thunk\":").append(f.isThunk())
               .append(",\"thunk_target\":").append(thunk == null ? "null" : Long.toString(thunk.getOffset()))
               .append('}');
        }
        out.append("]}");
        Files.writeString(output, out.toString());
    }
}
