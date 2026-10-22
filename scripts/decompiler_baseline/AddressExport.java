// Development-only: decompile the functions at an explicit address list with full Ghidra.
// usage (script args): OUTPUT_JSON ADDRESS_LIST_JSON, a JSON array of {"address":<int>,"role":<str>}.
// Output matches BaselineExport. An address with no Ghidra function is exported with
// ok=false and error "no function at address", so function-set disagreement is counted.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.regex.*;

public class AddressExport extends GhidraScript {
    static String esc(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            if (c == '"' || c == '\\') b.append('\\').append(c);
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') b.append("\\r");
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Path output = Path.of(args[0]);
        String list = Files.readString(Path.of(args[1]));
        Matcher m = Pattern.compile("\"address\"\\s*:\\s*(\\d+)\\s*,\\s*\"role\"\\s*:\\s*\"([^\"]*)\"").matcher(list);
        LinkedHashMap<Long, String> wanted = new LinkedHashMap<>();
        while (m.find()) wanted.put(Long.parseLong(m.group(1)), m.group(2));
        int total = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) total++;
        DecompInterface decompiler = new DecompInterface();
        StringBuilder out = new StringBuilder("{\"ghidra\":" + esc(ghidra.framework.Application.getApplicationVersion())
            + ",\"image_base\":" + esc(currentProgram.getImageBase().toString())
            + ",\"total_functions\":" + total + ",\"functions\":[");
        try {
            if (!decompiler.openProgram(currentProgram)) throw new Exception(decompiler.getLastMessage());
            boolean first = true;
            for (Map.Entry<Long, String> e : wanted.entrySet()) {
                Address a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(e.getKey());
                Function f = getFunctionAt(a);
                if (!first) out.append(','); first = false;
                out.append("\n{\"address\":").append(esc("0x" + a.toString()))
                   .append(",\"role\":").append(esc(e.getValue()));
                if (f == null) {
                    out.append(",\"name\":null,\"size\":0,\"signature\":null,\"params\":0,\"ok\":false,\"ms\":0,\"callees\":[],\"c\":null,\"error\":\"no function at address\"}");
                    continue;
                }
                long t0 = System.nanoTime();
                DecompileResults r = decompiler.decompileFunction(f, 30, monitor);
                double ms = (System.nanoTime() - t0) / 1e6;
                boolean ok = r.decompileCompleted() && r.getDecompiledFunction() != null;
                List<String> callees = new ArrayList<>();
                for (Function c : f.getCalledFunctions(monitor)) callees.add(c.getName());
                Collections.sort(callees);
                out.append(",\"name\":").append(esc(f.getName()))
                   .append(",\"size\":").append(f.getBody().getNumAddresses())
                   .append(",\"thunk\":").append(f.isThunk())
                   .append(",\"signature\":").append(esc(f.getPrototypeString(false, false)))
                   .append(",\"params\":").append(f.getParameterCount())
                   .append(",\"ok\":").append(ok)
                   .append(",\"ms\":").append(String.format("%.3f", ms))
                   .append(",\"callees\":[");
                for (int i = 0; i < callees.size(); i++) out.append(i > 0 ? "," : "").append(esc(callees.get(i)));
                out.append("],\"c\":").append(esc(ok ? r.getDecompiledFunction().getC() : null))
                   .append(",\"error\":").append(esc(ok ? null : r.getErrorMessage())).append('}');
            }
        } finally {
            decompiler.dispose();
        }
        out.append("\n]}\n");
        Files.createDirectories(output.getParent());
        Files.writeString(output, out.toString(), StandardCharsets.UTF_8);
    }
}
