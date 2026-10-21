// Development-only: choose baseline functions after full analysis and decompile them.
// Selection uses only Ghidra's function list: entry point, one export, the function with the
// most distinct imports, and application functions at size percentiles. No output is inspected.
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class BaselineExport extends GhidraScript {
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
        int perSample = Integer.parseInt(args[1]);
        List<Function> app = new ArrayList<>();
        int total = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            total++;
            if (f.isThunk() || f.isExternal() || f.getBody().getNumAddresses() < 8) continue;
            app.add(f);
        }
        app.sort(Comparator.comparingLong((Function f) -> f.getBody().getNumAddresses())
            .thenComparing(f -> f.getEntryPoint()));
        LinkedHashMap<Address, String> chosen = new LinkedHashMap<>();
        Function entry = null;
        for (Address a : currentProgram.getSymbolTable().getExternalEntryPointIterator()) {
            Function f = getFunctionAt(a);
            if (f == null || f.isThunk()) continue;
            Symbol s = currentProgram.getSymbolTable().getPrimarySymbol(a);
            if (s != null && s.getName().equals("entry") && entry == null) entry = f;
            else if (!chosen.containsKey(a) && !chosen.containsValue("export")) chosen.put(a, "export");
        }
        if (entry != null) chosen.put(entry.getEntryPoint(), "entry");
        Function best = null; int bestCount = 0;
        for (Function f : app) {
            Set<Address> imports = new HashSet<>();
            for (Instruction i : currentProgram.getListing().getInstructions(f.getBody(), true))
                for (Reference r : i.getReferencesFrom()) {
                    Address t = r.getToAddress();
                    for (Reference r2 : currentProgram.getReferenceManager().getReferencesFrom(t))
                        if (r2.isExternalReference()) imports.add(t);
                }
            if (imports.size() > bestCount) { bestCount = imports.size(); best = f; }
        }
        if (best != null) chosen.putIfAbsent(best.getEntryPoint(), "most_imports");
        int[] pct = {10, 50, 90, 100, 25, 75, 99, 5, 60};
        for (int p : pct) {
            if (chosen.size() >= perSample || app.isEmpty()) break;
            int idx = (int) Math.min(app.size() - 1, Math.round((app.size() - 1) * p / 100.0));
            chosen.putIfAbsent(app.get(idx).getEntryPoint(), "p" + p);
        }
        DecompInterface decompiler = new DecompInterface();
        StringBuilder out = new StringBuilder("{\"ghidra\":" + esc(ghidra.framework.Application.getApplicationVersion())
            + ",\"image_base\":" + esc(currentProgram.getImageBase().toString())
            + ",\"total_functions\":" + total + ",\"application_functions\":" + app.size()
            + ",\"functions\":[");
        try {
            if (!decompiler.openProgram(currentProgram)) throw new Exception(decompiler.getLastMessage());
            boolean first = true;
            for (Map.Entry<Address, String> e : chosen.entrySet()) {
                Function f = getFunctionAt(e.getKey());
                if (f == null) continue;
                long t0 = System.nanoTime();
                DecompileResults r = decompiler.decompileFunction(f, 30, monitor);
                double ms = (System.nanoTime() - t0) / 1e6;
                boolean ok = r.decompileCompleted() && r.getDecompiledFunction() != null;
                List<String> callees = new ArrayList<>();
                for (Function c : f.getCalledFunctions(monitor)) callees.add(c.getName());
                Collections.sort(callees);
                if (!first) out.append(','); first = false;
                out.append("\n{\"address\":").append(esc("0x" + e.getKey().toString()))
                   .append(",\"role\":").append(esc(e.getValue()))
                   .append(",\"name\":").append(esc(f.getName()))
                   .append(",\"size\":").append(f.getBody().getNumAddresses())
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
