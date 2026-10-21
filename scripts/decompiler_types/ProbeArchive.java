// Development-only probe: summarize a .gdt data type archive.
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.io.File;
import java.util.*;

public class ProbeArchive extends GhidraScript {
    @Override
    public void run() throws Exception {
        FileDataTypeManager m = FileDataTypeManager.openFileArchive(new File(getScriptArgs()[0]), false);
        try {
            Map<String, Integer> kinds = new TreeMap<>();
            Map<String, Integer> cats = new TreeMap<>();
            List<FunctionDefinition> fns = new ArrayList<>();
            Iterator<DataType> it = m.getAllDataTypes();
            while (it.hasNext()) {
                DataType d = it.next();
                kinds.merge(d.getClass().getSimpleName(), 1, Integer::sum);
                if (d instanceof FunctionDefinition f) { fns.add(f); cats.merge(f.getCategoryPath().toString(), 1, Integer::sum); }
            }
            println("KINDS " + kinds);
            println("FUNCTION CATEGORIES " + cats.size());
            cats.entrySet().stream().limit(40).forEach(e -> println("  " + e));
            fns.sort(Comparator.comparing(FunctionDefinition::getName));
            for (String want : new String[]{"CreateFileW", "GetTickCount", "ExitProcess", "IsProcessorFeaturePresent", "AdjustTokenPrivileges", "RegisterClassExW"})
                for (FunctionDefinition f : fns) if (f.getName().equals(want)) {
                    println("FN " + f.getCategoryPath() + " " + f.getPrototypeString() + " cc=" + f.getCallingConventionName()
                        + " noreturn=" + f.hasNoReturn() + " varargs=" + f.hasVarArgs());
                }
        } finally { m.close(); }
    }
}
