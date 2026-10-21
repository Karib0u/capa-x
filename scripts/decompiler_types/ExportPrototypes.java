// Development-only: export function prototypes and their type closure from Ghidra data type
// archives, encoded with Ghidra's own decompiler marshalling so the embedded engine decodes
// exactly what Ghidra's decompiler would receive.
//
// args: OUTPUT ARCHIVE [ARCHIVE...]   (earlier archives win on name clashes)
// Output lines (tab separated, XML contains no tabs or newlines):
//   F name xml-prototype
//   T hex-id name xml-type
import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.pcode.*;
import java.io.File;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

public class ExportPrototypes extends GhidraScript {
    private static final Pattern TYPEREF = Pattern.compile("<typeref name=\"([^\"]*)\" id=\"(0x[0-9a-f]+)\"");
    private PcodeDataTypeManager pdtm;
    private final Map<String, String> typeXml = new TreeMap<>();   // id -> "name\txml"
    private final Set<String> visiting = new HashSet<>();
    private int skipped = 0;

    private String encode(DataType dt, boolean ref) throws Exception {
        XmlEncode e = new XmlEncode(false);
        if (ref) pdtm.encodeTypeRef(e, dt, dt.getLength()); else pdtm.encodeType(e, dt, dt.getLength());
        return e.toString().replace("\n", "").replace("\t", " ");
    }

    /** Record every named type reachable from dt. */
    private void collect(DataType dt) throws Exception {
        if (dt == null) return;
        if (dt instanceof TypeDef td) { record(dt); collect(td.getDataType()); return; }
        if (dt instanceof Pointer p) { collect(p.getDataType()); return; }
        if (dt instanceof Array a) { collect(a.getDataType()); return; }
        if (dt instanceof Composite c) {
            if (!record(dt)) return;
            for (DataTypeComponent comp : c.getDefinedComponents()) collect(comp.getDataType());
            return;
        }
        if (dt instanceof FunctionDefinition f) {
            collect(f.getReturnType());
            for (ParameterDefinition p : f.getArguments()) collect(p.getDataType());
            return;
        }
        record(dt);
    }

    /** @return true when newly recorded. */
    private boolean record(DataType dt) throws Exception {
        String ref = encode(dt, true);
        Matcher m = TYPEREF.matcher(ref);
        if (!m.find()) return false;
        String id = m.group(2);
        if (typeXml.containsKey(id) || !visiting.add(id)) return false;
        typeXml.put(id, m.group(1) + "\t" + encode(dt, false));
        return true;
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        pdtm = new PcodeDataTypeManager(currentProgram, name -> name);
        CompilerSpec spec = currentProgram.getCompilerSpec();
        Map<String, String> functions = new TreeMap<>();
        for (int a = 1; a < args.length; a++) {
            FileDataTypeManager m = FileDataTypeManager.openFileArchive(new File(args[a]), false);
            try {
                List<FunctionDefinition> defs = new ArrayList<>();
                Iterator<DataType> it = m.getAllDataTypes();
                while (it.hasNext()) if (it.next() instanceof FunctionDefinition f) defs.add(f);
                defs.sort(Comparator.comparing((FunctionDefinition f) -> f.getCategoryPath().toString())
                    .thenComparing(FunctionDefinition::getName));
                for (FunctionDefinition f : defs) {
                    String category = f.getCategoryPath().toString();
                    if (category.contains("intrin.h") || functions.containsKey(f.getName())) continue;
                    try {
                        FunctionPrototype proto = new FunctionPrototype(f, spec, false);
                        XmlEncode e = new XmlEncode(false);
                        proto.encodePrototype(e, pdtm, 0);
                        String xml = e.toString().replace("\n", "").replace("\t", " ");
                        collect(f);
                        functions.put(f.getName(), xml);
                    } catch (Exception ex) {
                        skipped++;
                        println("skip " + f.getName() + ": " + ex);
                    }
                }
            } finally {
                m.close();
            }
        }
        StringBuilder out = new StringBuilder();
        for (Map.Entry<String, String> e : functions.entrySet())
            out.append("F\t").append(e.getKey()).append('\t').append(e.getValue()).append('\n');
        for (Map.Entry<String, String> e : typeXml.entrySet())
            out.append("T\t").append(e.getKey()).append('\t').append(e.getValue()).append('\n');
        Files.writeString(Path.of(args[0]), out.toString());
        println("exported functions=" + functions.size() + " types=" + typeXml.size() + " skipped=" + skipped + " bytes=" + out.length());
    }
}
