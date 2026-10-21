// Development-only: dump Ghidra Function ID databases (.fidbf) for the offline packer.
// Args: <outDir> <db.fidbf>...
// Per database N writes: N.libs.tsv, N.funcs.tsv, N.sup.bin, N.inf.bin (little-endian u64 keys).
import db.*;
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.db.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.*;

public class ExportFid extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args[0]);
        out.mkdirs();
        FidFileManager mgr = FidFileManager.getInstance();
        for (int i = 1; i < args.length; i++) {
            File file = new File(args[i]);
            FidFile ff = mgr.addUserFidFile(file);
            try (FidDB fid = ff.getFidDB(false)) {
                dump(fid, new File(out, file.getName().replace(".fidbf", "")));
            }
        }
    }

    private void dump(FidDB fid, File base) throws Exception {
        DBHandle h = fid.getDBHandle();
        try (PrintWriter w = new PrintWriter(base + ".libs.tsv")) {
            for (LibraryRecord l : fid.getAllLibraries()) {
                w.println(l.getLibraryID() + "\t" + l.getLibraryFamilyName() + "\t" + l.getLibraryVersion()
                    + "\t" + l.getLibraryVariant() + "\t" + l.getGhidraLanguageID());
            }
        }
        Map<Long, String> strings = new HashMap<>();
        Table st = h.getTable("Strings Table");
        for (RecordIterator it = st.iterator(); it.hasNext();) {
            DBRecord r = it.next();
            strings.put(r.getKey(), r.getString(0));
        }
        long n = 0;
        try (PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(base + ".funcs.tsv")))) {
            Table ft = h.getTable("Functions Table");
            for (RecordIterator it = ft.iterator(); it.hasNext();) {
                DBRecord r = it.next();
                w.println(r.getKey() + "\t" + r.getLongValue(4) + "\t"
                    + Long.toHexString(r.getLongValue(1)) + "\t" + r.getShortValue(0) + "\t"
                    + r.getByteValue(2) + "\t" + Long.toHexString(r.getLongValue(3)) + "\t"
                    + (r.getByteValue(8) & 0xff) + "\t" + strings.get(r.getLongValue(5)));
                n++;
            }
        }
        long s = keys(h.getTable("Superior Table"), new File(base + ".sup.bin"));
        long inf = keys(h.getTable("Inferior Table"), new File(base + ".inf.bin"));
        println("FID " + base.getName() + " functions=" + n + " superior=" + s + " inferior=" + inf);
    }

    private long keys(Table t, File f) throws Exception {
        long n = 0;
        try (OutputStream o = new BufferedOutputStream(new FileOutputStream(f))) {
            ByteBuffer b = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
            for (RecordIterator it = t.iterator(); it.hasNext();) {
                b.clear();
                b.putLong(it.next().getKey());
                o.write(b.array());
                n++;
            }
        }
        return n;
    }
}
