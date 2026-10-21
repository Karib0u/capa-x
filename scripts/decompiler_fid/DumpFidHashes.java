// Development-only ground truth: Ghidra's own FID hashes and per-instruction hash inputs.
// Args: <out.tsv>. Writes lines:
//   F <entry> <name> <cus> <fullHash> <specAdd> <specHash> <bodyInstrCount> <fidBookmark|-> <T|-> <callee entries,>
//   I <entry> <addr> <hexbytes> <hexmask> <flow call 0/1> <op0 desc>|<op1 desc>...
// Operand desc is the list of objects as S:<signed>,R:<regoffset>,A for Scalar, Register, Address,
// prefixed by the operand type bits in hex.
import ghidra.app.script.GhidraScript;
import ghidra.feature.fid.hash.*;
import ghidra.feature.fid.service.FidProgramSeeker;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.address.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import java.io.*;
import java.util.*;

public class DumpFidHashes extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        FidService svc = new FidService();
        FidHasher hasher = svc.getHasher(currentProgram);
        try (PrintWriter w = new PrintWriter(new BufferedWriter(new FileWriter(args[0])))) {
            for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
                if (f.isExternal() || f.isThunk() && false) continue;
                FidHashQuad q;
                try {
                    q = hasher.hash(f);
                } catch (Exception e) {
                    continue;
                }
                if (q == null) continue;
                String entry = f.getEntryPoint().toString();
                int count = 0;
                StringBuilder ins = new StringBuilder();
                for (Instruction i : currentProgram.getListing().getInstructions(f.getBody(), true)) {
                    count++;
                    byte[] b = i.getBytes();
                    Mask m = i.getPrototype().getInstructionMask();
                    byte[] mb = m == null ? new byte[0] : m.getBytes();
                    ins.append("I\t").append(entry).append('\t').append(i.getAddress()).append('\t')
                        .append(hex(b)).append('\t').append(hex(mb)).append('\t')
                        .append(i.getFlowType().isCall() ? 1 : 0).append('\t');
                    for (int op = 0; op < i.getNumOperands(); op++) {
                        Mask om = i.getPrototype().getOperandValueMask(op);
                        ins.append(Integer.toHexString(i.getOperandType(op))).append('/')
                            .append(om == null ? "null" : hex(om.getBytes())).append(':');
                        for (Object o : i.getOpObjects(op)) {
                            if (o instanceof Scalar s) ins.append("S").append(s.getSignedValue()).append(',');
                            else if (o instanceof Register r) ins.append("R").append(r.getOffset()).append(',');
                            else if (o instanceof Address) ins.append("A,");
                            else ins.append("?").append(o.getClass().getSimpleName()).append(',');
                        }
                        ins.append('|');
                    }
                    ins.append('\n');
                }
                var bm = currentProgram.getBookmarkManager().getBookmark(f.getEntryPoint(), BookmarkType.ANALYSIS, "Function ID Analyzer");
                StringBuilder kids = new StringBuilder();
                for (Function c : FidProgramSeeker.getChildren(f, true)) kids.append(c.getEntryPoint()).append(',');
                w.println("F\t" + entry + "\t" + f.getName() + "\t" + q.getCodeUnitSize() + "\t"
                    + Long.toHexString(q.getFullHash()) + "\t" + q.getSpecificHashAdditionalSize() + "\t"
                    + Long.toHexString(q.getSpecificHash()) + "\t" + count + "\t"
                    + (bm == null ? "-" : bm.getComment()) + "\t" + (f.isThunk() ? "T" : "-") + "\t" + kids);
                w.print(ins);
            }
        }
    }

    private static String hex(byte[] b) {
        StringBuilder s = new StringBuilder();
        for (byte x : b) s.append(String.format("%02x", x & 0xff));
        return s.toString();
    }
}
