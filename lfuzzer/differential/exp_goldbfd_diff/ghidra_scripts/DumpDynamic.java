// Ghidra Java GhidraScript: ELF를 재파싱해 dynamic 태그를 덤프.
// R7 실증: Ghidra가 64비트 d_tag를 int로 절단하는지(getTag()) 확인.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.bin.FileByteProvider;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.elf.ElfDynamicTable;
import ghidra.app.util.bin.format.elf.ElfDynamic;
import java.io.File;
import java.nio.file.AccessMode;
public class DumpDynamic extends GhidraScript {
    @Override public void run() throws Exception {
        String path = currentProgram.getExecutablePath();
        File f = new File(path);
        FileByteProvider provider = new FileByteProvider(f, null, AccessMode.READ);
        ElfHeader elf = new ElfHeader(provider, msg -> {});
        elf.parse();
        println("GHIDRA_DUMP_START path=" + path);
        ElfDynamicTable dt = elf.getDynamicTable();
        if (dt == null) { println("no dynamic table"); }
        else {
            for (ElfDynamic d : dt.getDynamics()) {
                println("DT tag=0x" + Long.toHexString(d.getTag() & 0xffffffffL)
                        + " value=0x" + Long.toHexString(d.getValue()));
            }
        }
        try { int n=0; for (var st: elf.getSymbolTables()) n += st.getSymbols().length; println("GHIDRA_SYMCOUNT total=" + n); } catch (Throwable t) { println("GHIDRA_SYMCOUNT error=" + t); }
        println("GHIDRA_DUMP_END");
        provider.close();
    }
}
