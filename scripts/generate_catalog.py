#!/usr/bin/env python3
"""Maintain the bundled, curated discovery catalog from explicit tool records.

Running this script does not download, install, or execute any third-party tool.
"""
from pathlib import Path
import json

# id | name | category | executable alternatives | tags | official website
ROWS = r'''
rea-upstream|REA (morluto)|framework|rea|all,agent,workflow|https://github.com/morluto/rea
ghidra|Ghidra|native|analyzeHeadless|native,firmware,decompile|https://ghidra-sre.org/
ida|IDA / Hex-Rays|native|ida,idat,ida64|native,decompile|https://hex-rays.com/ida-pro/
hopper|Hopper Disassembler|native|hopper|native,decompile|https://www.hopperapp.com/
binary-ninja|Binary Ninja|native|binaryninja|native,decompile|https://binary.ninja/
rizin|Rizin|native|rizin,rz-bin|native,firmware|https://rizin.re/
radare2|radare2|native|r2,rabin2|native,firmware|https://rada.re/
cutter|Cutter|native|cutter|native|https://cutter.re/
angr|angr|symbolic|angr|native,symbolic|https://angr.io/
capstone|Capstone|native|cstool|native,disassemble|https://www.capstone-engine.org/
keystone|Keystone|native|kstool|native,assemble|https://www.keystone-engine.org/
unicorn|Unicorn|emulation|unicorn|native,emulation|https://www.unicorn-engine.org/
qiling|Qiling|emulation|qiling|native,firmware,emulation|https://qiling.io/
triton|Triton|symbolic|triton|native,symbolic|https://triton-library.github.io/
miasm|Miasm|symbolic|miasm|native,symbolic|https://github.com/cea-sec/miasm
manticore|Manticore|symbolic|manticore|native,symbolic|https://github.com/trailofbits/manticore
gdb|GNU Debugger|debug|gdb|native,runtime|https://sourceware.org/gdb/
lldb|LLDB|debug|lldb|native,apple,runtime|https://lldb.llvm.org/
x64dbg|x64dbg|debug|x64dbg,x32dbg|native,windows,runtime|https://x64dbg.com/
windbg|WinDbg|debug|windbg,WinDbgX|native,windows,runtime|https://learn.microsoft.com/windows-hardware/drivers/debugger/
rr|rr record and replay|debug|rr|native,linux,runtime|https://rr-project.org/
strace|strace|runtime|strace|native,linux,runtime|https://strace.io/
ltrace|ltrace|runtime|ltrace|native,linux,runtime|https://ltrace.org/
frida|Frida|runtime|frida,frida-trace|native,android,apple,runtime|https://frida.re/
frida-ps|Frida Process Tool|runtime|frida-ps|native,android,apple,runtime|https://frida.re/
bpftrace|bpftrace|runtime|bpftrace|native,linux,runtime|https://bpftrace.org/
perf|Linux perf|runtime|perf|native,linux,runtime|https://perf.wiki.kernel.org/
valgrind|Valgrind|runtime|valgrind|native,linux,runtime|https://valgrind.org/
qemu|QEMU|emulation|qemu-system-x86_64,qemu-aarch64|firmware,native,emulation|https://www.qemu.org/
readelf|GNU readelf|binary-utilities|readelf|native,firmware|https://sourceware.org/binutils/
objdump|GNU objdump|binary-utilities|objdump|native,firmware|https://sourceware.org/binutils/
llvm-objdump|LLVM objdump|binary-utilities|llvm-objdump|native,firmware,apple|https://llvm.org/
llvm-readobj|LLVM readobj|binary-utilities|llvm-readobj|native,firmware,apple|https://llvm.org/
nm|GNU nm|binary-utilities|nm|native|https://sourceware.org/binutils/
objcopy|GNU objcopy|binary-utilities|objcopy|native,firmware|https://sourceware.org/binutils/
strings|GNU strings|binary-utilities|strings|native,firmware|https://sourceware.org/binutils/
file|file(1)|binary-utilities|file|all,native,firmware|https://www.darwinsys.com/file/
xxd|xxd|binary-utilities|xxd|all|https://www.vim.org/
hexdump|hexdump|binary-utilities|hexdump|all|https://man7.org/linux/man-pages/man1/hexdump.1.html
hexyl|hexyl|binary-utilities|hexyl|all|https://github.com/sharkdp/hexyl
imhex|ImHex|binary-utilities|imhex|all,firmware|https://imhex.werwolv.net/
010-editor|010 Editor|binary-utilities|010editor|all,firmware|https://www.sweetscape.com/010editor/
kaitai|Kaitai Struct Compiler|binary-utilities|ksc|all,formats|https://kaitai.io/
detect-it-easy|Detect It Easy|binary-utilities|die|native,windows|https://github.com/horsicq/Detect-It-Easy
pe-bear|PE-bear|binary-utilities|PE-bear|native,windows|https://github.com/hasherezade/pe-bear
pestudio|pestudio|binary-utilities|pestudio|native,windows|https://www.winitor.com/
checksec|checksec|binary-utilities|checksec|native,security|https://github.com/slimm609/checksec
lief|LIEF|binary-utilities|lief|native,formats|https://lief.re/
pefile|pefile|binary-utilities|pefile|native,windows|https://github.com/erocarrera/pefile
exiftool|ExifTool|binary-utilities|exiftool|all,metadata|https://exiftool.org/
trid|TrID|binary-utilities|trid|all,formats|https://mark0.net/soft-trid-e.html
hashdeep|hashdeep|forensics|hashdeep|all,evidence|https://github.com/jessek/hashdeep
yara|YARA|forensics|yara|all,malware|https://virustotal.github.io/yara-x/
yara-x|YARA-X|forensics|yr|all,malware|https://virustotal.github.io/yara-x/
capa|capa|forensics|capa|native,malware|https://github.com/mandiant/capa
floss|FLOSS|forensics|floss|native,malware|https://github.com/mandiant/flare-floss
volatility3|Volatility 3|forensics|vol|memory,forensics|https://github.com/volatilityfoundation/volatility3
rekall|Rekall|forensics|rekall|memory,forensics|https://github.com/google/rekall
bulk-extractor|bulk_extractor|forensics|bulk_extractor|all,forensics|https://github.com/simsong/bulk_extractor
foremost|Foremost|forensics|foremost|all,forensics|https://foremost.sourceforge.net/
binwalk|Binwalk|firmware|binwalk|firmware,formats|https://github.com/ReFirmLabs/binwalk
ubi-reader|ubi_reader|firmware|ubireader_display_info|firmware|https://github.com/onekey-sec/ubi_reader
jefferson|Jefferson|firmware|jefferson|firmware|https://github.com/sviehb/jefferson
uefitool|UEFITool|firmware|UEFITool|firmware,uefi|https://github.com/LongSoft/UEFITool
uefi-firmware-parser|UEFI Firmware Parser|firmware|uefi-firmware-parser|firmware,uefi|https://github.com/theopolis/uefi-firmware-parser
chipsec|CHIPSEC|firmware|chipsec_main|firmware,uefi|https://github.com/chipsec/chipsec
flashrom|flashrom|firmware|flashrom|firmware,hardware|https://flashrom.org/
dtc|Device Tree Compiler|firmware|dtc|firmware,linux|https://www.devicetree.org/
squashfs-tools|SquashFS tools|firmware|unsquashfs,mksquashfs|firmware,filesystem|https://github.com/plougher/squashfs-tools
simg2img|simg2img|firmware|simg2img|firmware,android|https://android.googlesource.com/platform/system/core/
android-adb|ADB|android|adb|android,runtime|https://developer.android.com/tools/adb
android-aapt2|AAPT2|android|aapt2|android,static|https://developer.android.com/tools/aapt2
android-apkanalyzer|APK Analyzer|android|apkanalyzer|android,static|https://developer.android.com/studio/command-line/apkanalyzer
android-apksigner|apksigner|android|apksigner|android,static|https://developer.android.com/tools/apksigner
jadx|JADX|android|jadx,jadx-gui|android,decompile|https://github.com/skylot/jadx
apktool|Apktool|android|apktool|android,static|https://apktool.org/
dex2jar|dex2jar|android|d2j-dex2jar,d2j-dex2jar.sh|android,decompile|https://github.com/pxb1988/dex2jar
baksmali|baksmali|android|baksmali|android,disassemble|https://github.com/JesusFreke/smali
smali|smali|android|smali|android,assemble|https://github.com/JesusFreke/smali
androguard|Androguard|android|androguard|android,static|https://github.com/androguard/androguard
mobsf|MobSF|android|mobsf|android,apple,security|https://github.com/MobSF/Mobile-Security-Framework-MobSF
objection|Objection|android|objection|android,apple,runtime|https://github.com/sensepost/objection
jeb|JEB Decompiler|android|jeb|android,decompile|https://www.pnfsoftware.com/
bundletool|Bundletool|android|bundletool|android,static|https://github.com/google/bundletool
ilspy|ILSpy|dotnet|ilspycmd|dotnet,decompile|https://github.com/icsharpcode/ILSpy
dnspyex|dnSpyEx|dotnet|dnSpy|dotnet,windows,decompile|https://github.com/dnSpyEx/dnSpy
ildasm|IL Disassembler|dotnet|ildasm|dotnet,static|https://learn.microsoft.com/dotnet/framework/tools/ildasm-exe-il-disassembler
monodis|Mono Disassembler|dotnet|monodis|dotnet,static|https://www.mono-project.com/
dotnet|dotnet CLI|dotnet|dotnet|dotnet,build|https://dotnet.microsoft.com/
java-javap|javap|java|javap|java,android,static|https://docs.oracle.com/en/java/
cfr|CFR Java Decompiler|java|cfr|java,decompile|https://www.benf.org/other/cfr/
procyon|Procyon|java|procyon|java,decompile|https://github.com/mstrobel/procyon
otool|otool|apple|otool|apple,native,static|https://developer.apple.com/
lipo|lipo|apple|lipo|apple,native,static|https://developer.apple.com/
codesign|codesign|apple|codesign|apple,static|https://developer.apple.com/
jtool2|jtool2|apple|jtool2|apple,native|https://www.newosxbook.com/tools/jtool.html
ipsw|ipsw|apple|ipsw|apple,firmware|https://github.com/blacktop/ipsw
wasm-tools|wasm-tools|wasm|wasm-tools|wasm,static|https://github.com/bytecodealliance/wasm-tools
wabt|WABT|wasm|wasm2wat,wasm-objdump|wasm,static|https://github.com/WebAssembly/wabt
binaryen|Binaryen|wasm|wasm-opt,wasm-dis|wasm,static|https://github.com/WebAssembly/binaryen
wasmtime|Wasmtime|wasm|wasmtime|wasm,runtime|https://wasmtime.dev/
node|Node.js|javascript|node|javascript,electron,web|https://nodejs.org/
npm|npm|javascript|npm|javascript,electron,web|https://www.npmjs.com/
asar|asar|javascript|asar|electron,static|https://github.com/electron/asar
ripgrep|ripgrep|javascript|rg|javascript,electron,web,source|https://github.com/BurntSushi/ripgrep
semgrep|Semgrep|javascript|semgrep|source,security,web|https://semgrep.dev/
esbuild|esbuild|javascript|esbuild|javascript,source|https://esbuild.github.io/
source-map-explorer|Source Map Explorer|javascript|source-map-explorer|javascript,web|https://github.com/danvk/source-map-explorer
playwright|Playwright|javascript|playwright|web,runtime|https://playwright.dev/
chrome|Chrome / Chromium|javascript|chromium,google-chrome,chrome|web,electron,runtime|https://www.chromium.org/
mitmproxy|mitmproxy|network|mitmproxy,mitmdump|network,web,runtime|https://mitmproxy.org/
wireshark|Wireshark|network|wireshark|network,forensics|https://www.wireshark.org/
tshark|tshark|network|tshark|network,forensics|https://www.wireshark.org/docs/man-pages/tshark.html
tcpdump|tcpdump|network|tcpdump|network,runtime|https://www.tcpdump.org/
scapy|Scapy|network|scapy|network,forensics|https://scapy.net/
protobuf|Protocol Buffers compiler|network|protoc|network,protocol|https://protobuf.dev/
grpcurl|grpcurl|network|grpcurl|network,protocol|https://github.com/fullstorydev/grpcurl
burp|Burp Suite|network|burpsuite|web,security|https://portswigger.net/burp
zap|OWASP ZAP|network|zap.sh,zap|web,security|https://www.zaproxy.org/
caido|Caido|network|caido|web,security|https://caido.io/
jq|jq|data|jq|all,data|https://jqlang.github.io/jq/
sqlite3|SQLite CLI|data|sqlite3|all,data|https://www.sqlite.org/
python|Python|data|python3,python|all,scripting|https://www.python.org/
git|Git|data|git|all,source|https://git-scm.com/
'''.strip()

ADAPTERS = {"file", "readelf", "objdump", "llvm-objdump", "llvm-readobj", "nm", "exiftool", "otool", "android-aapt2"}
expected = {"all", "native", "firmware", "android", "apple", "dotnet", "wasm", "electron", "javascript", "web", "network", "java", "runtime", "symbolic", "evidence", "source", "static", "data", "security", "scripting", "malware", "decompile", "disassemble", "assemble", "debug", "memory", "forensics", "windows", "linux", "emulation", "filesystem", "formats", "hardware", "uefi", "build", "metadata", "protocol", "agent", "workflow"}
items=[]
for i, line in enumerate(ROWS.splitlines(),1):
    parts=line.strip().split("|")
    if len(parts)!=6: raise ValueError(f"bad line {i}: {line}")
    ident,name,category,executables,tags,url=parts
    item={"id":ident,"name":name,"category":category,"executables":executables.split(","),"tags":tags.split(","),"homepage":url,
          "integration": "static-adapter" if ident in ADAPTERS else "discovery-only",
          "requires_authorization": True, "bundled": False}
    if not url.startswith("https://") or set(item["tags"])-expected: raise ValueError(f"Invalid tool data: {item}")
    items.append(item)
assert len({t['id'] for t in items})==len(items)
path=Path(__file__).resolve().parents[1]/"src"/"rei_rea"/"data"/"tools.json"
path.write_text(json.dumps({"schema_version":1,"tools":items},indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
print(f"wrote {len(items)} tools to {path}")
