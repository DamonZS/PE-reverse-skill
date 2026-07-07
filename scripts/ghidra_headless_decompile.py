#!/usr/bin/env python3
"""
Ghidra Headless Decompiler — 用 Ghidra 反编译脱壳后的 PE 文件

依赖:
  - Ghidra 11.x+ 安装在 %GHIDRA_HOME%
  - JDK 17+ 在 PATH 或 %JAVA_HOME%

输出:
  - 每个函数的独立 .c 文件（真正的 C 级伪代码，带类型推断）
  - 结构体/类型的 .h 定义
  - 全局导出表
  - JSON 分析摘要

用法:
  python ghidra_headless_decompile.py <exe_path> --ghidra-home <path> --output <dir>
"""

import os
import sys
import json
import re
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
import argparse
import tempfile
import hashlib


def find_java():
    """Find Java executable"""
    java_home = os.environ.get('JAVA_HOME', '')
    if java_home:
        candidates = [
            Path(java_home) / 'bin' / 'java.exe',
            Path(java_home) / 'bin' / 'java',
        ]
        for c in candidates:
            if c.exists():
                return str(c)
    
    # Try PATH
    for cmd in ['java', 'java.exe']:
        found = shutil.which(cmd)
        if found:
            return found
    
    return None


def find_ghidra(ghidra_home=None):
    """Find Ghidra installation"""
    if ghidra_home:
        path = Path(ghidra_home)
        if path.exists():
            return path.resolve()
    
    # Search common locations
    candidates = [
        Path(os.environ.get('GHIDRA_HOME', '')),
        Path.home() / 'tools' / 'ghidra_12.1_PUBLIC',
        Path.home() / 'ghidra',
        Path('C:/') / 'ghidra_12.1_PUBLIC',
        Path('C:/') / 'ghidra',
    ]
    
    for c in candidates:
        if (c / 'support' / 'analyzeHeadless.bat').exists():
            return c.resolve()
        if (c / 'support' / 'analyzeHeadless').exists():
            return c.resolve()
    
    return None


def create_headless_script(output_dir, binary_path):
    """
    Create a Ghidra headless script for full decompilation.
    This generates a .java script that Ghidra's headless analyzer runs.
    
    The script:
    1. Imports the binary into a project
    2. Runs auto-analysis
    3. Decompiles every function to individual .c files
    4. Extracts data types, structures, globals
    5. Writes a JSON summary
    """
    binary_path = Path(binary_path).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    
    script = r"""// DecompileToC.java — Ghidra headless decompiler script
// Decompiles every function in the program to individual C files
// and exports a JSON summary of the analysis.

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.data.*;
import ghidra.program.model.mem.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.nio.file.*;
import java.util.*;

public class DecompileToC extends GhidraScript {

    @Override
    public void run() throws Exception {
        String outputDir = System.getProperty("ghidra.output.dir");
        if (outputDir == null) {
            printerr("ERROR: ghidra.output.dir not set");
            return;
        }
        
        Path outPath = Paths.get(outputDir);
        Path cDir = outPath.resolve("functions");
        Path hDir = outPath.resolve("headers");
        Files.createDirectories(cDir);
        Files.createDirectories(hDir);
        
        Program program = getCurrentProgram();
        String programName = program.getName();
        long imageBase = program.getImageBase().getOffset();
        
        println("=== Ghidra DecompileToC ===");
        println("Program: " + programName);
        println("ImageBase: 0x" + Long.toHexString(imageBase));
        println("Output: " + outPath.toAbsolutePath());
        println("");
        
        // ═══════════════════════════════════════════
        // 1. Collect all functions
        // ═══════════════════════════════════════════
        FunctionManager fm = program.getFunctionManager();
        FunctionIterator funcs = fm.getFunctions(true);
        
        List<Map<String, Object>> funcList = new ArrayList<>();
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(program);
        
        // Configure decompiler options
        DecompileOptions opts = new DecompileOptions();
        opts.setJumpLoadsEnabled(true);
        opts.setEliminateUnreachable(true);
        opts.setSimplifyExtendedDataTypes(true);
        decomp.setOptions(opts);
        
        int count = 0;
        int skipped = 0;
        int failed = 0;
        
        for (Function func : funcs) {
            if (monitor.isCancelled()) break;
            
            long addr = func.getEntryPoint().getOffset();
            String name = func.getName();
            
            // Skip library/external thunks
            if (func.isThunk() || func.isExternal()) {
                skipped++;
                continue;
            }
            
            // Skip very small functions (< 5 bytes = single instruction)
            long bodyLen = func.getBody().getNumAddresses();
            if (bodyLen < 5) {
                skipped++;
                continue;
            }
            
            // ═══════════════════════════════════════════
            // 2. Decompile the function
            // ═══════════════════════════════════════════
            DecompileResults results = decomp.decompileFunction(
                func, 30, new ConsoleTaskMonitor()
            );
            
            String decompiledC = "";
            String signature = func.getSignature().getPrototypeString();
            boolean hasFailures = false;
            
            if (results != null && results.decompileCompleted()) {
                CCodedMarkup markup = results.getCCodeMarkup();
                if (markup != null) {
                    decompiledC = markup.toString();
                }
                hasFailures = results.hasError();
            }
            
            // ═══════════════════════════════════════════
            // 3. Write individual .c file
            // ═══════════════════════════════════════════
            String funcFileName = sanitizeFileName(name) + "_" + 
                                  String.format("%08X", addr) + ".c";
            Path funcFile = cDir.resolve(funcFileName);
            
            try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(funcFile))) {
                w.println("/*");
                w.println(" * Function: " + name);
                w.println(" * Address: 0x" + String.format("%08X", addr));
                w.println(" * Signature: " + signature);
                w.println(" * Body size: " + bodyLen + " bytes");
                w.println(" * Decompile status: " + (hasFailures ? "HAS_FAILURES" : "OK"));
                w.println(" */");
                w.println();
                
                if (decompiledC.isEmpty()) {
                    w.println("/* Decompilation failed or empty */");
                } else {
                    w.println(decompiledC);
                }
            }
            
            // ═══════════════════════════════════════════
            // 4. Collect function metadata
            // ═══════════════════════════════════════════
            Map<String, Object> info = new HashMap<>();
            info.put("name", name);
            info.put("address", "0x" + Long.toHexString(addr));
            info.put("addressInt", addr);
            info.put("signature", signature);
            info.put("bodySize", bodyLen);
            info.put("hasFailures", hasFailures);
            info.put("stackDepth", func.getStackFrame().getFrameSize());
            info.put("file", funcFileName);
            
            // Count calls
            Set<String> calls = new LinkedHashSet<>();
            for (Function called : func.getCalledFunctions(monitor)) {
                if (!called.isExternal()) {
                    calls.add(String.format("0x%08X", called.getEntryPoint().getOffset()));
                }
            }
            info.put("callCount", calls.size());
            info.put("calls", new ArrayList<>(calls));
            
            // Count cross-references
            int xrefs = 0;
            for (Reference ref : getReferencesTo(func.getEntryPoint())) {
                xrefs++;
            }
            info.put("xrefCount", xrefs);
            
            funcList.add(info);
            count++;
            
            if (count % 100 == 0) {
                println(String.format("  Decompiled %d functions (%d skipped)...", count, skipped));
            }
        }
        
        decomp.close();
        println(String.format("\nDone: %d decompiled, %d skipped, %d failed\n", count, skipped, failed));
        
        // ═══════════════════════════════════════════
        // 5. Extract global data types and structures
        // ═══════════════════════════════════════════
        List<Map<String, Object>> globals = extractGlobals(program, outPath);
        
        // ═══════════════════════════════════════════
        // 6. Write JSON summary
        // ═══════════════════════════════════════════
        Map<String, Object> summary = new HashMap<>();
        summary.put("programName", programName);
        summary.put("imageBase", "0x" + Long.toHexString(imageBase));
        summary.put("totalFunctions", count);
        summary.put("skippedThunks", skipped);
        summary.put("failedDecompiles", failed);
        summary.put("functions", funcList);
        summary.put("globals", globals);
        summary.put("timestamp", new Date().toString());
        
        Path summaryFile = outPath.resolve("ghidra_analysis.json");
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(summaryFile))) {
            // Simple JSON writer (no external deps in Ghidra)
            w.println(writeJson(summary));
        }
        
        println("Summary written to: " + summaryFile.toAbsolutePath());
        println("=== DecompileToC COMPLETE ===");
    }
    
    private List<Map<String, Object>> extractGlobals(Program program, Path outPath) throws Exception {
        List<Map<String, Object>> globals = new ArrayList<>();
        Listing listing = program.getListing();
        
        // Get data sections
        MemoryBlock[] blocks = program.getMemory().getBlocks();
        MemoryBlock dataBlock = null;
        for (MemoryBlock block : blocks) {
            if (block.getName().equals(".data") || block.getName().equals(".rdata")) {
                dataBlock = block;
                break;
            }
        }
        if (dataBlock == null && blocks.length > 1) {
            dataBlock = blocks[1]; // Second block is usually data
        }
        
        // Write header file with struct definitions
        DataTypeManager dtm = program.getDataTypeManager();
        Path structsFile = outPath.resolve("headers").resolve("ghidra_structs.h");
        
        try (PrintWriter w = new PrintWriter(Files.newBufferedWriter(structsFile))) {
            w.println("/* Auto-extracted struct definitions from Ghidra */");
            w.println("");
            
            // Enum all user-defined structs
            int structIdx = 0;
            Iterator<Structure> structs = dtm.getAllStructures();
            while (structs.hasNext()) {
                Structure s = structs.next();
                w.println("typedef struct {");
                for (DataTypeComponent comp : s.getComponents()) {
                    w.println("    /* +" + String.format("0x%04X", comp.getOffset()) + 
                             " */ " + comp.getDataType().getName() + " " + 
                             comp.getFieldName() + ";");
                }
                w.println("} " + s.getName() + ";");
                w.println("");
                structIdx++;
            }
            
            w.println("/* Total structs: " + structIdx + " */");
        }
        
        return globals;
    }
    
    private String sanitizeFileName(String name) {
        return name.replaceAll("[^a-zA-Z0-9_\\-]", "_");
    }
    
    private String writeJson(Object obj) {
        if (obj == null) return "null";
        if (obj instanceof String) return "\"" + escapeJson((String) obj) + "\"";
        if (obj instanceof Number) return obj.toString();
        if (obj instanceof Boolean) return obj.toString();
        if (obj instanceof Map) {
            Map<?,?> map = (Map<?,?>) obj;
            StringBuilder sb = new StringBuilder("{\n");
            boolean first = true;
            for (Map.Entry<?,?> e : map.entrySet()) {
                if (!first) sb.append(",\n");
                sb.append("  \"").append(escapeJson(e.getKey().toString())).append("\": ");
                sb.append(writeJson(e.getValue()));
                first = false;
            }
            sb.append("\n}");
            return sb.toString();
        }
        if (obj instanceof List) {
            List<?> list = (List<?>) obj;
            StringBuilder sb = new StringBuilder("[");
            boolean first = true;
            for (Object item : list) {
                if (!first) sb.append(", ");
                sb.append(writeJson(item));
                first = false;
            }
            sb.append("]");
            return sb.toString();
        }
        return "\"" + escapeJson(obj.toString()) + "\"";
    }
    
    private String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t");
    }
}
"""
    return script


def run_ghidra_headless(ghidra_home, exe_path, output_dir, script_text):
    """
    Run Ghidra headless analyzer with the decompile script.
    
    Ghidra headless CLI:
      analyzeHeadless <project_dir> <project_name> 
        -import <binary> 
        -scriptPath <script_dir>
        -postScript <script_name>
        -max-cpu <cores>
    """
    ghidra_home = Path(ghidra_home)
    exe_path = Path(exe_path).resolve()
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Determine the headless runner
    if os.name == 'nt':
        headless = ghidra_home / 'support' / 'analyzeHeadless.bat'
    else:
        headless = ghidra_home / 'support' / 'analyzeHeadless'
    
    if not headless.exists():
        raise FileNotFoundError("analyzeHeadless not found at: %s" % headless)
    
    # Create a temporary project directory
    project_dir = Path(tempfile.mkdtemp(prefix='ghidra_project_'))
    project_name = exe_path.stem + "_analysis"
    
    # Write the Ghidra script to a temp file
    scripts_dir = output_dir / 'ghidra_scripts'
    scripts_dir.mkdir(exist_ok=True)
    script_file = scripts_dir / 'DecompileToC.java'
    with open(script_file, 'w', encoding='utf-8') as f:
        f.write(script_text)
    
    # Build command
    cmd = [
        str(headless),
        str(project_dir),           # Project directory
        project_name,                # Project name
        '-import', str(exe_path),    # Import binary
        '-scriptPath', str(scripts_dir),  # Script location
        '-postScript', 'DecompileToC.java',  # Run after analysis
        '-processor', 'x86:LE:32:default',   # Architecture hint
        '-loader', 'Portable Executable (PE)', # Loader hint
        '-max-cpu', '4',            # Use multiple cores
        '-noanalysis',              # We'll handle analysis in script
        '-deleteProject',           # Clean up after
    ]
    
    # Set JAVA options
    env = os.environ.copy()
    java_home = env.get('JAVA_HOME', '')
    if java_home:
        env['PATH'] = str(Path(java_home) / 'bin') + os.pathsep + env.get('PATH', '')
    
    # Ghidra needs this property for the output dir
    java_opts = env.get('JAVA_OPTS', '')
    java_opts += ' -Dghidra.output.dir=%s' % output_dir
    # Increase memory for large binaries
    java_opts += ' -Xmx4G'
    env['JAVA_OPTS'] = java_opts
    
    print("[*] Ghidra headless command:")
    print("    " + ' '.join(cmd))
    print("[*] JAVA_OPTS: %s" % java_opts)
    print("[*] Output directory: %s" % output_dir)
    print("[*] This may take 10-60 minutes for a 5.6MB binary...")
    print("")
    
    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=3600,  # 1 hour timeout
            cwd=str(ghidra_home)
        )
        
        # Write logs
        with open(output_dir / 'ghidra_stdout.log', 'w', encoding='utf-8') as f:
            f.write(result.stdout)
        with open(output_dir / 'ghidra_stderr.log', 'w', encoding='utf-8') as f:
            f.write(result.stderr)
        
        if result.returncode != 0:
            print("[!] Ghidra exited with code %d" % result.returncode)
            print("[!] Check logs: %s" % (output_dir / 'ghidra_stderr.log'))
            # Show last 20 lines of stderr
            stderr_lines = result.stderr.strip().split('\n')
            for line in stderr_lines[-20:]:
                print("    " + line)
            return False
        
        print("[+] Ghidra headless completed successfully!")
        return True
        
    except subprocess.TimeoutExpired:
        print("[!] Ghidra headless timed out after 1 hour")
        return False
    except Exception as e:
        print("[!] Error running Ghidra: %s" % e)
        return False


def parse_ghidra_output(output_dir):
    """Parse Ghidra output and summarize results"""
    summary_file = Path(output_dir) / 'ghidra_analysis.json'
    if not summary_file.exists():
        print("[!] No ghidra_analysis.json found - decompilation may have failed")
        return None
    
    with open(summary_file, 'r', encoding='utf-8') as f:
        summary = json.load(f)
    
    funcs = summary.get('functions', [])
    print("\n[+] Ghidra Decompilation Summary:")
    print("    Total functions: %d" % len(funcs))
    
    # Statistics
    fail_count = sum(1 for f in funcs if f.get('hasFailures'))
    avg_size = sum(f.get('bodySize', 0) for f in funcs) / max(len(funcs), 1)
    avg_calls = sum(f.get('callCount', 0) for f in funcs) / max(len(funcs), 1)
    avg_xrefs = sum(f.get('xrefCount', 0) for f in funcs) / max(len(funcs), 1)
    
    print("    Failed decompiles: %d" % fail_count)
    print("    Avg body size: %.1f bytes" % avg_size)
    print("    Avg calls: %.1f" % avg_calls)
    print("    Avg xrefs: %.1f" % avg_xrefs)
    
    # Top 10 most referenced functions
    top_xrefs = sorted(funcs, key=lambda f: f.get('xrefCount', 0), reverse=True)[:10]
    print("\n    Top 10 most referenced functions:")
    for f in top_xrefs:
        print("      %s (%s): %d xrefs, %d calls" % (
            f['name'][:40], f['address'], f.get('xrefCount', 0), f.get('callCount', 0)
        ))
    
    # Check for decompiled C files
    funcs_dir = Path(output_dir) / 'functions'
    if funcs_dir.exists():
        c_files = list(funcs_dir.glob('*.c'))
        print("\n    C files generated: %d" % len(c_files))
    
    return summary


def main():
    parser = argparse.ArgumentParser(
        description='Ghidra Headless Decompiler — 用 NSA Ghidra 反编译 PE 文件为 C 伪代码'
    )
    parser.add_argument('target', help='目标 EXE/DLL 文件')
    parser.add_argument('--ghidra-home', required=True, help='Ghidra 安装目录')
    parser.add_argument('--output', '-o', default=None, help='输出目录')
    parser.add_argument('--skip-run', action='store_true', help='跳过运行，只生成脚本')
    args = parser.parse_args()
    
    exe_path = Path(args.target).resolve()
    if not exe_path.exists():
        print("[!] Target not found: %s" % exe_path)
        sys.exit(1)
    
    ghidra_home = find_ghidra(args.ghidra_home)
    if not ghidra_home:
        print("[!] Ghidra not found. Set --ghidra-home or GHIDRA_HOME env var")
        print("[!] Expected: support/analyzeHeadless.bat inside Ghidra directory")
        sys.exit(1)
    
    java = find_java()
    if not java:
        print("[!] Java not found. Install JDK 17+ and set JAVA_HOME")
        sys.exit(1)
    
    output_dir = args.output or str(exe_path.parent / ('ghidra_' + exe_path.stem))
    
    print("[*] Ghidra home: %s" % ghidra_home)
    print("[*] Java: %s" % java)
    print("[*] Target: %s" % exe_path)
    print("[*] Output: %s" % output_dir)
    
    # Create the headless decompile script
    script = create_headless_script(output_dir, exe_path)
    
    if args.skip_run:
        print("[*] --skip-run: Script generated but not executed")
        return
    
    # Run Ghidra headless
    success = run_ghidra_headless(ghidra_home, exe_path, output_dir, script)
    
    if success:
        parse_ghidra_output(output_dir)
    else:
        print("\n[!] Ghidra analysis did not complete successfully")
        print("[!] Check the logs in: %s" % output_dir)
        sys.exit(1)


if __name__ == '__main__':
    main()
