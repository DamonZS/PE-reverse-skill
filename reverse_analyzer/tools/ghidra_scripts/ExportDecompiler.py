# ExportDecompiler.py - Ghidra headless postScript for reverse_analyzer
#@category ReverseAnalyzer

import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import CodeUnit


def ensure_dir(path):
    if not os.path.isdir(path):
        os.makedirs(path)


def write_text(path, text):
    parent = os.path.dirname(path)
    if parent:
        ensure_dir(parent)
    f = open(path, "w")
    try:
        f.write(text)
    finally:
        f.close()


def write_json(path, value):
    write_text(path, json.dumps(value, indent=2, sort_keys=True))


def addr(value):
    try:
        return str(value)
    except Exception:
        return "unknown"


def function_name(function):
    try:
        return function.getName(True)
    except Exception:
        return function.getName()


def decompile_function(ifc, function, monitor):
    try:
        result = ifc.decompileFunction(function, 60, monitor)
        if result and result.decompileCompleted():
            return result.getDecompiledFunction().getC()
        if result:
            return "/* decompile failed: %s */\n" % result.getErrorMessage()
    except Exception as exc:
        return "/* decompile exception: %s */\n" % exc
    return "/* decompile unavailable */\n"


def disassemble_function(program, function):
    listing = program.getListing()
    lines = []
    try:
        instructions = listing.getInstructions(function.getBody(), True)
        while instructions.hasNext():
            instruction = instructions.next()
            lines.append("%s: %s" % (instruction.getAddress(), instruction.toString()))
    except Exception as exc:
        lines.append("; disassembly exception: %s" % exc)
    return "\n".join(lines) + "\n"


def called_functions(function, monitor):
    calls = []
    try:
        iterator = function.getCalledFunctions(monitor)
        while iterator.hasNext():
            callee = iterator.next()
            calls.append({"name": function_name(callee), "entry": addr(callee.getEntryPoint())})
    except Exception:
        pass
    return calls


def collect_strings(program):
    results = []
    listing = program.getListing()
    try:
        data_iter = listing.getDefinedData(True)
        while data_iter.hasNext():
            data = data_iter.next()
            try:
                if data.hasStringValue():
                    value = str(data.getValue())
                    results.append({"address": addr(data.getAddress()), "value": value[:500]})
            except Exception:
                pass
    except Exception:
        pass
    return results


def collect_imports(program):
    imports = []
    try:
        external_manager = program.getExternalManager()
        locations = external_manager.getExternalLocations()
        while locations.hasNext():
            loc = locations.next()
            imports.append({"label": str(loc.getLabel()), "library": str(loc.getLibraryName())})
    except Exception:
        pass
    return imports


def main():
    args = getScriptArgs()
    out_dir = args[0] if args else os.path.join(os.getcwd(), "ghidra_export")
    ensure_dir(out_dir)
    ensure_dir(os.path.join(out_dir, "pseudocode"))
    ensure_dir(os.path.join(out_dir, "disassembly"))

    monitor = ConsoleTaskMonitor()
    ifc = DecompInterface()
    ifc.openProgram(currentProgram)

    functions = []
    call_edges = []
    function_manager = currentProgram.getFunctionManager()
    iterator = function_manager.getFunctions(True)
    while iterator.hasNext():
        function = iterator.next()
        entry = addr(function.getEntryPoint())
        name = function_name(function)
        safe = entry.replace(":", "_").replace(".", "_")
        calls = called_functions(function, monitor)
        for callee in calls:
            call_edges.append({"source": entry, "target": callee.get("entry"), "target_name": callee.get("name")})
        functions.append(
            {
                "name": name,
                "entry": entry,
                "body_size": int(function.getBody().getNumAddresses()),
                "signature": str(function.getSignature()),
                "calls": calls,
            }
        )
        write_text(os.path.join(out_dir, "pseudocode", "fn_%s.c" % safe), decompile_function(ifc, function, monitor))
        write_text(os.path.join(out_dir, "disassembly", "fn_%s.asm" % safe), disassemble_function(currentProgram, function))

    strings = collect_strings(currentProgram)
    imports = collect_imports(currentProgram)
    write_json(os.path.join(out_dir, "functions.json"), functions)
    write_json(os.path.join(out_dir, "call_graph.json"), {"nodes": functions, "edges": call_edges})
    write_json(os.path.join(out_dir, "strings_xrefs.json"), strings)
    write_json(os.path.join(out_dir, "imports_xrefs.json"), imports)
    write_json(
        os.path.join(out_dir, "summary.json"),
        {
            "program": currentProgram.getName(),
            "language": str(currentProgram.getLanguageID()),
            "compiler": str(currentProgram.getCompilerSpec().getCompilerSpecID()),
            "image_base": addr(currentProgram.getImageBase()),
            "function_count": len(functions),
            "string_count": len(strings),
            "import_count": len(imports),
        },
    )


main()
