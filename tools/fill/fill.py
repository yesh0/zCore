import argparse
import subprocess
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dump symbol table")
    parser.add_argument("kernel", help="kernel file path")
    parser.add_argument("arch", help="e.g. riscv64")
    parser.add_argument("path", help="dir of the symbol table")
    args = parser.parse_args()
    print(args)
    
    # TODO: no adhoc
    CMD_NM = args.arch + "-unknown-elf-" + "nm"
    CMD_OBJDUMP = args.arch  + "-unknown-elf-" + "objdump"
    file = args.kernel
    sym_path = os.path.join(args.path, "kernel.sym")
    obj_path = os.path.join(args.path, "kernel.obj")
    
    if not os.path.exists(args.path):
        os.mkdir(args.path)

    demangled_output = subprocess.check_output([
        CMD_NM, '-C', '-n',
        file])
    with open(sym_path, 'wb') as f:
        f.write(demangled_output)
    
    dump = subprocess.check_output([
        CMD_OBJDUMP, '-D', '-j', '.text', '-F', '-C',
        file])
    with open(obj_path, 'wb') as f:
        f.write(dump)
    
    print("Done dumping symbol table to " + sym_path)