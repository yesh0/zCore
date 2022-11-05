import argparse
import subprocess

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Dump symbol table")
    parser.add_argument("kernel", help="kernel file path")
    parser.add_argument("arch", help="e.g. riscv64-unknown-elf-")
    args = parser.parse_args()
    print(args)
    
    CMD_NM = args.arch + "nm"
    CMD_OBJDUMP = args.arch + "objdump"
    file = args.kernel
    
    # TODO: combine external symbols with -D?
    demangled_output = subprocess.check_output([
        CMD_NM, '-C', '-n',
        file])
    with open('./sym_demangled.txt', 'wb') as f:
        f.write(demangled_output)
    
    demangled_output_ext = subprocess.check_output([
        CMD_NM, '-C', '-g', '-n',
        file])
    with open('./ext_sym_demangled.txt', 'wb') as f:
        f.write(demangled_output_ext)
    
    dump = subprocess.check_output([
        CMD_OBJDUMP, '-D', '-j', '.text', '-F', '-C',
        file])
    with open('./objdump.txt', 'wb') as f:
        f.write(dump)
    
    print("Done!")