//! Provide backtrace upon panic
use core::mem::size_of;
use core::arch::asm;
use zircon_object::symbol::symbol_table_with;

extern "C" {
    fn stext();
    fn etext();
    fn sstack();
}

/// Returns the current frame pointer or stack base pointer
#[inline(always)]
pub fn fp() -> usize {
    let ptr: usize;
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        asm!("mv {}, s0", out(reg) ptr);
    }
    ptr
}

/// Returns the current link register.or return address
#[inline(always)]
pub fn lr() -> usize {
    let ptr: usize;
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        asm!("mv {}, ra", out(reg) ptr);
    }
    ptr
}

// Print the backtrace starting from the caller
pub fn backtrace() {
    #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
    unsafe {
        let mut current_pc = lr();
        let mut current_fp = fp();
        let mut stack_num = 0;
        println!("=== BEGIN zCore stack trace ===");

        while current_pc >= stext as usize
            && current_pc <= etext as usize
            && current_fp as usize != 0
        {
            // print current backtrace
            match size_of::<usize>() {
                4 => {
                    println!(
                        "#{:02} PC: {:#010X} FP: {:#010X}",
                        stack_num,
                        current_pc - size_of::<usize>(),
                        current_fp
                    );
                }
                _ => {
                    println!(
                        "#{:02} PC: {:#018X} FP: {:#018X}",
                        stack_num,
                        current_pc - size_of::<usize>(),
                        current_fp
                    );
                }
            }

            symbol_table_with(|table| {
                if let Some((name, addr)) = table.find_symbol(current_pc) {
                    print!("    {}", name);
                    let offset = current_pc - addr;
                    if offset != 0 {
                        print!(" +{:#x}", offset);
                    }
                    println!("");
                }
            });

            stack_num = stack_num + 1;
            #[cfg(any(target_arch = "riscv32", target_arch = "riscv64"))]
            {
                current_fp = *(current_fp as *const usize).offset(-2);
                // raw address 0x803ba000 appeared in the backtrace and I don't know why, traced into bootloading phase?
                if current_fp < sstack as usize {
                    break;
                }
                current_pc = *(current_fp as *const usize).offset(-1);
            }
        }
        println!("=== END zCore stack trace ===");
    }
}