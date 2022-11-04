//! eBPF system call 
//!
//! - bpf(2)

use super::*;
use alloc::string::String;

impl Syscall<'_> {
    pub fn sys_bpf(cmd: i32, bpf_attr: *const _ , size: u32) -> i32 {
        notimplemented!();
    }
}
