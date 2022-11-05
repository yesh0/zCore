//! eBPF system call 
//!
//! - bpf(2)

use super::*;
use alloc::string::String;
use zircon_object::ebpf;
use ebpf::consts::BpfCommand;

impl Syscall<'_> {
    pub fn sys_bpf(cmd: i32, bpf_attr: *const _ , size: u32) -> i32 {
        if let Some(bpf_cmd) = BpfCommand::try_from(cmd) {
            use BpfCommand;
            match bpf_cmd {
                BPF_MAP_CREATE => sys_bpf_map_create(bpf_attr, size),
                BPF_MAP_LOOKUP_ELEM => sys_bpf_map_lookup_elem(bpf_attr, size),
                BPF_MAP_UPDATE_ELEM => sys_bpf_map_update_elem(bpf_attr, size),
                BPF_MAP_DELETE_ELEM => sys_bpf_map_delete_elem(bpf_attr, size),
                BPF_MAP_GET_NEXT_KEY => todo!(),
                BPF_PROG_LOAD => todo!(),
                BPF_PROG_ATTACH => sys_bpf_program_attach(bpf_attr, size),
                BPF_PROG_DETACH => todo!(),
                BPF_PROG_LOAD_EX => sys_bpf_program_load_ex(bpf_attr, size),
            }
        } else {
            -1
        }
    }
}
