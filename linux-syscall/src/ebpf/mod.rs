//! eBPF system call 
//!
//! - bpf(2)
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(unreachable_patterns)]

use super::*;
use alloc::string::String;
use zircon_object::ebpf::program::MapFdEntry;
use zircon_object::ebpf::{
    consts::BpfCommand,
    program::ProgramLoadExAttr,
    syscall::*,
};
use zircon_object::vm::{
    VmObject
};
use kernel_hal::user::{Out, UserInPtr, UserOutPtr, UserPtr};




impl Syscall<'_> {

    pub fn sys_bpf(&self, cmd: i32, bpf_attr: *const u8 , size: u32) -> i32 {
        if let Ok(bpf_cmd) = BpfCommand::try_from(cmd) {
            use BpfCommand::*;
            match bpf_cmd {
                BPF_MAP_CREATE => sys_bpf_map_create(bpf_attr, size),
                BPF_MAP_LOOKUP_ELEM => sys_bpf_map_lookup_elem(bpf_attr, size),
                BPF_MAP_UPDATE_ELEM => sys_bpf_map_update_elem(bpf_attr, size),
                BPF_MAP_DELETE_ELEM => sys_bpf_map_delete_elem(bpf_attr, size),
                BPF_MAP_GET_NEXT_KEY => todo!(),
                BPF_PROG_LOAD => todo!(),
                BPF_PROG_ATTACH => sys_bpf_program_attach(bpf_attr, size),
                BPF_PROG_DETACH => todo!(),
                BPF_PROG_LOAD_EX => self.sys_temp_bpf_program_load_ex(bpf_attr, size),
            }
        } else {
            -1
        }
    }

    #[allow(unused_mut)]
    fn sys_temp_bpf_program_load_ex(&self, attr_ptr: *const u8, size: u32) -> i32 {
        let ptr = UserInPtr::<ProgramLoadExAttr>::from(attr_ptr as usize);
        let attr = ptr.read().unwrap();
        // ELF relocatable object info
        let base = attr.elf_prog as *mut u8;
        let size = attr.elf_size as usize;
        let vm = self.zircon_process().vmar();
        let mut prog = vec![0 as u8; size];
        let buf = &mut prog[..];
        let mut actual_read = vm.read_memory(base as usize, buf).unwrap();
        assert_eq!(actual_read, size);

        let arr_len = attr.map_array_len as usize;

        let mut map_fd_array = vec![0 as u8; arr_len * core::mem::size_of::<MapFdEntry>()];
        let buf = &mut map_fd_array[..];
        actual_read = vm.read_memory(attr.map_array as usize, buf).unwrap();
        assert_eq!(actual_read, arr_len * core::mem::size_of::<MapFdEntry>());

        let mut map_info = alloc::vec::Vec::new();
        for i in 0..arr_len {
            let entry = &map_fd_array[i];
            let name = "";
            //let name = check_and_clone_cstr(entry.name)?;
            //map_info.push((name, entry.fd));
        }
        sys_bpf_program_load_ex(&mut prog[..], &map_info[..]);
        -1
    }
}
