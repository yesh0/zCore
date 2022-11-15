

// ! OS dependent part

use super::{
    map::*,
    map::MapAttr,
    map::MapOpAttr,
    retcode::BpfResult,
    tracepoints::KprobeAttachAttr,
    tracepoints::*,
};

use core::mem::size_of;
use crate::ebpf::program::bpf_program_load_ex;
use crate::object::{task::Thread, KernelObject};
use alloc::sync::Arc;
use alloc::string::String;

pub trait ThreadLike : Sync + Send {
    fn get_pid(&self) -> u64;
    fn get_tid(&self) -> u64;
    fn get_name(&self) -> String;
}

impl ThreadLike for Thread {
    fn get_pid(&self) -> u64 {
        return self.proc().id();
    }
    fn get_tid(&self) -> u64 {
        return self.related_koid() as u64;
    }
    fn get_name(&self) -> String {
        return String::from("not viable in zCore")
    }
}

pub fn os_current_thread() -> Arc<dyn ThreadLike> {
    if let Some(thread) = kernel_hal::thread::get_current_thread() {
        let ret = thread.downcast::<Thread>().unwrap();
        ret
    } else {
        panic!("cannot get current thread!")
    }
}

pub fn os_current_time() -> u128 {
    kernel_hal::timer::timer_now().as_nanos()
}

pub fn os_get_current_cpu() -> u8 {
    kernel_hal::cpu::cpu_id()
}

fn convert_result(result: BpfResult) -> i32 {
    match result {
        Ok(val) => val as i32,
        Err(_) => -1,
    }
}

pub fn sys_bpf_map_create(attr: *const u8, size: usize) -> i32 {
    assert_eq!(size as usize, size_of::<MapAttr>());
    let map_attr = unsafe {
        *(attr as *const MapAttr)
    };
    convert_result(bpf_map_create(map_attr))
}

pub fn sys_bpf_map_lookup_elem(attr: *const u8, size: usize) -> i32 {
    assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr = unsafe {
        *(attr as *const MapOpAttr)
    };
    convert_result(bpf_map_lookup_elem(map_op_attr))
}

pub fn sys_bpf_map_update_elem(attr: *const u8, size: usize) -> i32 {
    assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr = unsafe {
        *(attr as *const MapOpAttr)
    };
    convert_result(bpf_map_update_elem(map_op_attr))

}

pub fn sys_bpf_map_delete_elem(attr: *const u8, size: usize) -> i32 {
    assert_eq!(size as usize, size_of::<MapOpAttr>());
    let map_op_attr = unsafe {
        *(attr as *const MapOpAttr)
    };
    convert_result(bpf_map_delete_elem(map_op_attr))
}

pub fn sys_bpf_program_attach(attr: *const u8, size: usize) -> i32 {
  //  assert_eq!(size, size_of::<KprobeAttachAttr>());
    let attach_attr = unsafe {
        *(attr as *const KprobeAttachAttr)
    };
    let target_name = unsafe {
        core::str::from_utf8(
            core::slice::from_raw_parts(attach_attr.target, attach_attr.str_len as usize)
        ).unwrap()
    };
    error!("target name str: {}", target_name);
    convert_result(bpf_program_attach(target_name, attach_attr.prog_fd))
}


// this is a custome function, so we just copy from rCore
pub fn sys_bpf_program_load_ex(prog: &mut [u8], map_info: &[(String, u32)]) -> i32 {
    //error!("loaded prog:\n{:?}", prog);  
    let ret = convert_result(bpf_program_load_ex(prog, &map_info));
    error!("load ex ret: {}", ret);
    ret
}