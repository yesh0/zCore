

use super::{
    map::*,
};



pub fn sys_bpf_map_create(attr: *const _, size: u32) -> i32 {
    let map_attr = unsafe {
        *(attr as *const MapAttr)
    };
    if let Some(val) = bpf_map_create(map_attr) {
        val
    } else {
        -1
    }
}

pub fn sys_bpf_map_lookup_elem(attr: *const _, size: u32) -> i32 {
    todo!()
}

pub fn sys_bpf_map_update_elem(attr: *const _, size: u32) -> i32 {
    todo!()
}
pub fn sys_bpf_map_delete_elem(attr: *const _, size: u32) -> i32 {
    todo!()
}

pub fn sys_bpf_program_attach(attr: *const _, size: u32) -> i32 {
    todo!()
}

pub fn sys_bpf_program_load_ex(attr: *const _, size: u32) -> i32 {
    todo!()
}