use kernel_hal::mem::{virt_to_phys, phys_to_virt, pmem_copy};
use kernel_hal::KernelHandler;
use lock::Mutex;
use lazy_static::*;

lazy_static! {
    static ref KHANDLER: Mutex<Option<&'static dyn KernelHandler>> = Mutex::new(None);
}

pub const PAGE_SIZE: usize = kernel_hal::PAGE_SIZE;

pub fn init_osutils(handler: &'static dyn KernelHandler) {
    *KHANDLER.lock() = Some(handler);
}

// TODO: actually modify page table
pub fn alloc_page() -> usize {
    let pa = KHANDLER.lock().unwrap().frame_alloc().unwrap();
    let va = phys_to_virt(pa);
    trace!("alloc_page: va = {:#x}", va);
    va
}

pub fn dealloc_page(va: usize) {
    let pa = virt_to_phys(va);
    trace!("dealloc_page: va = {:#x}", va);
    KHANDLER.lock().unwrap().frame_dealloc(pa);
}

pub fn byte_copy(dst_addr: usize, src_addr: usize, len: usize) {
    trace!("byte_copy: src = {:#x}, dst = {:#x}, len = {:#x}", src_addr, dst_addr, len);
    pmem_copy(virt_to_phys(dst_addr),
                virt_to_phys(src_addr),
                len);
}
