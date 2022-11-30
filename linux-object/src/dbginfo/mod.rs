use crate::fs::INodeExt;
use alloc::sync::Arc;
use crate::fs::vfs::FileSystem;
use lock::Mutex;
mod parse;
mod address;
mod stacktrace;

pub use stacktrace::print_stacktrace;

static ROOTFS: Mutex<Option<Arc<dyn FileSystem>>> = Mutex::new(None);

pub fn init_debuginfo(rootfs: &Arc<dyn FileSystem>) {
    match rootfs.root_inode().lookup("./zcore") {
        Ok(_) => {
            ROOTFS.lock().replace(rootfs.clone());
            ()
        }
        Err(e) => error!("failed to lookup /zcore: {:?}, debuginfo can't be used", e)
    }
}

pub fn addr_to_line(probe: usize) {
    let inode = ROOTFS.lock().as_ref().unwrap()
                 .root_inode().lookup("./zcore").unwrap();
    let data = inode.read_as_vec().unwrap();
    parse::parse_elf_and_print(data, probe).unwrap();
}
