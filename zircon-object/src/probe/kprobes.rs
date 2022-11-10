use lock::Mutex;
use alloc::collections::btree_map::BTreeMap;
use alloc::sync::Arc;
use core::ops::Fn;
use lazy_static::*;

use super::arch::*;
use super::{KProbeArgs, TrapFrame};

pub type Handler = dyn Fn(&mut TrapFrame, usize) -> isize + Sync + Send;
pub type HandlerFn = fn(&mut TrapFrame, usize) -> isize;

struct KProbe {
    addr: usize, // entry address
    pre_handler: Arc<Handler>,
    post_handler: Option<Arc<Handler>>,
    user_data: usize,
    insn_buf: InstructionBuffer,
    insn_len: usize,
    active_count: usize,
    emulate: bool,
}

#[derive(PartialEq)]
pub enum SingleStepType {
    Unsupported,
    Execute,
    Emulate,
}

lazy_static! {
    static ref KPROBES: Mutex<BTreeMap<usize, KProbe>> = Mutex::new(BTreeMap::new());
    static ref ADDR_MAP: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
}

impl KProbe {
    pub fn new(
        addr: usize,
        pre_handler: Arc<Handler>,
        post_handler: Option<Arc<Handler>>,
        user_data: usize,
        emulate: bool,
    ) -> Self {
        Self {
            addr,
            pre_handler,
            post_handler,
            user_data,
            insn_buf: InstructionBuffer::new(),
            insn_len: get_insn_length(addr),
            active_count: 0,
            emulate,
        }
    }

    pub fn arm(&self) {
        // write instruction buffer
        self.insn_buf.copy_in(0, self.addr, self.insn_len);
        self.insn_buf.add_breakpoint(self.insn_len);
        // replace original instruction with breakpoints
        inject_breakpoints(self.addr, Some(self.insn_len));
        invalidate_icache();
    }

    pub fn disarm(&self) {
        // change to original instruction
        self.insn_buf.copy_out(0, self.addr, self.insn_len);
        invalidate_icache();
    }
}

// returns whether this event is handled
pub fn kprobe_trap_handler(tf: &mut TrapFrame) -> bool {
    let pc = get_trapframe_pc(tf);
    let mut map = KPROBES.lock();
    if let Some(probe) = map.get_mut(&pc) {
        // breakpoint hit for the first time
        probe.active_count += 1;
        let _ = (probe.pre_handler)(tf, probe.user_data);

        // emulate branch instructions
        if probe.emulate {
            emulate_execution(tf, probe.insn_buf.addr(), probe.addr);
            if let Some(handler) = &probe.post_handler {
                let _ = handler(tf, probe.user_data);
            }
            probe.active_count -= 1;
            return true;
        }

        // redirect to instruction buffer (single step type is 'execute')
        // warn!("redirect target {:#x}", probe.insn_buf.addr());
        set_trapframe_pc(tf, probe.insn_buf.addr());
        // return true -> redirect to buffer -> ebreak in buffer -> post_handler -> in ADDR_MAP instead of KPROBES
        info!("set pc to {:#x}", probe.insn_buf.addr());
        return true;
    }

    if let Some(orig_addr) = ADDR_MAP.lock().get(&pc) {
        let probe = map.get_mut(orig_addr).unwrap();
        if let Some(handler) = &probe.post_handler {
            let _ = handler(tf, probe.user_data);
        }
        probe.active_count -= 1;
        set_trapframe_pc(tf, *orig_addr + probe.insn_len);
        return true;
    }
    false
}

pub fn register_kprobe(addr: usize, args: KProbeArgs) -> bool {
    let mut map = KPROBES.lock();
    if map.contains_key(&addr) {
        error!("kprobe for address {:#x} already exist", addr);
        return false;
    }

    let insn_type = get_insn_type(addr);
    if insn_type == SingleStepType::Unsupported {
        error!("target instruction is not supported");
        return false;
    }

    let emulate = insn_type == SingleStepType::Emulate;
    info!(
        "register kprobe at {:#x}",
        addr,
    );
    let probe = KProbe::new(
        addr,
        args.pre_handler,
        args.post_handler,
        args.user_data,
        emulate,
    );
    // bp in inst buffer, will be executed if inst not emulated
    let next_bp_addr = probe.insn_buf.addr() + probe.insn_len;
    probe.arm();

    ADDR_MAP.lock().insert(next_bp_addr, addr);
    map.insert(addr, probe);
    info!(
        "kprobe for address {:#x} inserted. {} kprobes registered",
        addr,
        map.len()
    );
    true
}

pub fn unregister_kprobe(addr: usize) -> bool {
    let mut map = KPROBES.lock();
    if let Some(probe) = map.get(&addr) {
        if probe.active_count > 0 {
            error!(
                "cannot remove kprobe for address {:#x} as it is still active",
                addr
            );
            false
        } else {
            probe.disarm();
            map.remove(&addr).unwrap();
            true
        }
    } else {
        false
    }
}
