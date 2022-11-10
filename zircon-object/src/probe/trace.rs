use lock::Mutex;
use alloc::collections::btree_map::BTreeMap;
use alloc::collections::btree_set::BTreeSet;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::Arc;
use lazy_static::lazy_static;
use crate::symbol::*;

use super::arch::{get_trapframe_pc, foreach_function_call};
use super::{register_kprobe, unregister_kprobe, KProbeArgs};
use super::TrapFrame;

pub struct TraceSamples {
    pub depth: usize,
    pub targets: BTreeMap<usize, usize>, // function address -> depth
    pub calls: BTreeSet<usize>, // addresses of probed call instructions
}

lazy_static! {
    static ref SAMPLES: Mutex<TraceSamples> = Mutex::new(TraceSamples::new());
}

impl TraceSamples {
    pub fn new() -> Self {
        Self {
            depth: 0,
            targets: BTreeMap::new(),
            calls: BTreeSet::new(),
        }
    }

    pub fn unregister_all(&self) {
        for &addr in &self.calls {
            unregister_kprobe(addr).unwrap();
        }
    }

    pub fn with<T>(&mut self, f: impl FnOnce(&mut Self) -> T) -> T {
        f(self)
    }
}

pub fn unregister_all() {
    SAMPLES.lock().unregister_all();
}

pub fn trace_samples_with<T>(f: impl FnOnce(&mut TraceSamples) -> T) -> T {
    let mut samples = SAMPLES.lock();
    samples.with(f)
}

fn find_function_range(symbols: &Vec<(String, usize)>, entry: usize) -> Option<(usize, usize)> {
    let mut l: usize = 0;
    let mut r = symbols.len();
    while l < r {
        let m = l + (r - l) / 2;
        if symbols[m].1 <= entry {
            l = m + 1;
        } else {
            r = m;
        }
    }
    if r < symbols.len() {
        Some((entry, symbols[r].1))
    } else {
        None
    }
}

fn dynamic_trace_kprobe_pre_handler(_tf: &mut TrapFrame, _data: usize) -> isize {
    0
}

fn dynamic_trace_kprobe_post_handler(tf: &mut TrapFrame, _data: usize) -> isize {
    let pc = get_trapframe_pc(tf);
    // warn!("call target: {:#x}", pc);
    trace_samples_with(|samples| {
        let targets = &mut samples.targets;
        if !targets.contains_key(&pc) {
            targets.insert(pc, samples.depth + 1);
        }
    });
    0
}

/// Add tracepoint to all function calls in the given function
pub fn trace_root_function(fn_entry: usize) {
    let range = symbol_table_with(|ksymbols| {
        find_function_range(&ksymbols.kernel_symbols, fn_entry)
    }).unwrap();

    let count = foreach_function_call(range, |addr| {
        trace_samples_with(|samples| {
            let args = KProbeArgs {
                pre_handler: Arc::new(dynamic_trace_kprobe_pre_handler),
                post_handler: Some(Arc::new(dynamic_trace_kprobe_post_handler)),
                user_data: samples.depth,
            };
            // register_kprobe may fail when "range"s of different functions overlap
            if register_kprobe(addr, args).is_some() {
                samples.calls.insert(addr);
            }
        })
    });

    symbol_table_with(|ksymbols| {
        let name = ksymbols.find_symbol(fn_entry).unwrap().0;
        info!("{} call instructions found for {}", count, name);
    });

    trace_samples_with(|samples| {
        samples.targets.insert(fn_entry, samples.depth);
    });
}

pub fn trace_next_step() {
    let mut target_fns = Vec::new();
    trace_samples_with(|samples| {
        samples.depth += 1;
        for (&fn_entry, &depth) in &samples.targets {
            if depth == samples.depth {
                target_fns.push(fn_entry);
            }
        }
    });

    for fn_entry in target_fns {
        trace_root_function(fn_entry);
    }
}
