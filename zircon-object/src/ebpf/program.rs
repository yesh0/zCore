use core::mem::size_of;

use alloc::string::String;
use alloc::vec::Vec;
use ebpf_analyzer::{
    analyzer::{Analyzer, AnalyzerConfig},
    interpreter::vm::Vm,
    spec::proto::helpers::HELPERS,
    track::{
        pointees::{dyn_region::DynamicRegion, pointed},
        pointer::Pointer,
    },
};
use xmas_elf;
use xmas_elf::header::Machine;
use xmas_elf::sections::*;
use xmas_elf::symbol_table::Entry;

#[cfg(target_arch = "riscv64")]
use ebpf2rv::compile;

use crate::{ebpf::retcode::BpfErrorCode, error};

use super::{
    consts::*, helpers::*, retcode::BpfErrorCode::*, retcode::BpfResult,
    tracepoints::KProbeBPFContext, *,
};

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MapFdEntry {
    pub name: *const u8,
    pub fd: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProgramLoadExAttr {
    pub elf_prog: u64,
    pub elf_size: u32,
    pub map_array_len: u32,
    pub map_array: *const MapFdEntry,
}

pub struct BpfProgram {
    bpf_insns: Option<Vec<u64>>,
    jited_prog: Option<Vec<u32>>, // TODO: should be something like Vec<u8>
    pub map_fd_table: Option<Vec<u32>>,
}

impl BpfProgram {
    // TODO: run with context
    pub fn run(&self, ctx: *const u8) -> i64 {
        if let Some(compiled_code) = &self.jited_prog {
            let result = unsafe {
                type JitedFn = unsafe fn(*const u8) -> i64;
                let f = core::mem::transmute::<*const u32, JitedFn>(compiled_code.as_ptr());
                f(ctx)
            };
            return result;
        }

        todo!("eBPF interpreter missing")
    }
}

// #[cfg(target_arch = "riscv64")]
pub fn bpf_program_load_ex(prog: &mut [u8], map_info: &[(String, u32)]) -> BpfResult {
    trace!("bpf program load ex");
    let _base = prog.as_ptr();
    let elf = xmas_elf::ElfFile::new(prog).map_err(|_| EINVAL)?;
    match elf.header.pt2.machine().as_machine() {
        Machine::BPF => (), // machine type must be BPF
        _ => return Err(EINVAL),
    }

    // build map fd table. storage must be fixed after this.

    let mut map_fd_table = Vec::with_capacity(200);
    info!("addr {:x}, len {}", map_fd_table.as_ptr() as usize, map_info.len());
    for map_fd in map_info {
        map_fd_table.push(map_fd.1);
        trace!("pushed fd: {}", map_fd.1);
    }

    info!("map fd table built len: {}", map_fd_table.len());

    // build index -> map_fd variable address mapping
    let mut map_symbols = BTreeMap::new();
    let sym_tab_hdr = elf.find_section_by_name(".symtab").ok_or(ENOENT)?;
    if let Ok(SectionData::SymbolTable64(sym_entries)) = sym_tab_hdr.get_data(&elf) {
        for (sym_idx, sym) in sym_entries.iter().enumerate() {
            if let Ok(name) = sym.get_name(&elf) {
                for (map_idx, map_fd) in map_info.iter().enumerate() {
                    if &(map_fd.0) == name {
                        let base = map_fd_table.as_ptr() as usize;
                        let p = base + map_idx * core::mem::size_of::<u32>();
                        map_symbols.insert(sym_idx, p);
                        info!("insert map sym, idx: {}, addr: {:x}", sym_idx, p);
                    }
                }
            }
        }
    }
    if map_symbols.len() != map_info.len() {
        error!("map symbol len not match! expected: {:?} found:{:?}", map_info.len(), map_symbols.len());

        // unable to resolve all map info
        return Err(ENOENT);
    }

    trace!("map resolution finished");
    // relocate maps
    for sec_hdr in elf.section_iter() {
        if let Ok(ShType::Rel) = sec_hdr.get_type() {
            if let Ok(SectionData::Rel64(rel_entries)) = sec_hdr.get_data(&elf) {
                let sec_name = sec_hdr.get_name(&elf).map_or(Err(EINVAL), |v| Ok(v))?;
                let target_sec_name = &sec_name[4..]; // ".relXXX"
                let target_sec_hdr = elf.find_section_by_name(target_sec_name).ok_or(ENOENT)?;
                let base = target_sec_hdr.raw_data(&elf).as_ptr() as usize;

                for rel in rel_entries {
                    let offset = rel.get_offset() as usize;
                    let sym_idx = rel.get_symbol_table_index() as usize;
                    let rel_type = rel.get_type();

                    let relocated_addr: usize;
                    if let Some(&addr) = map_symbols.get(&sym_idx) {
                        relocated_addr = addr;
                    } else {
                        continue;
                    }
                    info!("relocate entry idx: {} offset:{:x} type:{:?} to addr:{:x}", sym_idx, offset, rel_type, relocated_addr);

                    match rel_type {
                        // relocation for LD_IMM64 instruction
                        R_BPF_64_64 => {
                            trace!("rel type match load 64!");
                            let addr = relocated_addr as u64;
                            let (v1, v2) = (addr as u32, (addr >> 32) as u32);
                            let p1 = (base + offset + 4) as *mut u32;
                            let p2 = (base + offset + 12) as *mut u32;
                            unsafe {
                                *p1 = v1;
                                *p2 = v2;
                            }
                        }
                        R_BPF_64_32 => {
                            trace!("rel type match call");
                            let addr = relocated_addr as u64;
                            let v = addr / 8 - 1;
                            let (v1, v2) = (v as u32, (v >> 32) as u32);
                            let p1 = (base + offset + 4) as *mut u32;
                            let p2 = (base + offset + 12) as *mut u32;
                            unsafe {
                                *p1 = v1;
                                *p2 = v2;
                            }
                        }
                        _ => (),
                    }
                }
            }
        }
    }

    let sec_hdr = elf.find_section_by_name(".text").ok_or(ENOENT)?;
    let code = sec_hdr.raw_data(&elf);
    let bpf_insns = unsafe {
        core::slice::from_raw_parts(
            code.as_ptr() as *const u64,
            code.len() / core::mem::size_of::<u64>(),
        )
    };

    // validate eBPF code
    let result = Analyzer::analyze(bpf_insns, &ANALYZER_CONFIG);
    if map_symbols.is_empty() {
        if let Err(ref e) = result {
            error!("eBPF failed verification: {:?}", e);
            return Err(BpfErrorCode::EINVAL);
        }
    } else {
        error!("Skipping verification for maps: {}", result.err());
    }
    warn!("eBPF verified");

    // compile eBPF code
    let mut jit_ctx = compile::JitContext::new(bpf_insns);
    let helper_fn_table =
        unsafe { core::mem::transmute::<&[BpfHelperFn], &[u64]>(&HELPER_FN_TABLE) };
    compile::compile(&mut jit_ctx, helper_fn_table, 512);

    info!("map fd table addr {:x}", map_fd_table.as_ptr() as usize);

    let compiled_code = jit_ctx.code; // partial move

    let program = BpfProgram {
        bpf_insns: None, // currently we do not store original BPF instructions
        jited_prog: Some(compiled_code),
        map_fd_table: Some(map_fd_table),
    };

    let fd = bpf_allocate_fd();
    bpf_object_create_program(fd, program);
    Ok(fd as usize)
}

const ANALYZER_CONFIG: AnalyzerConfig = AnalyzerConfig {
    helpers: HELPERS,
    setup: &|vm| {
        let context_region = pointed(DynamicRegion::new(size_of::<KProbeBPFContext>()));
        vm.add_external_resource(context_region.clone());
        *vm.reg(1) = Pointer::nrwa(context_region).into();
    },
    processed_instruction_limit: 1_000_000,
    map_fd_collector: &|_| None,
};

#[cfg(not(target_arch = "riscv64"))]
pub fn bpf_program_load_ex(prog: &mut [u8], map_info: &[(String, u32)]) -> SysResult {
    Err(EINVAL) // not supported
}
