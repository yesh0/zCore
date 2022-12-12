use core::arch::global_asm;
use alloc::string::*;
use alloc::vec::*;
use lock::Mutex;
use lazy_static::lazy_static;
global_asm!(include_str!("symbol_table.asm"));

pub struct SymbolTable {
    // sorted by address
    pub kernel_symbols: Vec<(String, usize)>,
}

lazy_static! {
    static ref SYMBOL_TABLE: Mutex<Option<SymbolTable>> = Mutex::new(None);
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            kernel_symbols: Vec::new(),
        }
    }

    pub fn add_symbol(&mut self, name: String, addr: usize) {
        info!("add symbol: {:x} {}", addr, name);
        self.kernel_symbols.push((name, addr));
    }

    pub fn translate(&self, name: &str) -> Option<usize> {
        for (symbol_name, addr) in self.kernel_symbols.iter() {
            if symbol_name == name {
                return Some(*addr);
            }
        }
        None
    }

    pub fn find_symbol(&self, addr: usize) -> Option<(&str, usize)> {
        let mut l: usize = 0;
        let mut r = self.kernel_symbols.len();
        while l < r {
            let m = l + (r - l) / 2;
            if self.kernel_symbols[m].1 <= addr {
                l = m + 1;
            } else {
                r = m;
            }
        }
        if l > 0 {
            Some((&self.kernel_symbols[l - 1].0, self.kernel_symbols[l - 1].1))
        } else {
            None
        }
    }

    pub fn init_kernel_symbols(&mut self, kernel_symbols: &str) {
        let lines = kernel_symbols.lines();
        for l in lines.into_iter() {
            let mut words = l.split_whitespace();
            let address = words.next().unwrap();
            let _stype = words.next().unwrap();
            // Current compiler is too old and it don't have SplitWhitespace::as_str
            // We have to use some workaround
            // let name = words.as_str();
            let remaining: Vec<_> = words.collect();
            let name: &str = &remaining.join(" ");
            let addr = usize::from_str_radix(address, 16).unwrap();
            self.add_symbol(name.to_string(), addr);
        }
    }

    pub fn load_kernel_symbols_from_elf(&mut self) {
        extern "C" {
            fn zcore_symbol_table();
            fn zcore_symbol_table_size();
        }
        let symbol_table_start: usize = zcore_symbol_table as usize;
        let symbol_table_len: usize =
            unsafe { *(zcore_symbol_table_size as usize as *const usize) };
        warn!(
            "Loading kernel symbol table {:08x} with size {:08x}",
            symbol_table_start as usize, symbol_table_len as usize
        );
        if symbol_table_len == 0 {
            warn!("Load kernel symbol table failed! This is because you didn't attach kernel table onto binary.");
            return;
        }
        let real_symbols = unsafe {
            core::slice::from_raw_parts(symbol_table_start as *const u8, symbol_table_len)
        }
        .to_vec();
        use core::str::from_utf8;
        self.init_kernel_symbols(from_utf8(&real_symbols).unwrap());
    }

    // should be called only once
    pub fn init() {
        info!("Symbol Table loading...");
        let mut table = Self::new();
        table.load_kernel_symbols_from_elf();

        SYMBOL_TABLE.lock().replace(table);
        info!("Symbol Table loaded!");
    }
}

pub fn init_symbol_table() {
    SymbolTable::init();
}

pub fn symbol_to_addr(name: &str) -> Option<usize> {
    warn!("symbol_to_addr: {}", name);
    let addr = SYMBOL_TABLE.lock().as_ref().unwrap().translate(name);
    warn!("symbol_to_addr: {} -> {:x}", name, addr.unwrap());
    addr
}

pub fn symbol_table_with<T>(f: impl FnOnce(&SymbolTable) -> T) -> T {
    let table = SYMBOL_TABLE.lock();
    let symbols = table.as_ref().unwrap();
    f(symbols)
}
