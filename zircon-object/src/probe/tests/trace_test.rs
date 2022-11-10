use super::trace;
use crate::symbol::addr_to_symbol;
use crate::alloc::string::ToString;

#[inline(never)]
fn bar(x: isize) -> isize {
    if x > 5 {
        x - 10
    } else {
        x + 2
    }
}

#[inline(never)]
fn baz(x: isize) -> isize {
    let mut y = x;
    y = bar(y);
    if x >= 10 {
        y += bar(x - 6);
    }
    x - y + bar(y)
}

#[inline(never)]
pub fn foo(n: usize) -> isize {
    let mut x = 4;
    let mut y = 0;
    for i in 0..n {
        if i % 4 == 3 {
            x += baz(x);
        }
        y += x;
        x = bar(x);
        y -= x;
    }
    y
}

pub struct Test(i32);
impl Test {
    #[inline(never)]
    pub fn l0(&mut self) { self.l1_1(); self.l1_2(); self.0 -= 1;}
    #[inline(never)]
    pub fn l1_1(&mut self) { self.l2_1(); self.l2_2(); self.0 -= 2; }
    #[inline(never)]
    pub fn l1_2(&mut self) { self.l2_3(); self.l2_4(); self.0 -= 2; }
    #[inline(never)]
    pub fn l2_1(&mut self) { self.0 += 1; }
    #[inline(never)]
    pub fn l2_2(&mut self) { self.0 += 2; }
    #[inline(never)]
    pub fn l2_3(&mut self) { self.0 += 3; }
    #[inline(never)]
    pub fn l2_4(&mut self) { self.0 += 4; }
}

pub fn run_dynamic_trace_test() {
    trace::trace_root_function(foo as usize);

    let mut t = Test(0);
    trace::trace_root_function(Test::l0 as usize);
    t.l0();
    trace::trace_next_step();
    t.l0();
    trace::trace_samples_with(|samples| {
        for (&addr, &depth) in &samples.targets {
            let name = addr_to_symbol(addr).unwrap_or("unknown".to_string());
            warn!("function {} at depth {})", name, depth);
        }
    });
    trace::unregister_all();
}
