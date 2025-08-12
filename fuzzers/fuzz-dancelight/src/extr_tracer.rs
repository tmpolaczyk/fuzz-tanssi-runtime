use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Default)]
pub struct ExtrTracer {
    seen_ok_extr: BTreeMap<(u8, u8), String>,
}

impl ExtrTracer {
    pub fn insert<F: FnOnce() -> String>(&mut self, value: (u8, u8), extr_fmt: F) {
        self.seen_ok_extr.entry(value).or_insert_with(extr_fmt);
    }

    pub fn print_ok_extrs(&self) {
        for (first_2_bytes, event) in self.seen_ok_extr.iter() {
            println!("{:3} {:3} {}", first_2_bytes.0, first_2_bytes.1, event);
        }
    }
}
