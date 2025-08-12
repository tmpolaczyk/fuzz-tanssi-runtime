use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Default)]
pub struct EventTracer {
    seen_events: BTreeMap<(u8, u8), String>,
}

impl EventTracer {
    pub fn insert<F: FnOnce() -> String>(&mut self, value: (u8, u8), event_fmt: F) {
        self.seen_events.entry(value).or_insert_with(event_fmt);
    }

    pub fn print_events(&self) {
        for (first_2_bytes, event) in self.seen_events.iter() {
            println!("{:3} {:3} {}", first_2_bytes.0, first_2_bytes.1, event);
        }
    }
}
