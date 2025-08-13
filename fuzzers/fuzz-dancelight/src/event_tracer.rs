use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Default)]
pub struct EventTracer {
    // ((u8, u8), is_root) => Event name
    seen_events: HashMap<((u8, u8), bool), String>,
}

impl EventTracer {
    pub fn insert<F: FnOnce() -> String>(&mut self, value: (u8, u8), is_root: bool, event_fmt: F) {
        self.seen_events
            .entry((value, is_root))
            .or_insert_with(event_fmt);
    }

    pub fn print_events(&self) {
        let mut seen_events: Vec<_> = self
            .seen_events
            .iter()
            .map(|((k, is_root), v)| ((*k, if *is_root { "R " } else { " S" }), v))
            .collect();
        seen_events.sort();
        seen_events.dedup_by(|(b, _), (a, _)| {
            if a.0 == b.0 {
                if a.1 != b.1 {
                    a.1 = "RS";
                }

                true
            } else {
                false
            }
        });
        for ((first_2_bytes, prefix), event) in seen_events {
            //println!("{} {:3} {:3} {}", prefix, first_2_bytes.0, first_2_bytes.1, event);
            println!("{} {}", prefix, event);
        }
    }
}
